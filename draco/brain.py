"""Épico 3 — O "Cérebro": árvore de decisão condicional.

A ferramenta não roda um comando gigante único: ela ITERA e decide os próximos
passos com base nas saídas anteriores. Este módulo implementa esse fluxo:

  * extrai CPEs/serviços das portas abertas;
  * SE porta web (80/443/...) aberta -> dispara Nuclei apontado à URL;
  * correlaciona CVEs (searchsploit + NVD + Vulners) por porta;
  * deriva "Vetores Recomendados" de enumeração (nível de recomendação,
    sem código de ataque).

Funções puras (should_run_nuclei, build_recommended_vectors) são testáveis sem
executar nenhum binário.
"""

from __future__ import annotations

from .correlation import correlate_port, dedupe_vulnerabilities
from .models import HostReport, Port
from .parser import parse_nuclei_jsonl
from .runner import run


# ---------------------------------------------------------------------------
# Decisões puras
# ---------------------------------------------------------------------------
def web_ports_open(ports: list[Port], cfg) -> list[Port]:
    """Portas web abertas segundo brain.web_ports."""
    web = set(cfg["brain"].get("web_ports", [80, 443, 8080, 8443]))
    return [p for p in ports if p.state == "open" and p.number in web]


def should_run_nuclei(ports: list[Port], cfg) -> bool:
    """True se o Nuclei deve ser disparado (há porta web aberta e está habilitado)."""
    if not (cfg["brain"].get("run_nuclei_on_web", True)):
        return False
    return bool(web_ports_open(ports, cfg))


def _port_to_url(port: Port, host: str) -> str:
    scheme = "https" if port.number in (443, 8443) else "http"
    if port.number in (80, 443):
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port.number}"


# ---------------------------------------------------------------------------
# Nuclei
# ---------------------------------------------------------------------------
def run_nuclei(urls: list[str], cfg, logger=None) -> dict:
    """Executa o Nuclei nas URLs web. Retorna {vulns, commands, warnings}."""
    ncfg = cfg["nuclei"]
    binary = cfg["execution"]["binaries"].get("nuclei", "nuclei")
    commands, warnings, vulns = [], [], []

    if not urls:
        return {"vulns": vulns, "commands": commands, "warnings": warnings}

    argv = [binary]
    for u in urls:
        argv += ["-u", u]
    sev = ncfg.get("severities") or []
    if sev:
        argv += ["-severity", ",".join(sev)]
    if ncfg.get("jsonl", True):
        argv.append("-jsonl")
    if ncfg.get("rate_limit"):
        argv += ["-rl", str(ncfg["rate_limit"])]
    argv += ["-silent"]
    argv += list(ncfg.get("extra_args", []) or [])

    commands.append(" ".join(argv))
    if logger:
        logger.command(argv)
        logger.info(f"Varredura web com Nuclei iniciada nas {len(urls)} URLs. Isso pode levar alguns minutos (rate_limit={ncfg.get('rate_limit', 150)})...")
    result = run(argv, timeout=ncfg.get("timeout_seconds", 900))
    if result.error:
        warnings.append(f"nuclei falhou: {result.error}")
        if logger:
            logger.warning(f"nuclei falhou: {result.error}")
        return {"vulns": vulns, "commands": commands, "warnings": warnings}

    vulns = parse_nuclei_jsonl(result.stdout)
    if logger:
        for v in vulns:
            logger.nuclei(f"[{v.identifier}] [{v.severity.upper()}] {v.service or v.title}")
    return {"vulns": vulns, "commands": commands, "warnings": warnings}


# ---------------------------------------------------------------------------
# Vetores recomendados (recomendação, sem código de ataque)
# ---------------------------------------------------------------------------
def build_recommended_vectors(report: HostReport, cfg) -> list[str]:
    """Deriva próximos passos DEFENSIVOS/de enumeração a partir dos achados.

    São recomendações de auditoria — nunca payloads ou exploits prontos.
    """
    vectors: list[str] = []
    open_ports = report.open_ports
    open_nums = {p.number for p in open_ports}
    services = {p.service_name.lower() for p in open_ports if p.service_name}

    # Web
    if open_nums & {80, 443, 8080, 8443}:
        vectors.append(
            "Spider/Crawling Profundo: realizar o mapeamento completo e recursivo da aplicação web "
            "(como o spider do Google) para descobrir links, parâmetros, APIs escondidas e endpoints não autenticados."
        )
        vectors.append(
            "Enumeração Web Avançada: mapear diretórios e arquivos ocultos (ex.: ffuf/gobuster) "
            "e revisar cabeçalhos de segurança HTTP ausentes."
        )
        vectors.append(
            "Fingerprint de tecnologias web (ex.: whatweb) para confirmar "
            "framework/CMS e versões expostas."
        )

    # SSH
    if 22 in open_nums or "ssh" in services:
        vectors.append(
            "Auditoria SSH: revisar algoritmos/cifras aceitos e política de "
            "autenticação; validar exposição a enumeração de usuários (ex.: CVE-2018-15473)."
        )

    # FTP
    if 21 in open_nums or "ftp" in services:
        vectors.append(
            "Auditoria FTP: verificar login anônimo, versão do daemon e "
            "vulnerabilidades conhecidas do banner identificado."
        )

    # SMB
    if open_nums & {139, 445} or "microsoft-ds" in services or "netbios-ssn" in services:
        vectors.append(
            "Enumeração SMB: listar compartilhamentos e políticas (ex.: enum4linux) "
            "e checar assinatura SMB e exposição de MS17-010."
        )

    # DB
    if open_nums & {3306, 5432, 1433, 27017}:
        vectors.append(
            "Serviço de banco de dados exposto: validar necessidade de exposição, "
            "credenciais padrão e regras de firewall/segmentação."
        )

    # Baseado em CVEs correlacionados
    cve_ports = {v.port for v in report.vulnerabilities if v.identifier.startswith("CVE-")}
    for port in sorted(p for p in cve_ports if p):
        vectors.append(
            f"Porta {port}: validar em ambiente controlado os CVEs correlacionados "
            "e priorizar correção/mitigação conforme o CVSS."
        )

    if not vectors:
        vectors.append(
            "Nenhum vetor óbvio: manter monitoramento, revisar superfície exposta "
            "e repetir a auditoria periodicamente."
        )
    return vectors


# ---------------------------------------------------------------------------
# Orquestração do cérebro para um host
# ---------------------------------------------------------------------------
def analyze(report: HostReport, cfg, logger=None) -> HostReport:
    """Aplica a árvore de decisão sobre um HostReport já com portas/serviços.

    Muta e retorna o próprio report (vulnerabilidades + vetores recomendados).
    """
    open_ports = report.open_ports

    # 1) Nuclei condicional (porta web aberta)
    if should_run_nuclei(open_ports, cfg):
        host = report.target.ip or report.target.raw
        urls = [_port_to_url(p, host) for p in web_ports_open(open_ports, cfg)]
        if logger:
            logger.info(f"Portas web detectadas; disparando Nuclei em: {', '.join(urls)}")
        nuc = run_nuclei(urls, cfg, logger)
        report.vulnerabilities.extend(nuc["vulns"])
        report.commands.extend(nuc["commands"])
        report.warnings.extend(nuc["warnings"])
    else:
        if logger:
            logger.info("Nenhuma porta web aberta; Nuclei não será executado.")

    # 2) Correlação de CVEs por porta aberta com serviço identificado
    for port in open_ports:
        report.vulnerabilities.extend(correlate_port(port, cfg, logger))

    # 3) Dedupe
    report.vulnerabilities = dedupe_vulnerabilities(report.vulnerabilities)

    # 4) Vetores recomendados
    report.recommended_vectors = build_recommended_vectors(report, cfg)
    return report
