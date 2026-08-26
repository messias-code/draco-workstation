"""engine.py — O "Maestro" que orquestra o pipeline ponta a ponta.

Fluxo por host (árvore de decisão dos PDFs):
    ingestão (feita na CLI) -> descoberta -> [DOWN? relatório vazio e encerra]
    -> descoberta de portas (masscan/nmap) -> [sem portas? relatório e encerra]
    -> nmap dirigido (serviço/versão/OS) -> cérebro (nuclei + CVEs) -> relatório

Hosts são auditados em paralelo (execution.host_concurrency). O pipeline de
CADA host é sequencial, evitando condição de corrida no relatório.
"""

from __future__ import annotations

import datetime
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from . import brain, discovery, scanner
from .models import HostReport, Target
from .reporter import write_report
from .runner import resolve_privileged


def audit_target(target: Target, cfg, logger=None) -> HostReport:
    """Executa o pipeline completo para UM alvo e devolve o HostReport.

    Chamável de forma independente (útil p/ testes e futura GUI/API).
    Sempre retorna um HostReport — mesmo para host DOWN — para que o relatório
    seja gerado em qualquer cenário.
    """
    started = time.monotonic()
    report = HostReport(
        target=target,
        strategy_label=cfg["report"].get("strategy_label", ""),
        started_at=datetime.datetime.now().strftime("%d/%m/%Y"),
    )
    privileged = resolve_privileged(cfg["execution"].get("privileged", "auto"))
    host = target.ip or target.raw

    if logger:
        logger.info(f"Iniciando Pipeline Stealth para {target.raw} ({host}) — Módulo de Auditoria Ativo.")
        if not privileged:
            logger.warning(
                "Sem privilégio (raw sockets): usando alternativas connect-scan. "
                "Rode com sudo para SYN/masscan/OS fingerprint completos."
            )

    # --- Fase 2a: descoberta de host ---
    report.discovery = discovery.discover_host(host, cfg, logger)
    if not report.is_up:
        _finish(report, started)
        if logger:
            logger.info(f"Host {host} DOWN — gerando relatório com Visão Geral DOWN.")
        return report

    # --- Fase 2b: descoberta de portas ---
    disc = scanner.discover_ports(host, cfg, logger, privileged)
    report.commands.extend(disc["commands"])
    report.warnings.extend(disc["warnings"])
    open_ports = disc["ports"]

    if not open_ports:
        if logger:
            logger.info(f"Nenhuma porta aberta encontrada em {host}. Finalizando host.")
        _finish(report, started)
        return report

    # --- Fase 2c: nmap dirigido (serviço/versão/OS) ---
    nmap_res = scanner.run_nmap(host, open_ports, cfg, logger, privileged)
    report.ports = nmap_res["ports"]
    report.os_matches = nmap_res["os_matches"]
    report.commands.extend(nmap_res["commands"])
    report.warnings.extend(nmap_res["warnings"])
    # Findings dos scripts NSE (vulners/vuln/http-enum) entram antes do cérebro,
    # que fará o dedupe junto com nuclei/searchsploit/NVD.
    report.vulnerabilities.extend(nmap_res.get("nse_vulns", []))

    # Se o nmap não trouxe portas (ex.: falha), preserva ao menos as do masscan.
    if not report.ports:
        from .models import Port

        report.ports = [Port(number=n, protocol=proto, state="open") for proto, n in open_ports]
        report.warnings.append("nmap não detalhou portas; exibindo portas cruas do masscan.")

    # --- Fase 3: cérebro (nuclei + correlação de CVEs + vetores) ---
    brain.analyze(report, cfg, logger)

    _finish(report, started)
    if logger:
        logger.info(f"Auditoria de {host} concluída: {len(report.open_ports)} portas abertas, "
                    f"{len(report.vulnerabilities)} vulnerabilidades correlacionadas.")
    return report


def _finish(report: HostReport, started: float) -> None:
    report.finished_at = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    report.duration_seconds = time.monotonic() - started


def run_pipeline(targets: list[Target], cfg, logger=None) -> list[str]:
    """Orquestra todos os alvos (em paralelo) e grava um relatório por host.

    Retorna a lista de caminhos dos relatórios gerados.
    """
    if not targets:
        if logger:
            logger.error("Nenhum alvo em escopo para auditar. Encerrando.")
        return []

    concurrency = max(1, int(cfg["execution"].get("host_concurrency", 4)))
    paths: list[str] = []

    def _one(t: Target) -> str:
        report = audit_target(t, cfg, logger)
        return write_report(report, cfg, logger)

    if concurrency == 1 or len(targets) == 1:
        for t in targets:
            paths.append(_one(t))
        return paths

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = {pool.submit(_one, t): t for t in targets}
        for fut in as_completed(futures):
            t = futures[fut]
            try:
                paths.append(fut.result())
            except Exception as exc:  # noqa: BLE001 - um host não pode derrubar os demais
                if logger:
                    logger.error(f"Falha inesperada auditando {t.raw}: {exc}")
    return paths
