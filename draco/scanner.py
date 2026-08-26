"""Épico 2b/2c — Motor de Varredura (masscan + nmap).

Hierarquia leve -> profundo:
  1. discover_ports(): masscan varre 1-65535 (TCP e UDP) em --rate configurável.
     Sem masscan/privilégio, cai para um nmap de descoberta (connect scan).
  2. run_nmap(): nmap apontado SOMENTE para as portas abertas, com scan furtivo
     (SYN), versionamento (-sV), OS fingerprint (-O), --reason e stealth
     (-T2 -f --data-length). Exporta sempre XML (-oX) para parsing estruturado.

Cada função é chamável de forma independente e devolve dados estruturados +
o comando executado (para auditabilidade no relatório).
"""

from __future__ import annotations

import contextlib
import os
import tempfile

from .parser import nse_findings, parse_masscan_json, parse_masscan_list, parse_nmap_xml
from .runner import run


# ---------------------------------------------------------------------------
# Descoberta de portas (masscan, com fallback nmap)
# ---------------------------------------------------------------------------
def discover_ports(target_ip: str, cfg, logger=None, privileged: bool = False) -> dict:
    """Descobre portas abertas (TCP e UDP). Retorna dict estruturado.

    {
      "ports": [("tcp", 22), ("tcp", 80), ("udp", 53), ...],
      "method": "masscan" | "nmap-connect",
      "commands": [str, ...],
      "warnings": [str, ...],
    }
    """
    mcfg = cfg["masscan"]
    commands: list[str] = []
    warnings: list[str] = []

    masscan_bin = cfg["execution"]["binaries"].get("masscan", "masscan")
    use_masscan = privileged

    if not privileged:
        msg = "masscan exige privilégio (raw sockets); usando nmap connect scan p/ descoberta."
        warnings.append(msg)
        if logger:
            logger.warning(msg)

    if use_masscan:
        ports, cmds, warns = _masscan_discover(target_ip, cfg, masscan_bin, logger)
        commands += cmds
        warnings += warns
        if ports:
            return {"ports": ports, "method": "masscan", "commands": commands, "warnings": warnings}
        # masscan não achou nada ou falhou -> tenta nmap como rede de segurança
        warnings.append("masscan não retornou portas; tentando descoberta via nmap.")

    ports, cmds, warns = _nmap_discover(target_ip, cfg, logger, privileged)
    commands += cmds
    warnings += warns
    return {"ports": ports, "method": "nmap-connect", "commands": commands, "warnings": warnings}


def _masscan_discover(target_ip, cfg, masscan_bin, logger):
    mcfg = cfg["masscan"]
    commands, warnings = [], []
    all_ports: list[tuple[str, int]] = []

    # masscan trata TCP e UDP em execuções separadas para clareza de parsing.
    scans = [("tcp", mcfg["ports"].get("tcp", "1-65535"))]
    if mcfg.get("scan_udp", True) and mcfg["ports"].get("udp"):
        scans.append(("udp", mcfg["ports"]["udp"]))

    for proto, port_spec in scans:
        tmp = tempfile.NamedTemporaryFile(
            prefix=f"draco_masscan_{proto}_", suffix=".list", delete=False
        )
        tmp.close()
        port_arg = port_spec if proto == "tcp" else f"U:{port_spec}"
        argv = [
            masscan_bin,
            "-p", port_arg,
            "--rate", str(mcfg.get("rate", 500)),
            "--wait", str(mcfg.get("wait_seconds", 3)),
            "-oL", tmp.name,
        ] + list(mcfg.get("extra_args", []) or []) + [target_ip]
        commands.append(" ".join(argv))
        if logger:
            logger.command(argv)
            logger.info(f"Varredura masscan ({proto}) em todas as portas iniciada. Isso leva alguns segundos (rate={mcfg.get('rate', 2500)})...")
        result = run(argv, timeout=mcfg.get("timeout_seconds", 1800))
        if result.error:
            warnings.append(f"masscan {proto} falhou: {result.error}")
            if logger:
                logger.warning(f"masscan {proto} falhou: {result.error}")
        try:
            with open(tmp.name, encoding="utf-8") as fh:
                content = fh.read()
            parsed = parse_masscan_list(content) or parse_masscan_json(content)
            all_ports += parsed
        except OSError:
            pass
        finally:
            _safe_unlink(tmp.name)

    uniq = sorted(set(all_ports), key=lambda x: (x[0], x[1]))
    for proto, port in uniq:
        if logger:
            logger.resultado(f"- masscan: {port}/{proto} aberta")
    return uniq, commands, warnings


def _nmap_discover(target_ip, cfg, logger, privileged):
    """Descoberta de portas via nmap quando masscan não está disponível."""
    nmap_bin = cfg["execution"]["binaries"].get("nmap", "nmap")
    commands, warnings = [], []
    tcp_spec = cfg["masscan"]["ports"].get("tcp", "1-65535")

    # -sS se privilegiado, senão -sT (connect). Sem -O aqui (só descoberta).
    scan_flag = "-sS" if privileged else "-sT"
    argv = [nmap_bin, scan_flag, "-Pn", "--open", "-T4", "-p", tcp_spec, "-oX", "-", target_ip]
    commands.append(" ".join(argv))
    if logger:
        logger.command(argv)
    result = run(argv, timeout=cfg["nmap"].get("timeout_seconds", 3600))
    ports: list[tuple[str, int]] = []
    if result.error:
        warnings.append(f"nmap (descoberta) falhou: {result.error}")
        if logger:
            logger.warning(f"nmap (descoberta) falhou: {result.error}")
        return ports, commands, warnings
    parsed = parse_nmap_xml(result.stdout)
    for p in parsed["ports"]:
        if p.state == "open":
            ports.append((p.protocol, p.number))
    return sorted(set(ports), key=lambda x: (x[0], x[1])), commands, warnings


# ---------------------------------------------------------------------------
# Varredura profunda (nmap dirigido às portas abertas)
# ---------------------------------------------------------------------------
def build_nmap_args(target_ip, open_ports, cfg, privileged, xml_out="-", evasion=True):
    """Monta o argv do nmap a partir da config e das portas abertas.

    `evasion` liga/desliga as flags de fragmentação/padding/decoy/mtu. O motor
    usa evasion=False no fallback de confiabilidade (quando a evasão furtiva não
    obtém resposta em redes que descartam pacotes fragmentados, ex.: WSL2/NAT).

    Retorna a lista argv. Separado para ser testável sem executar nada.
    """
    ncfg = cfg["nmap"]
    nmap_bin = cfg["execution"]["binaries"].get("nmap", "nmap")
    argv = [nmap_bin]

    tcp_ports = sorted({port for proto, port in open_ports if proto == "tcp"})
    udp_ports = sorted({port for proto, port in open_ports if proto == "udp"})

    # Tipo de scan: SYN furtivo (-sS) se privilegiado; senão connect (-sT).
    if ncfg.get("syn_scan", True) and privileged:
        argv.append("-sS")
    elif ncfg.get("connect_scan_if_unprivileged", True):
        argv.append("-sT")

    # UDP (-sU) somando às portas abertas UDP, se habilitado e houver alvo.
    if ncfg.get("scan_udp", True) and udp_ports and privileged:
        argv.append("-sU")

    # -A (aggressive): SO + versão + scripts default + traceroute. Barulhento.
    if ncfg.get("aggressive", False):
        argv.append("-A")

    if ncfg.get("service_version", True):
        argv.append("-sV")
        vi = ncfg.get("version_intensity")
        if vi is not None:
            argv += ["--version-intensity", str(vi)]
    if ncfg.get("os_fingerprint", True) and privileged:
        argv.append("-O")
    if ncfg.get("reason", True):
        argv.append("--reason")
    if ncfg.get("skip_host_discovery", True):
        argv.append("-Pn")

    tmpl = ncfg.get("timing_template", 2)
    if tmpl is not None:
        argv.append(f"-T{tmpl}")

    # --- Evasão avançada (raw sockets => só com privilégio; desligável no fallback) ---
    if evasion and privileged:
        if ncfg.get("fragment_packets", True):
            argv.append("-f")
        dl = ncfg.get("data_length")
        if dl:
            argv += ["--data-length", str(dl)]
        decoys = ncfg.get("decoys") or ""
        if decoys:
            argv += ["-D", str(decoys)]
        mtu = ncfg.get("mtu")
        if mtu:
            argv += ["--mtu", str(mtu)]
        source_port = ncfg.get("source_port")
        if source_port:
            argv += ["-g", str(source_port)]
        spoof_mac = ncfg.get("spoof_mac") or ""
        if spoof_mac:
            argv += ["--spoof-mac", str(spoof_mac)]

    # --- NSE: consolida atalhos legados + lista explícita em um único --script ---
    scripts: list[str] = []
    if ncfg.get("default_scripts", False):
        argv.append("-sC")
    if ncfg.get("nse_vuln_scripts", False):
        scripts.append("vuln")
    scripts += [str(s) for s in (ncfg.get("nse_scripts") or [])]
    if scripts:
        # dedup preservando ordem
        seen: set[str] = set()
        uniq = [s for s in scripts if not (s in seen or seen.add(s))]
        argv += ["--script", ",".join(uniq)]
    script_args = ncfg.get("nse_script_args") or ""
    if script_args:
        argv += ["--script-args", str(script_args)]

    # Especificação de portas (-p) combinando TCP e UDP.
    port_specs = []
    if tcp_ports:
        port_specs.append("T:" + ",".join(str(p) for p in tcp_ports))
    if udp_ports and privileged and ncfg.get("scan_udp", True):
        port_specs.append("U:" + ",".join(str(p) for p in udp_ports))
    if port_specs:
        argv += ["-p", ",".join(port_specs)]

    argv += list(ncfg.get("extra_args", []) or [])
    argv += ["-oX", xml_out, target_ip]
    return argv


def run_nmap(target_ip, open_ports, cfg, logger=None, privileged=False) -> dict:
    """Executa o nmap dirigido às portas abertas. Retorna estrutura parseada.

    {
      "ports": [Port, ...],
      "os_matches": [OSMatch, ...],
      "commands": [str, ...],
      "warnings": [str, ...],
      "xml": "<...>",
    }
    """
    if not open_ports:
        return {"ports": [], "os_matches": [], "commands": [], "warnings": [], "xml": ""}

    warnings: list[str] = []
    commands: list[str] = []
    timeout = cfg["nmap"].get("timeout_seconds", 3600)

    def _scan(evasion: bool):
        argv = build_nmap_args(target_ip, open_ports, cfg, privileged, xml_out="-", evasion=evasion)
        if logger:
            logger.command(argv)
        res = run(argv, timeout=timeout)
        commands.append(" ".join(argv))
        if res.error:
            warnings.append(f"nmap falhou: {res.error}")
            if logger:
                logger.error(f"nmap falhou: {res.error}")
        return res.stdout or "", parse_nmap_xml(res.stdout or "")

    xml, parsed = _scan(evasion=True)

    # Fallback de confiabilidade: masscan achou portas abertas mas o nmap furtivo
    # não obteve resposta (comum quando fragmentação é descartada pela rede/NAT).
    # Refaz SEM evasão para não perder o versionamento/serviço.
    evaded = any(p.state == "open" for p in parsed["ports"])
    if privileged and not evaded and _has_evasion(cfg):
        if logger:
            logger.warning(
                "nmap furtivo não obteve resposta das portas abertas; refazendo "
                "SEM fragmentação/evasão (fallback de confiabilidade)."
            )
        warnings.append("Fallback: nmap refeito sem evasão (fragmentação descartada pela rede).")
        xml2, parsed2 = _scan(evasion=False)
        if any(p.state == "open" for p in parsed2["ports"]):
            xml, parsed = xml2, parsed2

    if logger:
        for p in parsed["ports"]:
            logger.resultado(
                f"- Porta {p.number}/{p.protocol} | Estado: {p.state.upper()} | Razão: {p.reason}"
            )
        for p in parsed["ports"]:
            if p.state == "open" and (p.product or p.service_name):
                cpe = f" [CPE: {p.cpes[0]}]" if p.cpes else ""
                logger.servico(f"- {p.number}/{p.protocol}: {p.service_version_str}{cpe}")

    # Converte a saída dos scripts NSE (vulners/vuln/http-enum/...) em findings.
    nse_vulns = nse_findings(parsed)
    if logger:
        for v in nse_vulns:
            sev = v.normalized_severity()
            cvss = f" (CVSS {v.cvss})" if v.cvss is not None else ""
            logger.found(f"{v.identifier}{cvss} [{sev}] via {v.source}")

    return {
        "ports": parsed["ports"],
        "os_matches": parsed["os_matches"],
        "nse_vulns": nse_vulns,
        "commands": commands,
        "warnings": warnings,
        "xml": xml,
    }


def _has_evasion(cfg) -> bool:
    """True se alguma flag de evasão está ativa (justifica o fallback)."""
    n = cfg["nmap"]
    return bool(
        n.get("fragment_packets", True) or n.get("data_length")
        or n.get("decoys") or n.get("mtu") or n.get("source_port") or n.get("spoof_mac")
    )


def _safe_unlink(path: str) -> None:
    with contextlib.suppress(OSError):
        os.unlink(path)
