"""Épico 2a — Descoberta de Host (UP/DOWN) com fallback.

Executa TODOS os métodos habilitados e reporta quais responderam:
  * ICMP  — via o binário 'ping' do SO (setuid; não exige root);
  * TCP-connect — connect() puro em portas comuns (Python socket; sem privilégio).

Se NENHUM método responder, o host é marcado DOWN e o pipeline encerra para
aquele IP — mas o relatório ainda é gerado (Visão Geral DOWN, tabelas vazias),
evitando que a ferramenta trave tentando escanear um host inativo.
"""

from __future__ import annotations

import socket
import time

from .models import DiscoveryResult
from .runner import run


def _icmp_ping(host: str, cfg, logger=None) -> float | None:
    """Ping ICMP via binário do SO. Retorna tempo (ms) se respondeu, senão None."""
    icmp = cfg["discovery"]["icmp"]
    count = int(icmp.get("count", 2))
    timeout = int(icmp.get("timeout_seconds", 2))
    ping_bin = cfg["execution"]["binaries"].get("ping", "ping")
    # -c count (nº de pacotes), -W timeout (Linux, segundos por resposta)
    argv = [ping_bin, "-c", str(count), "-W", str(timeout), host]
    if logger:
        logger.command(argv)
    started = time.monotonic()
    # margem de tempo generosa para não matar o ping antes da hora
    result = run(argv, timeout=count * timeout + 5)
    if result.error:
        if logger:
            logger.warning(f"ICMP indisponível para {host}: {result.error}")
        return None
    if result.returncode == 0:
        rtt = _parse_ping_rtt(result.stdout)
        return rtt if rtt is not None else (time.monotonic() - started) * 1000.0
    return None


def _parse_ping_rtt(output: str) -> float | None:
    """Extrai o menor RTT (ms) da saída do ping (linha 'rtt min/avg/max')."""
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("rtt ") or line.startswith("round-trip"):
            try:
                stats = line.split("=", 1)[1].strip().split()[0]
                return float(stats.split("/")[0])
            except (IndexError, ValueError):
                return None
    return None


def _tcp_connect(host: str, cfg, logger=None) -> tuple[float | None, int | None]:
    """Tenta connect() nas portas comuns. Retorna (tempo_ms, porta) do 1º sucesso."""
    dcfg = cfg["discovery"]
    ports = dcfg.get("tcp_connect_ports", [80, 443]) or []
    timeout = float(dcfg["tcp"].get("timeout_seconds", 2))
    for port in ports:
        try:
            start = time.monotonic()
            with socket.create_connection((host, int(port)), timeout=timeout):
                elapsed = (time.monotonic() - start) * 1000.0
                return elapsed, int(port)
        except (OSError, ValueError):
            continue
    return None, None


def discover_host(host: str, cfg, logger=None) -> DiscoveryResult:
    """Determina se `host` está UP, tentando todos os métodos configurados.

    Chamável de forma independente: recebe hostname/IP e a config, devolve um
    DiscoveryResult completo.
    """
    result = DiscoveryResult()
    methods = cfg["discovery"].get("methods", {})

    if not cfg.get("discovery.enabled", True):
        result.status = "UP"
        result.methods_tried.append("desabilitada")
        result.methods_responded.append("descoberta-desabilitada")
        if logger:
            logger.warning(f"Descoberta desabilitada; assumindo {host} como UP.")
        return result

    times: list[float] = []

    # --- ICMP ---
    if methods.get("icmp_ping", True):
        result.methods_tried.append("ICMP")
        rtt = _icmp_ping(host, cfg, logger)
        if rtt is not None:
            result.methods_responded.append("ICMP")
            times.append(rtt)
            if logger:
                logger.info(f"Host {host} respondeu ICMP ({rtt:.0f}ms).")

    # --- TCP connect (fallback, sempre executado se habilitado p/ robustez) ---
    if methods.get("tcp_connect", True):
        rtt, port = _tcp_connect(host, cfg, logger)
        label = "TCP-connect"
        result.methods_tried.append(label)
        if rtt is not None:
            result.methods_responded.append(f"{label}:{port}")
            times.append(rtt)
            if logger:
                logger.info(f"Host {host} respondeu TCP-connect na porta {port} ({rtt:.0f}ms).")

    if times:
        result.status = "UP"
        result.response_time_ms = min(times)
    else:
        result.status = "DOWN"
        if logger and cfg["discovery"].get("mark_down_if_all_fail", True):
            logger.warning(
                f"Host {host} marcado como DOWN (sem resposta a "
                f"{', '.join(result.methods_tried)})."
            )
    return result
