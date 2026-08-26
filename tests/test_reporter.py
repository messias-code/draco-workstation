"""Testes do Épico 4 — geração do relatório Markdown."""

from draco.models import DiscoveryResult, HostReport, Target, Vulnerability
from draco.parser import parse_nmap_xml
from draco.reporter import render_markdown


def _report_up(nmap_xml):
    out = parse_nmap_xml(nmap_xml)
    target = Target(raw="scanme.nmap.org", kind="domain", ip="45.33.32.156")
    report = HostReport(target=target, strategy_label="Stealth Recon")
    report.discovery = DiscoveryResult(
        status="UP", response_time_ms=112.0,
        methods_tried=["ICMP", "TCP-connect"], methods_responded=["ICMP"],
    )
    report.ports = out["ports"]
    report.os_matches = out["os_matches"]
    report.vulnerabilities = [
        Vulnerability(identifier="CVE-2014-0226", source="nvd", severity="medium",
                      cvss=6.8, port=80, service="Apache 2.4.7",
                      description="Race condition no mod_status."),
        Vulnerability(identifier="http-missing-security-headers", source="nuclei",
                      severity="low", port=80, service="http",
                      description="Cabecalhos de seguranca ausentes."),
    ]
    report.recommended_vectors = ["Enumeração Web Avançada", "Auditoria SSH"]
    report.commands = ["nmap -sS -sV -O --reason -T2 -f 45.33.32.156"]
    return report


# ---- caminho feliz --------------------------------------------------------
def test_report_has_all_sections(cfg, nmap_xml):
    md = render_markdown(_report_up(nmap_xml), cfg)
    assert "## 1. Status Geral do Host" in md
    assert "## 2. Mapeamento Estruturado de Portas" in md
    assert "## 3. Vulnerabilidades Identificadas e CVEs" in md
    assert "## 4. Vetores Recomendados" in md


def test_report_status_up(cfg, nmap_xml):
    md = render_markdown(_report_up(nmap_xml), cfg)
    assert "🟢 UP" in md
    assert "45.33.32.156" in md
    assert "Linux" in md


def test_report_distinguishes_reason(cfg, nmap_xml):
    md = render_markdown(_report_up(nmap_xml), cfg)
    # syn-ack (aberta), reset (fechada), no-response (filtrada) — todos presentes
    assert "syn-ack" in md
    assert "reset" in md
    assert "no-response" in md
    assert "Aberta" in md and "Fechada" in md and "Filtrada" in md


def test_report_vulns_with_cvss(cfg, nmap_xml):
    md = render_markdown(_report_up(nmap_xml), cfg)
    assert "CVE-2014-0226" in md
    assert "CVSS 6.8" in md


# ---- host DOWN ------------------------------------------------------------
def test_report_down_empty_tables(cfg):
    target = Target(raw="10.0.0.9", kind="ip", ip="10.0.0.9")
    report = HostReport(target=target)
    report.discovery = DiscoveryResult(
        status="DOWN", methods_tried=["ICMP", "TCP-connect"], methods_responded=[]
    )
    md = render_markdown(report, cfg)
    assert "🔴 DOWN" in md
    assert "host está marcado" not in md  # sanity
    assert "DOWN" in md
    # sem portas nem vulnerabilidades reais
    assert "Host DOWN" in md or "tabelas seguintes ficam vazias" in md


def test_report_no_emoji_option(cfg, nmap_xml):
    cfg["report"]["use_emoji"] = False
    md = render_markdown(_report_up(nmap_xml), cfg)
    assert "🟢" not in md and "🔴" not in md
