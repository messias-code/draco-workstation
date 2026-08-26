"""Testes do Épico 3 — o "Cérebro" (decisões condicionais puras)."""

from draco.brain import build_recommended_vectors, should_run_nuclei, web_ports_open
from draco.models import HostReport, Port, Target, Vulnerability


def _ports(*specs):
    """Atalho: _ports((80,'open'), (22,'open')) -> lista de Port."""
    return [Port(number=n, state=s) for n, s in specs]


# ---- disparo condicional do Nuclei ---------------------------------------
def test_nuclei_triggers_on_web_port(cfg):
    ports = _ports((80, "open"), (22, "open"))
    assert should_run_nuclei(ports, cfg) is True
    assert {p.number for p in web_ports_open(ports, cfg)} == {80}


def test_nuclei_not_triggered_without_web(cfg):
    ports = _ports((22, "open"), (3306, "open"))
    assert should_run_nuclei(ports, cfg) is False


def test_nuclei_respects_disable(cfg):
    cfg["brain"]["run_nuclei_on_web"] = False
    ports = _ports((80, "open"))
    assert should_run_nuclei(ports, cfg) is False


def test_nuclei_only_open_ports(cfg):
    # porta 80 fechada não deve disparar o nuclei
    ports = _ports((80, "closed"))
    assert should_run_nuclei(ports, cfg) is False


# ---- vetores recomendados -------------------------------------------------
def test_vectors_web_and_ssh(cfg):
    report = HostReport(target=Target(raw="scanme.nmap.org", kind="domain", ip="45.33.32.156"))
    report.ports = _ports((80, "open"), (22, "open"))
    report.discovery.status = "UP"
    vectors = build_recommended_vectors(report, cfg)
    joined = " ".join(vectors).lower()
    assert "web" in joined
    assert "ssh" in joined


def test_vectors_reference_cve_ports(cfg):
    report = HostReport(target=Target(raw="host", kind="domain", ip="1.2.3.4"))
    report.ports = _ports((80, "open"))
    report.discovery.status = "UP"
    report.vulnerabilities = [
        Vulnerability(identifier="CVE-2014-0226", source="nvd", port=80, cvss=6.8)
    ]
    vectors = build_recommended_vectors(report, cfg)
    assert any("80" in v for v in vectors)


def test_vectors_empty_host(cfg):
    report = HostReport(target=Target(raw="host", kind="ip", ip="1.2.3.4"))
    report.discovery.status = "UP"
    vectors = build_recommended_vectors(report, cfg)
    # nunca vazio: sempre há ao menos a recomendação genérica
    assert len(vectors) >= 1
