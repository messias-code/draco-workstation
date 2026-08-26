"""Testes de integração do pipeline (engine) — sem rede nem binários reais.

Cobre os dois cenários de aceitação dos PDFs:
  * Caminho feliz: host UP, portas 22/80, serviço+versão, Nuclei e CVE -> .md completo.
  * Host offline: host DOWN -> .md com Visão Geral DOWN e tabelas seguintes vazias.

As fases que executam binários/rede (discovery, scanner, nuclei) são substituídas
por stubs que devolvem dados vindos das fixtures.
"""

import os

from draco import brain, engine, scanner
from draco.discovery import DiscoveryResult
from draco.engine import audit_target
from draco.models import Target
from draco.parser import parse_nmap_xml, parse_nuclei_jsonl
from draco.reporter import render_markdown, write_report


def _target():
    return Target(raw="scanme.nmap.org", kind="domain", ip="45.33.32.156", in_scope=True)


# ---- caminho feliz --------------------------------------------------------
def test_happy_path_pipeline(cfg, monkeypatch, nmap_xml, nuclei_jsonl, tmp_path):
    cfg["paths"]["outputs_dir"] = str(tmp_path)

    # Host UP
    monkeypatch.setattr(
        engine.discovery, "discover_host",
        lambda host, c, logger=None: DiscoveryResult(
            status="UP", response_time_ms=112.0,
            methods_tried=["ICMP", "TCP-connect"], methods_responded=["ICMP"],
        ),
    )
    # Descoberta de portas (masscan/nmap) -> 22 e 80 abertas
    monkeypatch.setattr(
        engine.scanner, "discover_ports",
        lambda ip, c, logger=None, privileged=False: {
            "ports": [("tcp", 22), ("tcp", 80)], "method": "masscan",
            "commands": ["masscan -p 1-65535 --rate 500 45.33.32.156"], "warnings": [],
        },
    )
    # nmap dirigido -> portas parseadas da fixture
    parsed = parse_nmap_xml(nmap_xml)
    monkeypatch.setattr(
        engine.scanner, "run_nmap",
        lambda ip, ports, c, logger=None, privileged=False: {
            "ports": parsed["ports"], "os_matches": parsed["os_matches"],
            "commands": ["nmap -sS -sV -O --reason -T2 -f 45.33.32.156"], "warnings": [], "xml": nmap_xml,
        },
    )
    # Nuclei -> achados parseados da fixture
    monkeypatch.setattr(
        brain, "run_nuclei",
        lambda urls, c, logger=None: {
            "vulns": parse_nuclei_jsonl(nuclei_jsonl),
            "commands": ["nuclei -u http://scanme.nmap.org -jsonl"], "warnings": [],
        },
    )

    report = audit_target(_target(), cfg)

    # Estrutura
    assert report.is_up
    assert {p.number for p in report.open_ports} == {22, 80}
    assert report.os_best.name.startswith("Linux")
    # Nuclei alimentou vulnerabilidades
    ids = {v.identifier for v in report.vulnerabilities}
    assert "http-missing-security-headers" in ids
    # Vetores recomendados derivados (web + ssh)
    joined = " ".join(report.recommended_vectors).lower()
    assert "web" in joined and "ssh" in joined

    # Relatório em disco
    path = write_report(report, cfg)
    assert os.path.isfile(path)
    md = open(path, encoding="utf-8").read()
    assert "🟢 UP" in md
    assert "syn-ack" in md and "reset" in md and "no-response" in md
    assert "## 3. Vulnerabilidades" in md


# ---- host offline / DOWN --------------------------------------------------
def test_host_down_pipeline(cfg, monkeypatch, tmp_path):
    cfg["paths"]["outputs_dir"] = str(tmp_path)

    called = {"ports": False}

    def _no_ports(*a, **k):
        called["ports"] = True
        return {"ports": [], "method": "masscan", "commands": [], "warnings": []}

    monkeypatch.setattr(
        engine.discovery, "discover_host",
        lambda host, c, logger=None: DiscoveryResult(
            status="DOWN", methods_tried=["ICMP", "TCP-connect"], methods_responded=[],
        ),
    )
    monkeypatch.setattr(engine.scanner, "discover_ports", _no_ports)

    report = audit_target(_target(), cfg)

    # DOWN encerra o pipeline sem escanear portas
    assert not report.is_up
    assert report.ports == []
    assert called["ports"] is False  # não tentou escanear portas de host inativo

    md = render_markdown(report, cfg)
    assert "🔴 DOWN" in md
    assert "## 2. Mapeamento Estruturado de Portas" in md  # seção existe, porém vazia


def test_scanner_build_nmap_args_privileged(cfg):
    # Verifica que as flags stealth aparecem quando privilegiado
    argv = scanner.build_nmap_args("45.33.32.156", [("tcp", 22), ("tcp", 80)], cfg,
                                   privileged=True, xml_out="-")
    joined = " ".join(argv)
    assert "-sS" in argv and "-sV" in argv and "-O" in argv
    assert "--reason" in argv and "-f" in argv
    assert "--data-length" in joined and "-T2" in joined
    assert "T:22,80" in joined
    assert argv[-3:] == ["-oX", "-", "45.33.32.156"]


def test_scanner_build_nmap_args_unprivileged(cfg):
    # Sem privilégio: connect scan, sem -sS/-O/-f
    argv = scanner.build_nmap_args("45.33.32.156", [("tcp", 80)], cfg,
                                   privileged=False, xml_out="-")
    assert "-sT" in argv
    assert "-sS" not in argv and "-O" not in argv and "-f" not in argv


def test_scanner_evasion_flags(cfg):
    # Técnicas avançadas de evasão só entram quando privilegiado.
    cfg["nmap"]["decoys"] = "RND:5"
    cfg["nmap"]["mtu"] = 24
    cfg["nmap"]["source_port"] = 53
    cfg["nmap"]["spoof_mac"] = "0"
    argv = scanner.build_nmap_args("45.33.32.156", [("tcp", 80)], cfg,
                                   privileged=True, xml_out="-")
    joined = " ".join(argv)
    assert "-D RND:5" in joined
    assert "--mtu 24" in joined
    assert "-g 53" in joined
    assert "--spoof-mac 0" in joined

    # Sem privilégio, nenhuma evasão de raw socket aparece.
    argv2 = scanner.build_nmap_args("45.33.32.156", [("tcp", 80)], cfg,
                                    privileged=False, xml_out="-")
    j2 = " ".join(argv2)
    assert "-D" not in argv2 and "--mtu" not in j2 and "-g" not in argv2


def test_scanner_nse_scripts_consolidated(cfg):
    cfg["nmap"]["nse_scripts"] = ["vulners", "http-enum", "smb-vuln*"]
    cfg["nmap"]["nse_vuln_scripts"] = True  # atalho legado -> 'vuln'
    argv = scanner.build_nmap_args("45.33.32.156", [("tcp", 80)], cfg,
                                   privileged=True, xml_out="-")
    i = argv.index("--script")
    scripts = argv[i + 1]
    assert "vulners" in scripts and "http-enum" in scripts and "smb-vuln*" in scripts
    assert "vuln" in scripts.split(",")


def test_scanner_aggressive_flag(cfg):
    cfg["nmap"]["aggressive"] = True
    argv = scanner.build_nmap_args("45.33.32.156", [("tcp", 80)], cfg,
                                   privileged=True, xml_out="-")
    assert "-A" in argv


def test_scanner_evasion_disabled_fallback(cfg):
    # evasion=False (fallback de confiabilidade) remove fragmentação/padding/decoy.
    cfg["nmap"]["decoys"] = "RND:5"
    argv = scanner.build_nmap_args("45.33.32.156", [("tcp", 80)], cfg,
                                   privileged=True, xml_out="-", evasion=False)
    joined = " ".join(argv)
    assert "-f" not in argv
    assert "--data-length" not in joined
    assert "-D" not in argv
    # mas o scan em si continua (SYN + versão)
    assert "-sS" in argv and "-sV" in argv
