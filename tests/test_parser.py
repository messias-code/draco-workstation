"""Testes do parser — nmap XML, masscan, nuclei JSONL, searchsploit, CPE."""

from draco.parser import (
    cpe22_to_23,
    cpe_product_version,
    nse_findings,
    parse_masscan_list,
    parse_nmap_xml,
    parse_nuclei_jsonl,
    parse_searchsploit_json,
)


# ---- nmap XML -------------------------------------------------------------
def test_parse_nmap_ports(nmap_xml):
    out = parse_nmap_xml(nmap_xml)
    ports = {p.number: p for p in out["ports"]}
    assert set(ports) == {22, 80, 139, 445}

    assert ports[22].state == "open"
    assert ports[22].reason == "syn-ack"
    assert ports[22].product == "OpenSSH"
    assert "openssh" in ports[22].cpes[0]

    assert ports[80].product == "Apache httpd"
    assert ports[80].version == "2.4.7"

    # estado + razão distinguem fechada (reset) de filtrada (no-response)
    assert ports[139].state == "closed" and ports[139].reason == "reset"
    assert ports[445].state == "filtered" and ports[445].reason == "no-response"


def test_parse_nmap_os_and_status(nmap_xml):
    out = parse_nmap_xml(nmap_xml)
    assert out["status"] == "up"
    assert "45.33.32.156" in out["addresses"]
    assert out["os_matches"][0].name.startswith("Linux")
    assert out["os_matches"][0].accuracy == 95


def test_parse_nmap_malformed_returns_empty():
    out = parse_nmap_xml("<isto nao eh xml valido")
    assert out["ports"] == [] and out["os_matches"] == []


def test_service_version_str(nmap_xml):
    ports = {p.number: p for p in parse_nmap_xml(nmap_xml)["ports"]}
    assert ports[80].service_version_str == "Apache httpd 2.4.7 (Ubuntu)"


# ---- masscan --------------------------------------------------------------
def test_parse_masscan_list(masscan_list):
    ports = parse_masscan_list(masscan_list)
    assert ("tcp", 22) in ports
    assert ("tcp", 80) in ports
    assert ("udp", 123) in ports


# ---- nuclei ---------------------------------------------------------------
def test_parse_nuclei(nuclei_jsonl):
    vulns = parse_nuclei_jsonl(nuclei_jsonl)
    ids = {v.identifier for v in vulns}
    assert "http-missing-security-headers" in ids
    assert "CVE-2017-15710" in ids
    # severidade e porta derivada da URL
    cve = next(v for v in vulns if v.identifier == "CVE-2017-15710")
    assert cve.severity == "medium"
    assert cve.cvss == 5.9
    assert cve.port == 443  # https


# ---- searchsploit ---------------------------------------------------------
def test_parse_searchsploit(searchsploit_json):
    records = parse_searchsploit_json(searchsploit_json)
    assert len(records) == 2
    assert records[0]["Codes"] == "CVE-2014-0226"


# ---- CPE helpers ----------------------------------------------------------
def test_cpe22_to_23():
    got = cpe22_to_23("cpe:/a:apache:http_server:2.4.7")
    assert got == "cpe:2.3:a:apache:http_server:2.4.7:*:*:*:*:*:*:*"


def test_cpe22_to_23_idempotent():
    already = "cpe:2.3:a:apache:http_server:2.4.7:*:*:*:*:*:*:*"
    assert cpe22_to_23(already) == already


def test_cpe_product_version():
    vendor, product, version = cpe_product_version("cpe:/a:openbsd:openssh:7.7p1")
    assert (vendor, product, version) == ("openbsd", "openssh", "7.7p1")


# ---- NSE (scripts) --------------------------------------------------------
def test_nse_scripts_attached_to_ports(nmap_nse_xml):
    parsed = parse_nmap_xml(nmap_nse_xml)
    ports = {p.number: p for p in parsed["ports"]}
    assert any(s["id"] == "vulners" for s in ports[22].scripts)
    assert any(s["id"] == "http-enum" for s in ports[80].scripts)
    # host-level script (smb-vuln) capturado
    assert any(s["id"].startswith("smb-vuln") for s in parsed["host_scripts"])


def test_nse_vulners_extracts_cve_cvss(nmap_nse_xml):
    parsed = parse_nmap_xml(nmap_nse_xml)
    findings = nse_findings(parsed)
    vulners = {v.identifier: v for v in findings if v.source == "nse:vulners"}
    assert "CVE-2018-15473" in vulners
    assert vulners["CVE-2018-15473"].cvss == 5.3
    assert vulners["CVE-2018-15473"].port == 22
    assert vulners["CVE-2018-15473"].normalized_severity() == "medium"


def test_nse_smb_vuln_high_severity(nmap_nse_xml):
    findings = nse_findings(parse_nmap_xml(nmap_nse_xml))
    smb = next(v for v in findings if v.source.startswith("nse:smb-vuln"))
    assert smb.severity == "high"
    assert smb.identifier == "CVE-2017-0143"


def test_nse_http_enum_captured(nmap_nse_xml):
    findings = nse_findings(parse_nmap_xml(nmap_nse_xml))
    he = next(v for v in findings if v.source == "nse:http-enum")
    assert he.severity == "info"
    assert "server-status" in he.description


def test_nse_ignores_pure_info_scripts(nmap_nse_xml):
    # http-title não deve virar finding (sem CVE/VULNERABLE)
    findings = nse_findings(parse_nmap_xml(nmap_nse_xml))
    assert not any(v.source == "nse:http-title" for v in findings)
