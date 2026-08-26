"""Parsers das saídas brutas das ferramentas -> structs de draco.models.

Fontes suportadas:
  * Nmap XML (-oX)          -> lista de Port + OSMatch + metadados
  * Masscan lista (-oL)     -> conjunto de (protocolo, porta) abertas
  * Nuclei JSONL (-jsonl)   -> lista de Vulnerability (source='nuclei')
  * SearchSploit JSON (--json) -> lista de dicts de exploit (crus)

Todo parser é tolerante a saída malformada: em vez de estourar, registra e
retorna o que conseguiu extrair.
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET

from .models import OSMatch, Port, Vulnerability, severity_from_cvss

# CVE + nota CVSS na saída do script vulners (ex.: "CVE-2018-15473  5.3  https://...")
_CVE_CVSS_RE = re.compile(r"(CVE-\d{4}-\d{4,7})\s+(\d+(?:\.\d+)?)")
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")


# ---------------------------------------------------------------------------
# CPE helpers
# ---------------------------------------------------------------------------
def cpe22_to_23(cpe: str) -> str | None:
    """Converte CPE 2.2 (cpe:/a:apache:http_server:2.4.7) em 2.3.

    Ex.: -> cpe:2.3:a:apache:http_server:2.4.7:*:*:*:*:*:*:*
    Necessário para consultar a API 2.0 do NVD.
    """
    if not cpe:
        return None
    cpe = cpe.strip()
    if cpe.startswith("cpe:2.3:"):
        return cpe
    if not cpe.startswith("cpe:/"):
        return None
    body = cpe[len("cpe:/"):]
    parts = body.split(":")  # part, vendor, product, version, update, edition, lang
    # Garante 7 campos do 2.2, depois completa até 11 do 2.3 com '*'
    while len(parts) < 7:
        parts.append("")
    fields = [p if p else "*" for p in parts[:7]]
    fields += ["*"] * (11 - len(fields))
    return "cpe:2.3:" + ":".join(fields)


def cpe_product_version(cpe: str) -> tuple[str, str, str]:
    """Extrai (vendor, product, version) de uma string CPE 2.2 ou 2.3."""
    if not cpe:
        return "", "", ""
    if cpe.startswith("cpe:2.3:"):
        parts = cpe.split(":")
        # cpe:2.3:part:vendor:product:version:...
        vendor = parts[3] if len(parts) > 3 else ""
        product = parts[4] if len(parts) > 4 else ""
        version = parts[5] if len(parts) > 5 else ""
    elif cpe.startswith("cpe:/"):
        parts = cpe[len("cpe:/"):].split(":")
        vendor = parts[1] if len(parts) > 1 else ""
        product = parts[2] if len(parts) > 2 else ""
        version = parts[3] if len(parts) > 3 else ""
    else:
        return "", "", ""
    clean = lambda x: "" if x in ("*", "-") else x  # noqa: E731
    return clean(vendor), clean(product), clean(version)


# ---------------------------------------------------------------------------
# Nmap XML
# ---------------------------------------------------------------------------
def parse_nmap_xml(xml_data: str) -> dict:
    """Faz o parse de um relatório XML do nmap.

    Retorna dict:
        {
          "ports": [Port, ...],
          "os_matches": [OSMatch, ...],
          "hostnames": [...],
          "addresses": [...],
          "status": "up"|"down"|None,
        }
    Aceita tanto o XML em string quanto o caminho de um arquivo.
    """
    out = {
        "ports": [], "os_matches": [], "hostnames": [], "addresses": [],
        "status": None, "host_scripts": [],
    }
    if not xml_data:
        return out
    try:
        # Permite passar caminho de arquivo ou o XML direto.
        if xml_data.lstrip().startswith("<"):
            root = ET.fromstring(xml_data)
        else:
            root = ET.parse(xml_data).getroot()
    except (ET.ParseError, OSError):
        return out

    host = root.find("host")
    if host is None:
        return out

    status_el = host.find("status")
    if status_el is not None:
        out["status"] = status_el.get("state")

    for addr in host.findall("address"):
        a = addr.get("addr")
        if a:
            out["addresses"].append(a)

    hostnames_el = host.find("hostnames")
    if hostnames_el is not None:
        for hn in hostnames_el.findall("hostname"):
            name = hn.get("name")
            if name:
                out["hostnames"].append(name)

    ports_el = host.find("ports")
    if ports_el is not None:
        for port_el in ports_el.findall("port"):
            out["ports"].append(_parse_port_el(port_el))

    os_el = host.find("os")
    if os_el is not None:
        for match in os_el.findall("osmatch"):
            acc = match.get("accuracy")
            out["os_matches"].append(
                OSMatch(name=match.get("name", "?"), accuracy=int(acc) if acc else None)
            )

    # Scripts NSE de nível de host (ex.: smb-vuln* aparecem em <hostscript>).
    hostscript_el = host.find("hostscript")
    if hostscript_el is not None:
        for script_el in hostscript_el.findall("script"):
            out["host_scripts"].append(_parse_script_el(script_el))

    return out


def _parse_script_el(script_el) -> dict:
    """Extrai {id, output} de um elemento <script> do NSE."""
    return {
        "id": script_el.get("id", "nse"),
        "output": (script_el.get("output") or "").strip(),
    }


def nse_findings(parsed: dict) -> list[Vulnerability]:
    """Converte a saída dos scripts NSE (portas + host) em Vulnerabilities.

    Tratamentos especiais:
      * vulners        -> extrai pares (CVE, CVSS) e cria 1 finding por CVE;
      * *vuln* / smb-vuln* com 'VULNERABLE' -> finding de alta severidade;
      * http-enum      -> consolida os caminhos descobertos num finding informativo;
      * demais scripts com CVE ou 'VULNERABLE' na saída -> finding informativo.
    Scripts puramente informativos (http-title, etc.) são ignorados aqui — eles
    permanecem em Port.scripts para inspeção, mas não poluem a tabela de CVEs.
    """
    findings: list[Vulnerability] = []

    def _handle(scripts: list[dict], port_num, proto, service_lbl):
        for sc in scripts or []:
            findings.extend(_script_to_vulns(sc, port_num, proto, service_lbl))

    for port in parsed.get("ports", []):
        _handle(port.scripts, port.number, port.protocol, port.service_version_str)
    _handle(parsed.get("host_scripts", []), None, "tcp", "host")
    return findings


def _script_to_vulns(sc: dict, port_num, proto, service_lbl) -> list[Vulnerability]:
    sid = sc.get("id", "nse")
    output = sc.get("output", "") or ""
    vulns: list[Vulnerability] = []

    # 1) vulners: pares CVE + CVSS
    if "vulners" in sid:
        for cve, score in _CVE_CVSS_RE.findall(output):
            s = float(score)
            vulns.append(
                Vulnerability(
                    identifier=cve, source="nse:vulners", cvss=s,
                    severity=severity_from_cvss(s), title=cve,
                    description=f"NSE vulners: {cve} associado a {service_lbl}.",
                    port=port_num, protocol=proto, service=service_lbl,
                )
            )
        if vulns:
            return vulns

    # 2) scripts de vulnerabilidade explícita (vuln, smb-vuln*, etc.)
    upper = output.upper()
    if "vuln" in sid or "VULNERABLE" in upper:
        cve = next(iter(_CVE_RE.findall(output)), sid)
        is_vuln = "VULNERABLE" in upper
        vulns.append(
            Vulnerability(
                identifier=cve,
                source=f"nse:{sid}",
                severity="high" if is_vuln else "medium",
                title=sid,
                description=_snippet(output) or f"Script NSE {sid} reportou achado.",
                port=port_num, protocol=proto, service=service_lbl,
            )
        )
        return vulns

    # 3) http-enum: consolida caminhos descobertos
    if sid == "http-enum" and output:
        vulns.append(
            Vulnerability(
                identifier="http-enum", source="nse:http-enum", severity="info",
                title="Diretórios/arquivos descobertos (http-enum)",
                description=_snippet(output),
                port=port_num, protocol=proto, service=service_lbl,
            )
        )
        return vulns

    # 4) qualquer script cuja saída contenha CVE
    cves = _CVE_RE.findall(output)
    for cve in dict.fromkeys(cves):  # únicos, ordem preservada
        vulns.append(
            Vulnerability(
                identifier=cve, source=f"nse:{sid}", severity="unknown",
                title=sid, description=_snippet(output),
                port=port_num, protocol=proto, service=service_lbl,
            )
        )
    return vulns


def _snippet(text: str, limit: int = 280) -> str:
    """Compacta a saída multi-linha do NSE numa descrição curta."""
    flat = re.sub(r"\s+", " ", text or "").strip()
    return flat[: limit - 3] + "..." if len(flat) > limit else flat


def _parse_port_el(port_el) -> Port:
    number = int(port_el.get("portid", "0"))
    protocol = port_el.get("protocol", "tcp")

    state_el = port_el.find("state")
    state = state_el.get("state", "unknown") if state_el is not None else "unknown"
    reason = state_el.get("reason", "") if state_el is not None else ""

    port = Port(number=number, protocol=protocol, state=state, reason=reason)

    svc = port_el.find("service")
    if svc is not None:
        port.service_name = svc.get("name", "") or ""
        port.product = svc.get("product", "") or ""
        port.version = svc.get("version", "") or ""
        port.extrainfo = svc.get("extrainfo", "") or ""
        for cpe_el in svc.findall("cpe"):
            if cpe_el.text:
                port.cpes.append(cpe_el.text.strip())

    # Scripts NSE associados à porta (vulners, http-enum, http-*, etc.)
    for script_el in port_el.findall("script"):
        port.scripts.append(_parse_script_el(script_el))
    return port


# ---------------------------------------------------------------------------
# Masscan (-oL, formato "lista")
# ---------------------------------------------------------------------------
def parse_masscan_list(text: str) -> list[tuple[str, int]]:
    """Parse do formato -oL do masscan.

    Linhas úteis: 'open tcp 80 45.33.32.156 1690000000'
    Retorna lista de (protocolo, porta) únicas e abertas.
    """
    found: set[tuple[str, int]] = set()
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 4 and parts[0] == "open":
            proto = parts[1]
            try:
                port = int(parts[2])
            except ValueError:
                continue
            found.add((proto, port))
    return sorted(found, key=lambda x: (x[0], x[1]))


def parse_masscan_json(text: str) -> list[tuple[str, int]]:
    """Parse do formato -oJ do masscan (fallback ao -oL)."""
    found: set[tuple[str, int]] = set()
    try:
        # masscan -oJ produz um array JSON (às vezes com vírgula/linha extra).
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return []
    for rec in data if isinstance(data, list) else []:
        for p in rec.get("ports", []):
            proto = p.get("proto", "tcp")
            port = p.get("port")
            if isinstance(port, int) and p.get("status", "open") == "open":
                found.add((proto, port))
    return sorted(found, key=lambda x: (x[0], x[1]))


# ---------------------------------------------------------------------------
# Nuclei (JSONL)
# ---------------------------------------------------------------------------
def parse_nuclei_jsonl(text: str) -> list[Vulnerability]:
    """Cada linha do JSONL do nuclei vira uma Vulnerability (source='nuclei')."""
    vulns: list[Vulnerability] = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = rec.get("info", {}) or {}
        template_id = rec.get("template-id") or rec.get("templateID") or rec.get("template") or "?"
        severity = (info.get("severity") or "info").lower()
        matched = rec.get("matched-at") or rec.get("host") or rec.get("matched") or ""
        classification = info.get("classification") or {}
        cvss = classification.get("cvss-score")
        refs = info.get("reference") or []
        if isinstance(refs, str):
            refs = [refs]
        port = _extract_port_from_url(matched)
        vulns.append(
            Vulnerability(
                identifier=str(template_id),
                source="nuclei",
                severity=severity,
                cvss=float(cvss) if isinstance(cvss, (int, float)) else None,
                title=info.get("name", "") or "",
                description=info.get("description", "") or (matched and f"Alvo: {matched}") or "",
                port=port,
                protocol="tcp",
                service=matched,
                references=list(refs),
            )
        )
    return vulns


def _extract_port_from_url(url: str) -> int | None:
    """Deriva a porta de uma URL http(s), incluindo defaults 80/443."""
    if not url:
        return None
    try:
        from urllib.parse import urlparse

        parsed = urlparse(url if "://" in url else "//" + url, scheme="")
        if parsed.port:
            return parsed.port
        if url.startswith("https"):
            return 443
        if url.startswith("http"):
            return 80
    except ValueError:
        return None
    return None


# ---------------------------------------------------------------------------
# SearchSploit (--json)
# ---------------------------------------------------------------------------
def parse_searchsploit_json(text: str) -> list[dict]:
    """Extrai a lista de exploits do JSON do searchsploit.

    O binário devolve {"RESULTS_EXPLOIT": [...], "RESULTS_SHELLCODE": [...]}.
    Retornamos os registros de RESULTS_EXPLOIT (crus) para a correlação mapear.
    """
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return []
    if not isinstance(data, dict):
        return []
    results = data.get("RESULTS_EXPLOIT") or []
    return [r for r in results if isinstance(r, dict)]
