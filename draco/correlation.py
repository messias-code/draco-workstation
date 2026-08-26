"""Épico 3 — Correlação de Vulnerabilidades.

OFFLINE-FIRST. Três fontes complementares, todas tolerantes a falha:
  * searchsploit --json  : base local do Exploit-DB (funciona sem internet);
  * NIST NVD 2.0 (HTTP)  : CVE + CVSS + descrição a partir do CPE;
  * Vulners (HTTP)       : software/version -> CVEs (exige API key).

Falhas de rede NÃO derrubam o pipeline (fail_open). A parte online é opcional.
"""

from __future__ import annotations

from .models import Port, Vulnerability, severity_from_cvss
from .parser import cpe22_to_23, cpe_product_version, parse_searchsploit_json
from .runner import run

try:
    import requests
except ImportError:  # pragma: no cover - requests está em requirements
    requests = None


# ---------------------------------------------------------------------------
# Offline: searchsploit
# ---------------------------------------------------------------------------
def searchsploit_lookup(query: str, cfg, logger=None) -> list[dict]:
    """Consulta a base local do Exploit-DB. Retorna registros crus de exploit."""
    scfg = cfg["correlation"]["searchsploit"]
    if not scfg.get("enabled", True):
        return []
    binary = cfg["execution"]["binaries"].get("searchsploit", "searchsploit")
    argv = [binary]
    if scfg.get("json", True):
        argv.append("--json")
    # query dividida em tokens => nunca vai para um shell; sem injeção.
    argv += query.split()
    if logger:
        logger.command(argv)
    result = run(argv, timeout=scfg.get("timeout_seconds", 60))
    if result.error:
        if logger:
            logger.warning(f"searchsploit indisponível: {result.error}")
        return []
    return parse_searchsploit_json(result.stdout)


def _exploits_to_vulns(records: list[dict], port: Port) -> list[Vulnerability]:
    vulns: list[Vulnerability] = []
    for rec in records:
        title = rec.get("Title") or rec.get("title") or "Exploit"
        edb = rec.get("EDB-ID") or rec.get("Codes") or rec.get("Path") or "EDB"
        # searchsploit às vezes traz CVEs no campo Codes (ex.: 'CVE-2014-0226')
        codes = str(rec.get("Codes") or "")
        cve = next((c for c in codes.replace(";", ",").split(",") if c.strip().startswith("CVE-")), "")
        identifier = cve.strip() if cve else f"EDB-{edb}"
        vulns.append(
            Vulnerability(
                identifier=identifier,
                source="searchsploit",
                severity="unknown",
                cvss=None,
                title=title,
                description=f"Exploit público no Exploit-DB: {title} (path: {rec.get('Path', '?')}).",
                port=port.number,
                protocol=port.protocol,
                service=port.service_version_str,
                references=[c.strip() for c in codes.split(",") if c.strip()],
            )
        )
    return vulns


# ---------------------------------------------------------------------------
# Online: NVD 2.0
# ---------------------------------------------------------------------------
def nvd_lookup(cpe: str, cfg, logger=None) -> list[Vulnerability]:
    """Consulta a API 2.0 do NIST NVD por CPE. Fail-open em qualquer erro."""
    online = cfg["correlation"]["online"]
    nvd = online["nvd"]
    if not (online.get("enabled", True) and nvd.get("enabled", True)) or requests is None:
        return []

    cpe23 = cpe22_to_23(cpe)
    if not cpe23:
        return []

    params = {
        "virtualMatchString": cpe23,
        "resultsPerPage": nvd.get("results_per_cpe", 20),
    }
    headers = {}
    if nvd.get("api_key"):
        headers["apiKey"] = nvd["api_key"]

    data = _http_get_json(
        nvd.get("base_url"), params, headers,
        timeout=online.get("timeout_seconds", 10),
        retries=online.get("max_retries", 2),
        fail_open=online.get("fail_open", True),
        logger=logger, provider="NVD",
    )
    if not data:
        return []

    vulns: list[Vulnerability] = []
    for item in data.get("vulnerabilities", []) or []:
        cve = item.get("cve", {}) or {}
        cve_id = cve.get("id", "CVE-?")
        description = _nvd_description(cve)
        cvss, severity = _nvd_cvss(cve)
        vulns.append(
            Vulnerability(
                identifier=cve_id,
                source="nvd",
                severity=severity,
                cvss=cvss,
                title=cve_id,
                description=description,
                references=[cpe23],
            )
        )
    return vulns


def _nvd_description(cve: dict) -> str:
    for desc in cve.get("descriptions", []) or []:
        if desc.get("lang") == "en":
            return desc.get("value", "")
    descs = cve.get("descriptions", []) or []
    return descs[0].get("value", "") if descs else ""


def _nvd_cvss(cve: dict) -> tuple[float | None, str]:
    metrics = cve.get("metrics", {}) or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key)
        if arr:
            data = arr[0].get("cvssData", {}) or {}
            score = data.get("baseScore")
            sev = (data.get("baseSeverity") or arr[0].get("baseSeverity") or "").lower()
            if score is not None:
                return float(score), (sev or severity_from_cvss(float(score)))
    return None, "unknown"


# ---------------------------------------------------------------------------
# Online: Vulners
# ---------------------------------------------------------------------------
def vulners_lookup(product: str, version: str, cfg, logger=None) -> list[Vulnerability]:
    """Consulta a API do Vulners por software/versão. Exige API key."""
    online = cfg["correlation"]["online"]
    vcfg = online["vulners"]
    if not (online.get("enabled", True) and vcfg.get("enabled", True)) or requests is None:
        return []
    if not vcfg.get("api_key"):
        if logger:
            logger.debug("Vulners pulado: sem API key (VULNERS_API_KEY).")
        return []
    if not product or not version:
        return []

    params = {
        "software": product,
        "version": version,
        "type": "software",
        "apiKey": vcfg["api_key"],
    }
    data = _http_get_json(
        vcfg.get("base_url"), params, {},
        timeout=online.get("timeout_seconds", 10),
        retries=online.get("max_retries", 2),
        fail_open=online.get("fail_open", True),
        logger=logger, provider="Vulners",
    )
    if not data or data.get("result") != "OK":
        return []

    vulns: list[Vulnerability] = []
    search = (data.get("data", {}) or {}).get("search", []) or []
    for entry in search:
        src = entry.get("_source", {}) or {}
        cvss_obj = src.get("cvss", {}) or {}
        score = cvss_obj.get("score")
        vulns.append(
            Vulnerability(
                identifier=src.get("id", "?"),
                source="vulners",
                severity=severity_from_cvss(score) if score else "unknown",
                cvss=float(score) if score else None,
                title=src.get("title", src.get("id", "")),
                description=src.get("description", "")[:500],
                references=[src.get("href", "")] if src.get("href") else [],
            )
        )
    return vulns


# ---------------------------------------------------------------------------
# HTTP util com retry/backoff e fail-open
# ---------------------------------------------------------------------------
def _http_get_json(url, params, headers, timeout, retries, fail_open, logger, provider):
    if requests is None or not url:
        return None
    last_err = None
    for attempt in range(1, int(retries) + 2):
        try:
            resp = requests.get(url, params=params, headers=headers, timeout=timeout)
            if resp.status_code == 200:
                return resp.json()
            last_err = f"HTTP {resp.status_code}"
            # 403/429 => rate limit; espera curta antes de tentar de novo
            if resp.status_code in (403, 429) and attempt <= retries:
                continue
            break
        except Exception as exc:  # noqa: BLE001 - fail-open é o requisito
            last_err = str(exc)
    if logger:
        msg = f"{provider} indisponível ({last_err})."
        if fail_open:
            logger.warning(msg + " Seguindo offline.")
        else:
            logger.error(msg)
    return None


# ---------------------------------------------------------------------------
# Orquestração da correlação por host
# ---------------------------------------------------------------------------
def correlate_port(port: Port, cfg, logger=None) -> list[Vulnerability]:
    """Correlaciona uma única porta (offline + online). Chamável isoladamente."""
    vulns: list[Vulnerability] = []

    # Deriva produto/versão do CPE (preferido) ou dos banners do nmap.
    product, version = port.product, port.version
    if port.cpes:
        _, cpe_prod, cpe_ver = cpe_product_version(port.cpes[0])
        product = product or cpe_prod
        version = version or cpe_ver

    if not product:
        if logger:
            logger.vuln_check(f"Porta {port.number}: versão desconhecida, correlação limitada.")
        return vulns

    # Versão "limpa" (só o token de versão, sem '(Ubuntu)'/'protocol 2.0') para
    # consultas menos ruidosas — o banner completo continua no relatório.
    version_q = version.split()[0] if version else ""
    query = f"{product} {version_q}".strip()
    if logger:
        logger.vuln_check(f"Consultando CVEs para {query}...")

    # 1) Offline: searchsploit
    records = searchsploit_lookup(query, cfg, logger)
    vulns += _exploits_to_vulns(records, port)

    # 2) Online: NVD por CPE
    for cpe in port.cpes:
        vulns += _tag_port(nvd_lookup(cpe, cfg, logger), port)

    # 3) Online: Vulners por software/versão
    vulns += _tag_port(vulners_lookup(product, version_q, cfg, logger), port)

    # Log dos achados
    if logger:
        for v in vulns:
            sev = v.normalized_severity()
            cvss = f" (CVSS {v.cvss})" if v.cvss is not None else ""
            title = v.title or v.description[:60]
            logger.found(f"{v.identifier}{cvss} [{sev}] - {title}")

    return vulns


def _tag_port(vulns: list[Vulnerability], port: Port) -> list[Vulnerability]:
    for v in vulns:
        v.port = port.number
        v.protocol = port.protocol
        if not v.service:
            v.service = port.service_version_str
    return vulns


def dedupe_vulnerabilities(vulns: list[Vulnerability]) -> list[Vulnerability]:
    """Remove duplicatas por (porta, identificador), preferindo quem tem CVSS."""
    best: dict[tuple, Vulnerability] = {}
    for v in vulns:
        key = (v.port, v.identifier)
        if key not in best:
            best[key] = v
            continue
        # Mantém o registro mais informativo (com CVSS / descrição maior).
        cur = best[key]
        if (v.cvss is not None and cur.cvss is None) or (len(v.description) > len(cur.description)):
            best[key] = v
    return list(best.values())
