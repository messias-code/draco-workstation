"""Structs de dados do Draco-Workstation (as "estruturas" produzidas pelo parser).

Todas as etapas do pipeline (discovery -> scan -> parse -> brain -> reporter)
trocam informação por meio destas dataclasses. Manter os dados tipados aqui é o
que permite chamar cada função de forma independente e, no futuro, plugar uma
GUI/API sem reescrever a lógica.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Tabelas de apoio (severidade / estado) — usadas por relatório e correlação
# ---------------------------------------------------------------------------

# Rótulos PT-BR de severidade
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "none", "unknown"]

SEVERITY_LABEL_PT = {
    "critical": "Crítica",
    "high": "Alta",
    "medium": "Média",
    "low": "Baixa",
    "info": "Informativa",
    "none": "Nenhuma",
    "unknown": "Indeterminada",
}

SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
    "none": "🟢",
    "unknown": "⚫",
}

# Estado de porta -> emoji (relatório)
PORT_STATE_EMOJI = {
    "open": "🟢",
    "closed": "🔴",
    "filtered": "🟡",
    "open|filtered": "🟡",
    "closed|filtered": "🟡",
    "unfiltered": "🟢",
}

PORT_STATE_LABEL_PT = {
    "open": "Aberta",
    "closed": "Fechada",
    "filtered": "Filtrada",
    "open|filtered": "Aberta/Filtrada",
    "closed|filtered": "Fechada/Filtrada",
    "unfiltered": "Não filtrada",
}


def severity_from_cvss(score: float | None) -> str:
    """Converte uma nota CVSS (0-10) no rótulo de severidade canônico.

    Segue as faixas qualitativas do CVSS v3.x.
    """
    if score is None:
        return "unknown"
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "unknown"
    if s >= 9.0:
        return "critical"
    if s >= 7.0:
        return "high"
    if s >= 4.0:
        return "medium"
    if s > 0.0:
        return "low"
    return "none"


def severity_rank(severity: str) -> int:
    """Índice para ordenação (menor = mais severo)."""
    sev = (severity or "unknown").lower()
    return SEVERITY_ORDER.index(sev) if sev in SEVERITY_ORDER else len(SEVERITY_ORDER)


# ---------------------------------------------------------------------------
# Structs principais
# ---------------------------------------------------------------------------


@dataclass
class Target:
    """Alvo normalizado a partir de targets.txt."""

    raw: str                       # texto original (IP ou domínio)
    kind: str = "unknown"          # "ip" | "domain"
    ip: str | None = None       # IP resolvido (quando domínio) ou o próprio IP
    in_scope: bool = False         # passou pelo gate de escopo/autorização
    scope_reason: str = ""         # motivo (autorizado / fora da allowlist / negado)


@dataclass
class DiscoveryResult:
    """Resultado da fase de descoberta de host (Épico 2a)."""

    status: str = "DOWN"                       # "UP" | "DOWN"
    response_time_ms: float | None = None   # menor tempo de resposta observado
    methods_tried: list[str] = field(default_factory=list)
    methods_responded: list[str] = field(default_factory=list)

    @property
    def method_label(self) -> str:
        """Rótulo humano do método de checagem (ex.: 'ICMP / TCP-connect:80')."""
        if self.methods_responded:
            return " / ".join(self.methods_responded)
        if self.methods_tried:
            return " / ".join(self.methods_tried) + " (sem resposta)"
        return "N/D"


@dataclass
class Port:
    """Uma porta auditada, com estado, razão (--reason) e serviço/versão."""

    number: int
    protocol: str = "tcp"                 # "tcp" | "udp"
    state: str = "unknown"                # open | closed | filtered | ...
    reason: str = ""                      # syn-ack | reset | no-response | ...
    service_name: str = ""                # ssh, http, ...
    product: str = ""                     # OpenSSH, Apache httpd
    version: str = ""                     # 7.7p1, 2.4.7
    extrainfo: str = ""                   # (Ubuntu), protocol 2.0, ...
    cpes: list[str] = field(default_factory=list)
    scripts: list[dict] = field(default_factory=list)  # saída NSE: [{"id":..,"output":..}]

    @property
    def service_version_str(self) -> str:
        """Serviço + versão em texto legível (ex.: 'Apache httpd 2.4.7 (Ubuntu)')."""
        parts = [p for p in (self.product, self.version) if p]
        s = " ".join(parts)
        if self.extrainfo:
            s = f"{s} ({self.extrainfo})" if s else self.extrainfo
        return s or "-"


@dataclass
class OSMatch:
    """Palpite de sistema operacional do nmap (-O)."""

    name: str
    accuracy: int | None = None


@dataclass
class Vulnerability:
    """Falha correlacionada (CVE, exploit do Exploit-DB ou achado do Nuclei)."""

    identifier: str                       # CVE-2014-0226, EDB-ID, template-id do nuclei
    source: str = "unknown"               # searchsploit | nvd | vulners | nuclei
    severity: str = "unknown"             # critical|high|medium|low|info|none|unknown
    cvss: float | None = None
    title: str = ""
    description: str = ""
    port: int | None = None
    protocol: str = "tcp"
    service: str = ""                     # rótulo do serviço afetado (ex.: 'Apache 2.4.7')
    references: list[str] = field(default_factory=list)

    def normalized_severity(self) -> str:
        """Severidade coerente: se não veio rótulo mas há CVSS, deriva do CVSS."""
        if self.severity and self.severity.lower() in SEVERITY_LABEL_PT:
            return self.severity.lower()
        return severity_from_cvss(self.cvss)


@dataclass
class HostReport:
    """Agregado completo de um host — entrada única do gerador de relatório."""

    target: Target
    discovery: DiscoveryResult = field(default_factory=DiscoveryResult)
    os_matches: list[OSMatch] = field(default_factory=list)
    ports: list[Port] = field(default_factory=list)
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    recommended_vectors: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)   # comandos executados (auditabilidade)
    warnings: list[str] = field(default_factory=list)    # degradações não fatais
    strategy_label: str = ""
    started_at: str = ""                                 # ISO datetime
    finished_at: str = ""
    duration_seconds: float | None = None

    # ---- acessos convenientes ------------------------------------------
    @property
    def is_up(self) -> bool:
        return self.discovery.status == "UP"

    @property
    def open_ports(self) -> list[Port]:
        return [p for p in self.ports if p.state == "open"]

    @property
    def os_best(self) -> OSMatch | None:
        if not self.os_matches:
            return None
        return sorted(self.os_matches, key=lambda m: (m.accuracy or 0), reverse=True)[0]

    def sorted_vulnerabilities(self) -> list[Vulnerability]:
        """Vulnerabilidades ordenadas por severidade (mais crítica primeiro)."""
        return sorted(
            self.vulnerabilities,
            key=lambda v: (severity_rank(v.normalized_severity()), -(v.cvss or 0.0)),
        )
