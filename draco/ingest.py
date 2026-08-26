"""Épico 1 — Ingestão e Validação de Alvos.

Responsável por:
  * ler targets.txt (ignorando comentários/linhas vazias);
  * validar a sintaxe de cada alvo (IPv4 ou domínio);
  * resolver domínios em IP (best-effort);
  * aplicar o GATE DE ESCOPO/AUTORIZAÇÃO (allowlist/denylist + --i-am-authorized).

Regra dura (Épico 1): arquivo vazio/inválido => aborta o pipeline com log de erro.
"""

from __future__ import annotations

import ipaddress
import re
import socket

from .models import Target

# FQDN: rótulos alfanuméricos separados por ponto, com pelo menos um ponto.
# O TLD (último rótulo) deve conter ao menos uma letra — isso rejeita entradas
# puramente numéricas como "999.999.1.1", que não são domínios nem IPs válidos.
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+"          # 1+ rótulos, cada um seguido de ponto
    r"(?!-)(?=[A-Za-z0-9-]{1,63}$)[A-Za-z0-9-]*[A-Za-z][A-Za-z0-9-]*(?<!-)$"  # TLD com letra
)


class IngestError(Exception):
    """Erro fatal de ingestão (arquivo ausente/vazio/sem alvos válidos)."""


# ---------------------------------------------------------------------------
# Validação de sintaxe
# ---------------------------------------------------------------------------
def is_valid_ipv4(value: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv4Address)
    except ValueError:
        return False


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_valid_domain(value: str) -> bool:
    return bool(_DOMAIN_RE.match(value))


def classify(raw: str) -> str | None:
    """Retorna 'ip', 'domain' ou None (inválido)."""
    if is_valid_ip(raw):
        return "ip"
    if is_valid_domain(raw):
        return "domain"
    return None


# ---------------------------------------------------------------------------
# Leitura do arquivo
# ---------------------------------------------------------------------------
def read_targets_file(path: str) -> list[str]:
    """Lê linhas úteis de targets.txt. Erros fatais viram IngestError."""
    try:
        with open(path, encoding="utf-8") as fh:
            lines = fh.readlines()
    except FileNotFoundError as exc:
        raise IngestError(f"Arquivo de alvos não encontrado: {path}") from exc
    except OSError as exc:
        raise IngestError(f"Falha ao ler {path}: {exc}") from exc

    entries: list[str] = []
    for line in lines:
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        entries.append(s)
    if not entries:
        raise IngestError(f"Nenhum alvo válido em {path} (arquivo vazio ou só comentários).")
    return entries


def resolve_ip(target: Target) -> None:
    """Preenche target.ip. Para IP é ele mesmo; para domínio, resolve via DNS."""
    if target.kind == "ip":
        target.ip = target.raw
        return
    try:
        target.ip = socket.gethostbyname(target.raw)
    except OSError:
        target.ip = None  # sem DNS: seguimos com o hostname, discovery ainda tenta


# ---------------------------------------------------------------------------
# Gate de escopo / autorização
# ---------------------------------------------------------------------------
def _match_scope_entry(entry: str, target: Target) -> bool:
    """True se `entry` (IP, CIDR ou domínio) casa com o alvo."""
    entry = entry.strip()
    if not entry:
        return False
    # CIDR / rede
    if "/" in entry:
        try:
            net = ipaddress.ip_network(entry, strict=False)
            for candidate in (target.ip, target.raw):
                if candidate and is_valid_ip(candidate) and ipaddress.ip_address(candidate) in net:
                    return True
        except ValueError:
            return False
        return False
    # IP exato
    if is_valid_ip(entry):
        return entry in (target.ip, target.raw)
    # Domínio: casa exato ou subdomínio
    host = target.raw.lower()
    entry_l = entry.lower()
    return host == entry_l or host.endswith("." + entry_l)


def check_scope(target: Target, cfg, authorized_flag: bool) -> Target:
    """Aplica allowlist/denylist e a flag de autorização. Preenche in_scope/scope_reason."""
    scope = cfg["scope"]

    # 1) Flag global de autorização
    if scope.get("require_authorization_flag", True) and not authorized_flag:
        target.in_scope = False
        target.scope_reason = "faltou --i-am-authorized (autorização explícita de escopo)"
        return target

    # 2) Denylist tem precedência
    for entry in scope.get("denylist", []) or []:
        if _match_scope_entry(str(entry), target):
            target.in_scope = False
            target.scope_reason = f"alvo na denylist ({entry})"
            return target

    # 3) Allowlist
    if scope.get("enforce_allowlist", True):
        allow = scope.get("allowlist", []) or []
        for entry in allow:
            if _match_scope_entry(str(entry), target):
                target.in_scope = True
                target.scope_reason = f"autorizado pela allowlist ({entry})"
                return target
        target.in_scope = False
        target.scope_reason = "fora da allowlist de escopo"
        return target

    # allowlist desabilitada => autorizado (não recomendado)
    target.in_scope = True
    target.scope_reason = "allowlist desabilitada (enforce_allowlist=false)"
    return target


# ---------------------------------------------------------------------------
# Orquestração da ingestão
# ---------------------------------------------------------------------------
def ingest(path: str, cfg, authorized_flag: bool, logger=None) -> list[Target]:
    """Pipeline de ingestão completo.

    Retorna a lista de alvos DENTRO do escopo. Alvos inválidos ou fora do
    escopo são apenas registrados (não abortam o processo). Só aborta
    (IngestError) quando não há NENHUM alvo válido a considerar.
    """
    raw_entries = read_targets_file(path)  # pode levantar IngestError (fatal)

    valid: list[Target] = []
    for raw in raw_entries:
        kind = classify(raw)
        if kind is None:
            if logger:
                logger.error(f"Alvo com sintaxe inválida ignorado: {raw!r}")
            continue
        target = Target(raw=raw, kind=kind)
        resolve_ip(target)
        valid.append(target)
        if logger:
            ipinfo = f" ({target.ip})" if target.ip and target.ip != raw else ""
            logger.info(f"Alvo carregado: {raw}{ipinfo}")

    if not valid:
        raise IngestError("Nenhum alvo com sintaxe válida em targets.txt.")

    in_scope: list[Target] = []
    for target in valid:
        check_scope(target, cfg, authorized_flag)
        if target.in_scope:
            in_scope.append(target)
            if logger:
                logger.info(f"Escopo OK: {target.raw} — {target.scope_reason}")
        else:
            if logger:
                logger.error(f"Alvo FORA DE ESCOPO abortado: {target.raw} — {target.scope_reason}")

    return in_scope
