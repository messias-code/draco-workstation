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
# Orquestração da ingestão
# ---------------------------------------------------------------------------
def ingest(path: str, cfg, authorized_flag: bool = True, logger=None) -> list[Target]:
    """Pipeline de ingestão completo.

    Retorna a lista de alvos. Alvos inválidos (sintaxe errada) são
    ignorados. Só aborta (IngestError) quando não há NENHUM alvo válido.
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
        target.in_scope = True
        valid.append(target)
        if logger:
            ipinfo = f" ({target.ip})" if target.ip and target.ip != raw else ""
            logger.info(f"Alvo carregado: {raw}{ipinfo}")

    if not valid:
        raise IngestError("Nenhum alvo com sintaxe válida em targets.txt.")

    return valid
