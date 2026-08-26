"""Testes do Épico 1 — ingestão, validação e gate de escopo."""

import pytest

from draco import ingest
from draco.ingest import IngestError, check_scope, classify
from draco.models import Target


# ---- validação de sintaxe -------------------------------------------------
@pytest.mark.parametrize(
    "value,expected",
    [
        ("45.33.32.156", "ip"),
        ("192.168.0.1", "ip"),
        ("scanme.nmap.org", "domain"),
        ("sub.dominio.com.br", "domain"),
        ("999.999.1.1", None),       # octetos inválidos
        ("not a host", None),        # espaço
        ("", None),
    ],
)
def test_classify(value, expected):
    assert classify(value) == expected


# ---- leitura do arquivo ---------------------------------------------------
def test_read_missing_file():
    with pytest.raises(IngestError):
        ingest.read_targets_file("/caminho/inexistente/targets.txt")


def test_read_empty_file(tmp_path):
    f = tmp_path / "vazio.txt"
    f.write_text("# só comentário\n\n   \n")
    with pytest.raises(IngestError):
        ingest.read_targets_file(str(f))


def test_read_valid_file(tmp_path):
    f = tmp_path / "t.txt"
    f.write_text("# alvo\nscanme.nmap.org\n45.33.32.156\n")
    entries = ingest.read_targets_file(str(f))
    assert entries == ["scanme.nmap.org", "45.33.32.156"]


# ---- gate de escopo -------------------------------------------------------
# Nota: o gate estrito é OPT-IN. No modo simples (padrão) informar o alvo já
# autoriza; estes testes ligam o modo estrito explicitamente.
def _strict(cfg):
    cfg["scope"]["require_authorization_flag"] = True
    cfg["scope"]["enforce_allowlist"] = True
    return cfg


def test_scope_requires_auth_flag(cfg):
    _strict(cfg)
    t = Target(raw="scanme.nmap.org", kind="domain", ip="45.33.32.156")
    check_scope(t, cfg, authorized_flag=False)
    assert not t.in_scope
    assert "i-am-authorized" in t.scope_reason


def test_scope_allowlist_domain(cfg):
    _strict(cfg)
    cfg["scope"]["allowlist"] = ["scanme.nmap.org"]
    t = Target(raw="scanme.nmap.org", kind="domain", ip="45.33.32.156")
    check_scope(t, cfg, authorized_flag=True)
    assert t.in_scope


def test_scope_out_of_allowlist(cfg):
    _strict(cfg)
    cfg["scope"]["allowlist"] = ["scanme.nmap.org"]
    t = Target(raw="8.8.8.8", kind="ip", ip="8.8.8.8")
    check_scope(t, cfg, authorized_flag=True)
    assert not t.in_scope
    assert "allowlist" in t.scope_reason


def test_scope_cidr_match(cfg):
    _strict(cfg)
    cfg["scope"]["allowlist"] = ["192.168.0.0/16"]
    t = Target(raw="192.168.1.50", kind="ip", ip="192.168.1.50")
    check_scope(t, cfg, authorized_flag=True)
    assert t.in_scope


def test_scope_simple_mode_authorizes_any(cfg):
    # Modo simples (padrão): qualquer alvo não-negado é autorizado.
    t = Target(raw="8.8.8.8", kind="ip", ip="8.8.8.8")
    check_scope(t, cfg, authorized_flag=False)
    assert t.in_scope


def test_scope_denylist_blocks_even_simple_mode(cfg):
    cfg["scope"]["denylist"] = ["8.8.8.8"]
    t = Target(raw="8.8.8.8", kind="ip", ip="8.8.8.8")
    check_scope(t, cfg, authorized_flag=False)
    assert not t.in_scope
    assert "denylist" in t.scope_reason


def test_scope_denylist_precedence(cfg):
    cfg["scope"]["allowlist"] = ["10.0.0.0/8"]
    cfg["scope"]["denylist"] = ["10.0.0.5"]
    t = Target(raw="10.0.0.5", kind="ip", ip="10.0.0.5")
    check_scope(t, cfg, authorized_flag=True)
    assert not t.in_scope
    assert "denylist" in t.scope_reason


def test_ingest_end_to_end_scope(cfg, tmp_path):
    f = tmp_path / "t.txt"
    f.write_text("scanme.nmap.org\n8.8.8.8\n")
    _strict(cfg)
    cfg["scope"]["allowlist"] = ["scanme.nmap.org"]
    targets = ingest.ingest(str(f), cfg, authorized_flag=True)
    raws = {t.raw for t in targets}
    assert "scanme.nmap.org" in raws
    assert "8.8.8.8" not in raws  # fora do escopo
