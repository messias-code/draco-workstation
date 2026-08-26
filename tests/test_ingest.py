"""Testes do Épico 1 — ingestão, validação e gate de escopo."""

import pytest

from draco import ingest
from draco.ingest import IngestError, classify
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


