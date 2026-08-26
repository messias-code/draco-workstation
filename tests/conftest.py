"""Fixtures compartilhadas dos testes.

Os testes NÃO tocam a rede nem executam binários reais: usam saídas XML/JSON
capturadas em tests/fixtures/ e uma config baseada nos DEFAULTS.
"""

import os

import pytest

from draco.config import DEFAULTS, Config

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _read(name: str) -> str:
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as fh:
        return fh.read()


@pytest.fixture
def cfg():
    """Config a partir dos DEFAULTS, com online desligado p/ testes determinísticos."""
    import copy

    data = copy.deepcopy(DEFAULTS)
    data["correlation"]["online"]["enabled"] = False
    data["correlation"]["searchsploit"]["enabled"] = False  # não chamar binário real
    return Config(data)


@pytest.fixture
def nmap_xml():
    return _read("nmap_scanme.xml")


@pytest.fixture
def nuclei_jsonl():
    return _read("nuclei_scanme.jsonl")


@pytest.fixture
def searchsploit_json():
    return _read("searchsploit_apache.json")


@pytest.fixture
def masscan_list():
    return _read("masscan_scanme.list")


@pytest.fixture
def nmap_nse_xml():
    return _read("nmap_nse.xml")
