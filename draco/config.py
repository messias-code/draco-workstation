"""Carga de configuração (config/draco.yaml).

FILOSOFIA: o fluxo do Draco é FIXO. A config guarda apenas *valores de ajuste*
(taxas, timings, portas, timeouts, caminhos, chaves de API) — nunca interruptores
que liguem/desliguem etapas do pipeline. A ferramenta sempre segue a mesma esteira:
descoberta → masscan → nmap → nuclei (se web) → CVEs → relatório.

Os valores do usuário são mesclados sobre DEFAULTS seguros, de modo que um YAML
incompleto nunca quebra o pipeline. Chaves de API podem vir do ambiente.
"""

from __future__ import annotations

import copy
import os
from typing import Any, Optional

try:
    import yaml
except ImportError as exc:  # pragma: no cover - dependência declarada em requirements
    raise ImportError(
        "PyYAML é necessário. Instale com: pip install -r requirements.txt"
    ) from exc


# ---------------------------------------------------------------------------
# Defaults — SOMENTE valores de ajuste (nenhum liga/desliga de fluxo).
# ---------------------------------------------------------------------------
DEFAULTS: dict[str, Any] = {
    "paths": {
        "targets_file": "targets.txt",
        "outputs_dir": "outputs",
        "logs_dir": "logs",
        "report_filename": "relatorio_draco_{ip}_{date}.md",
    },
    "execution": {
        "host_concurrency": 4,               # nº de alvos auditados em paralelo
        "binaries": {
            "nmap": "nmap",
            "masscan": "masscan",
            "nuclei": "nuclei",
            "searchsploit": "searchsploit",
            "ping": "ping",
        },
    },
    "scope": {
        "denylist": [],                      # opcional: alvos a bloquear (IP/CIDR/domínio)
    },
    "discovery": {
        "tcp_connect_ports": [80, 443, 22, 21, 3389],
        "icmp_count": 2,
        "timeout_seconds": 2,
    },
    "masscan": {
        "rate": 500,
        "ports": {"tcp": "1-65535", "udp": "53,67,123,137,161,500,1900,5353"},
        "wait_seconds": 3,
        "timeout_seconds": 1800,
    },
    "nmap": {
        "timing_template": 2,                # -T2 (furtivo). 0..5
        "data_length": 24,                   # --data-length (padding)
        "version_intensity": 5,              # --version-intensity
        "decoys": "",                        # -D  (ex.: "RND:5")
        "mtu": None,                         # --mtu
        "source_port": None,                 # -g
        "spoof_mac": "",                     # --spoof-mac
        "nse_scripts": ["vulners"],          # scripts NSE (a saída vira CVEs no relatório)
        "timeout_seconds": 3600,
    },
    "brain": {
        "web_ports": [80, 443, 8080, 8443],  # portas que disparam o Nuclei
    },
    "nuclei": {
        "severities": ["info", "low", "medium", "high", "critical"],
        "rate_limit": 150,
        "timeout_seconds": 900,
    },
    "correlation": {
        "online_timeout_seconds": 10,
        "online_retries": 2,
        "nvd_api_key": "",                   # opcional; ou env NVD_API_KEY
        "vulners_api_key": "",               # opcional; ou env VULNERS_API_KEY (sem chave = pulado)
    },
    "report": {
        "strategy_label": "Stealth Recon (SYN Scan / T2 / Packet Fragmentation)",
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    """Mescla `override` sobre `base` recursivamente, sem mutar os originais."""
    result = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


class Config:
    """Wrapper leve sobre o dicionário de configuração mesclado."""

    def __init__(self, data: dict):
        self.data = data

    @classmethod
    def load(cls, path: Optional[str] = None) -> "Config":
        """Carrega o YAML e mescla sobre os DEFAULTS."""
        user_data: dict = {}
        if path and os.path.isfile(path):
            with open(path, encoding="utf-8") as fh:
                loaded = yaml.safe_load(fh) or {}
            if not isinstance(loaded, dict):
                raise ValueError(f"Config inválida em {path}: raiz não é um mapeamento.")
            user_data = loaded
        cfg = cls(_deep_merge(DEFAULTS, user_data))
        cfg._apply_env_overrides()
        return cfg

    def _apply_env_overrides(self) -> None:
        """Chaves de API podem vir do ambiente (se o YAML não as definiu)."""
        corr = self.data["correlation"]
        if not corr.get("nvd_api_key"):
            corr["nvd_api_key"] = os.environ.get("NVD_API_KEY", "")
        if not corr.get("vulners_api_key"):
            corr["vulners_api_key"] = os.environ.get("VULNERS_API_KEY", "")

    def __getitem__(self, key: str) -> Any:
        return self.data[key]

    def get(self, dotted: str, default: Any = None) -> Any:
        """Acesso por caminho pontilhado, ex.: get('nmap.timeout_seconds')."""
        node: Any = self.data
        for part in dotted.split("."):
            if isinstance(node, dict) and part in node:
                node = node[part]
            else:
                return default
        return node


def load_config(path: Optional[str] = None) -> Config:
    """Atalho funcional para Config.load()."""
    return Config.load(path)
