"""Carga de configuração.

FILOSOFIA: o fluxo do Draco é FIXO. A config guarda apenas *valores de ajuste*
(taxas, timings, portas, timeouts, caminhos, chaves de API).
A ferramenta sempre segue a mesma esteira:
descoberta → masscan → nmap → nuclei (se web) → CVEs → relatório.

Chaves de API podem vir do ambiente.
"""

from __future__ import annotations

import copy
import os
from typing import Any


# ---------------------------------------------------------------------------
# Defaults — SOMENTE valores de ajuste (nenhum liga/desliga de fluxo).
# ---------------------------------------------------------------------------
DEFAULTS: dict[str, Any] = {
    "logging": {
        "engine_tag": "DRACO-ENGINE",
        "level": "INFO",
        "console": True,
        "color": True,
        "timestamps": True,
    },
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
        "searchsploit": {"enabled": True},
        "online": {
            "enabled": True,
            "timeout_seconds": 10,
            "max_retries": 2,
            "fail_open": True,
            "nvd": {
                "base_url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
                "api_key": ""
            },
            "vulners": {
                "base_url": "https://vulners.com/api/v3/burp/software/",
                "api_key": ""
            }
        }
    },
    "report": {
        "strategy_label": "Stealth Recon (SYN Scan / T2 / Packet Fragmentation)",
    },
}


class Config:
    """Wrapper leve sobre o dicionário de configuração."""

    def __init__(self, data: dict):
        self.data = data

    @classmethod
    def load(cls) -> "Config":
        """Carrega os valores padrão e injeta variáveis de ambiente."""
        cfg = cls(copy.deepcopy(DEFAULTS))
        cfg._apply_env_overrides()
        return cfg

    def _apply_env_overrides(self) -> None:
        """Carrega do arquivo .env (se existir) e mapeia chaves de API."""
        env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
        if os.path.exists(env_path):
            with open(env_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and "=" in line and not line.startswith("#"):
                        k, v = line.split("=", 1)
                        os.environ.setdefault(k.strip(), v.strip().strip("'\""))

        corr = self.data["correlation"]["online"]
        if not corr["nvd"].get("api_key"):
            corr["nvd"]["api_key"] = os.environ.get("NVD_API_KEY", "")
        if not corr["vulners"].get("api_key"):
            corr["vulners"]["api_key"] = os.environ.get("VULNERS_API_KEY", "")

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


def load_config() -> Config:
    """Atalho funcional para Config.load()."""
    return Config.load()
