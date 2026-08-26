"""Motor de logs no padrão [DRACO-ENGINE].

Reproduz exatamente o estilo dos PDFs, por exemplo:

    [DRACO-ENGINE] [INFO] Alvo carregado: scanme.nmap.org (45.33.32.156)
    [DRACO-ENGINE] Executando comando: nmap -sS -Pn -p 1-1024 -T2 -f --reason 45.33.32.156
    [DRACO-ENGINE] [RESULTADO] - Porta 22/tcp | Estado: OPEN | Razão: syn-ack
    [DRACO-ENGINE] [FOUND] CVE-2014-0226 (CVSS 6.8) - Apache HTTP Server Race Condition.
    [NUCLEI] [http-missing-security-headers] [LOW] http://scanme.nmap.org

Escreve no console (com cor opcional quando TTY) e/ou em arquivo de log.
"""

from __future__ import annotations

import datetime
import os
import sys

_LEVELS = {"DEBUG": 10, "INFO": 20, "WARNING": 30, "ERROR": 40}

# Cores ANSI por rótulo (aplicadas apenas ao prefixo/rótulo, não ao texto todo)
_COLORS = {
    "INFO": "\033[36m",       # ciano
    "RESULTADO": "\033[32m",  # verde
    "FOUND": "\033[31m",      # vermelho
    "VULN-CHECK": "\033[35m", # magenta
    "SERVIÇOS": "\033[34m",   # azul
    "WARN": "\033[33m",       # amarelo
    "ERRO": "\033[31m",       # vermelho
    "NUCLEI": "\033[35m",     # magenta
    "reset": "\033[0m",
}


class DracoLogger:
    """Logger centralizado da engine.

    Pode ser construído a partir da configuração (``DracoLogger.from_config``)
    ou diretamente com defaults, o que o torna utilizável de forma isolada em
    testes ou numa futura GUI/API.
    """

    def __init__(
        self,
        tag: str = "DRACO-ENGINE",
        level: str = "INFO",
        console: bool = True,
        file_path: str | None = None,
        color: bool = True,
        timestamps: bool = True,
    ):
        self.tag = tag
        self.level = _LEVELS.get(str(level).upper(), 20)
        self.console = console
        self.timestamps = timestamps
        self.file_path = file_path
        self._fh = None
        # Cor só faz sentido em terminal interativo.
        self.color = color and sys.stdout.isatty()
        if file_path:
            os.makedirs(os.path.dirname(file_path) or ".", exist_ok=True)
            # buffering=1 => line-buffered, para o log persistir mesmo se cair no meio.
            self._fh = open(file_path, "a", encoding="utf-8", buffering=1)

    # -- construção a partir da config -----------------------------------
    @classmethod
    def from_config(cls, cfg, run_stamp: str | None = None) -> DracoLogger:
        logcfg = cfg["logging"]
        file_path = None
        if True:
            logs_dir = cfg["paths"]["logs_dir"]
            stamp = run_stamp or datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            file_path = os.path.join(logs_dir, f"draco_{stamp}.log")
        return cls(
            tag=logcfg.get("engine_tag", "DRACO-ENGINE"),
            level=logcfg.get("level", "INFO"),
            console=logcfg.get("console", True),
            file_path=file_path,
            color=logcfg.get("color", True),
            timestamps=logcfg.get("timestamps", True),
        )

    # -- infra de escrita ------------------------------------------------
    def _emit(self, line: str, min_level: int = 20, color_key: str | None = None) -> None:
        if min_level < self.level:
            return
        ts = ""
        if self.timestamps:
            ts = datetime.datetime.now().strftime("%H:%M:%S ")
        plain = f"{ts}{line}"
        # Console (com cor opcional no prefixo)
        if self.console:
            if self.color and color_key and color_key in _COLORS:
                colored = f"{ts}{_COLORS[color_key]}{line}{_COLORS['reset']}"
                print(colored)
            else:
                print(plain)
        # Arquivo (sempre sem cor)
        if self._fh:
            self._fh.write(plain + "\n")

    def _p(self, s: str) -> str:
        return f"[{self.tag}] {s}"

    # -- API de níveis ---------------------------------------------------
    def debug(self, msg: str) -> None:
        self._emit(self._p(f"[DEBUG] {msg}"), _LEVELS["DEBUG"])

    def info(self, msg: str) -> None:
        self._emit(self._p(f"[INFO] {msg}"), _LEVELS["INFO"], "INFO")

    def warning(self, msg: str) -> None:
        self._emit(self._p(f"[WARN] {msg}"), _LEVELS["WARNING"], "WARN")

    def error(self, msg: str) -> None:
        self._emit(self._p(f"[ERRO] {msg}"), _LEVELS["ERROR"], "ERRO")

    # -- API semântica (espelha os exemplos dos PDFs) --------------------
    def command(self, argv: list[str]) -> None:
        """[DRACO-ENGINE] Executando comando: <cmd>"""
        self._emit(self._p("Executando comando: " + " ".join(argv)), _LEVELS["INFO"])

    def resultado(self, msg: str) -> None:
        """[DRACO-ENGINE] [RESULTADO] - Porta 22/tcp | Estado: OPEN | Razão: syn-ack"""
        self._emit(self._p(f"[RESULTADO] {msg}"), _LEVELS["INFO"], "RESULTADO")

    def servico(self, msg: str) -> None:
        """[DRACO-ENGINE] [SERVIÇOS DETECTADOS] - 22/tcp: OpenSSH 7.7p1 ..."""
        self._emit(self._p(f"[SERVIÇOS DETECTADOS] {msg}"), _LEVELS["INFO"], "SERVIÇOS")

    def vuln_check(self, msg: str) -> None:
        """[DRACO-ENGINE] [VULN-CHECK] Consultando CVEs para Apache 2.4.7..."""
        self._emit(self._p(f"[VULN-CHECK] {msg}"), _LEVELS["INFO"], "VULN-CHECK")

    def found(self, msg: str) -> None:
        """[DRACO-ENGINE] [FOUND] CVE-2014-0226 (CVSS 6.8) - ..."""
        self._emit(self._p(f"[FOUND] {msg}"), _LEVELS["INFO"], "FOUND")

    def nuclei(self, msg: str) -> None:
        """[NUCLEI] [template-id] [SEVERITY] <url>"""
        self._emit(f"[NUCLEI] {msg}", _LEVELS["INFO"], "NUCLEI")

    # -- ciclo de vida ---------------------------------------------------
    def close(self) -> None:
        if self._fh:
            try:
                self._fh.close()
            finally:
                self._fh = None

    def __enter__(self) -> DracoLogger:
        return self

    def __exit__(self, *exc) -> None:
        self.close()
