"""Execução segura de binários externos.

Regras de segurança aplicadas aqui (requisito de engenharia):
  * NUNCA usa shell=True.
  * NUNCA interpola entrada de alvo não validada: os argumentos são passados
    como lista (argv), então o SO não reinterpreta metacaracteres de shell.
  * Todo erro (binário ausente, timeout, saída malformada) vira um
    CommandResult com `error` preenchido — jamais derruba o processo.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field


@dataclass
class CommandResult:
    """Resultado normalizado de uma execução de subprocesso."""

    argv: list[str]
    returncode: int | None = None
    stdout: str = ""
    stderr: str = ""
    duration: float = 0.0
    timed_out: bool = False
    error: str | None = None            # binário ausente / timeout / exceção
    extra: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        """True quando o comando rodou e retornou 0, sem erro de infraestrutura."""
        return self.error is None and self.returncode == 0

    @property
    def command_str(self) -> str:
        return " ".join(self.argv)


def which(binary: str) -> str | None:
    """Resolve o caminho absoluto de um binário no PATH (ou None)."""
    return shutil.which(binary)


def is_privileged() -> bool:
    """True se o processo pode abrir raw sockets (root em Unix).

    Aproximação conservadora: euid == 0. Em ambientes com capabilities
    (cap_net_raw) sem root, o usuário pode forçar `execution.privileged: true`
    na config para pular esta checagem.
    """
    try:
        return os.geteuid() == 0  # type: ignore[attr-defined]
    except AttributeError:  # pragma: no cover - não-Unix
        return False


def resolve_privileged(setting) -> bool:
    """Interpreta o valor de config `execution.privileged` (auto|true|false)."""
    if isinstance(setting, bool):
        return setting
    if isinstance(setting, str) and setting.lower() in ("true", "yes", "1"):
        return True
    if isinstance(setting, str) and setting.lower() in ("false", "no", "0"):
        return False
    # "auto" (ou qualquer coisa) => detecta.
    return is_privileged()


def run(
    argv: list[str],
    timeout: float | None = None,
    input_text: str | None = None,
    env: dict | None = None,
) -> CommandResult:
    """Executa `argv` com segurança e devolve um CommandResult.

    Nunca levanta exceção por falha do comando: erros de infraestrutura são
    capturados e reportados em `error`.
    """
    if not argv:
        return CommandResult(argv=[], error="argv vazio")

    binary = argv[0]
    # Se veio só o nome, garante que exista no PATH para dar erro claro.
    if os.path.sep not in binary and which(binary) is None:
        return CommandResult(argv=argv, error=f"binário não encontrado no PATH: {binary}")

    start = time.monotonic()
    try:
        proc = subprocess.run(  # noqa: S603 - argv validado; shell=False
            argv,
            input=input_text,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
            check=False,
        )
        return CommandResult(
            argv=argv,
            returncode=proc.returncode,
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
            duration=time.monotonic() - start,
        )
    except subprocess.TimeoutExpired as exc:
        return CommandResult(
            argv=argv,
            duration=time.monotonic() - start,
            timed_out=True,
            stdout=(exc.stdout or "") if isinstance(exc.stdout, str) else "",
            stderr=(exc.stderr or "") if isinstance(exc.stderr, str) else "",
            error=f"timeout após {timeout}s",
        )
    except FileNotFoundError:
        return CommandResult(argv=argv, error=f"binário não encontrado: {binary}")
    except PermissionError as exc:
        return CommandResult(argv=argv, error=f"permissão negada: {exc}")
    except OSError as exc:  # pragma: no cover - condições de SO raras
        return CommandResult(argv=argv, error=f"erro de SO: {exc}")
