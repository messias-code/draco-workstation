"""cli.py — Entrypoint do Draco-Workstation.

UM comando faz tudo. Descoberta -> masscan -> nmap -> nuclei -> searchsploit/NVD
-> relatório .md, encadeando automaticamente a saída de uma etapa na próxima.

    draco                      # alvo padrão: scanme.nmap.org (sancionado p/ testes)
    draco scanme.nmap.org      # um alvo
    draco 45.33.32.156         # um IP
    draco -f targets.txt       # vários alvos de um arquivo

O terminal mostra só os logs [DRACO-ENGINE]; o relatório vai para outputs/.
"""

from __future__ import annotations

import argparse
import datetime
import os
import sys
import tempfile

from .config import load_config
from .engine import run_pipeline
from .ingest import IngestError, ingest
from .logging_engine import DracoLogger

DEFAULT_TARGET = "scanme.nmap.org"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="draco",
        description="Draco-Workstation — auditoria completa de um alvo em um comando "
                    "(orquestra masscan + nmap + nuclei + searchsploit/NVD -> relatório .md).",
        epilog="Exemplos:\n"
               "  draco                     # alvo padrão scanme.nmap.org\n"
               "  draco scanme.nmap.org     # um domínio\n"
               "  draco 45.33.32.156        # um IP\n"
               "  draco -f targets.txt      # arquivo de alvos\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    # O jeito principal: um alvo posicional (domínio, IP ou caminho de arquivo).
    p.add_argument("target", nargs="?", default=None,
                   help="Alvo (domínio/IP) ou caminho de um arquivo de alvos. "
                        f"Se omitido, usa {DEFAULT_TARGET}.")
    p.add_argument("-f", "--file", default=None,
                   help="Arquivo de alvos (um por linha). Alternativa ao alvo posicional.")
    return p


def _resolve_targets_file(args, logger) -> str:
    """Decide de onde vêm os alvos e devolve um caminho de arquivo de alvos.

    Precedência: -f/--file > posicional (arquivo ou alvo único) > alvo padrão.
    """
    # 1) -f/--file explícito
    if args.file:
        return args.file

    # 2) posicional
    if args.target:
        if os.path.isfile(args.target):
            logger.info(f"Lendo alvos do arquivo: {args.target}")
            return args.target
        return _write_single_target(args.target)

    # 3) default
    logger.info(f"Nenhum alvo informado; usando o padrão de testes: {DEFAULT_TARGET}")
    return _write_single_target(DEFAULT_TARGET)


def _write_single_target(target: str) -> str:
    tmp = tempfile.NamedTemporaryFile(
        prefix="draco_target_", suffix=".txt", delete=False, mode="w", encoding="utf-8"
    )
    tmp.write(target + "\n")
    tmp.close()
    return tmp.name


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    try:
        cfg = load_config()
    except (OSError, ValueError) as exc:
        print(f"[DRACO-ENGINE] [ERRO] Falha ao carregar config: {exc}", file=sys.stderr)
        return 2

    run_stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    logger = DracoLogger.from_config(cfg, run_stamp=run_stamp)
    logger.info("Draco-Workstation iniciando — Módulo de Auditoria Ativo.")

    # Root é OBRIGATÓRIO: a varredura sênior (SYN furtivo, masscan, OS fingerprint,
    # evasão) depende de raw sockets. Sem root, abortamos com instrução clara.
    euid = getattr(os, "geteuid", lambda: 0)()
    if euid != 0:
        logger.error(
            "O Draco precisa de privilégios de root. Rode:  sudo draco <alvo>  "
            "(ou apenas 'draco', que eleva sozinho e pede a senha)."
        )
        logger.close()
        return 2

    targets_file = _resolve_targets_file(args, logger)

    # O alvo informado já é auditado — sem lista de permitidos. Só a validação de
    # sintaxe do Épico 1 é aplicada (evita disparar contra entrada malformada).
    logger.info("Alvo informado será auditado. Use apenas em alvos que você tem permissão de testar.")

    # --- Épico 1: ingestão ---
    try:
        targets = ingest(targets_file, cfg, authorized_flag=True, logger=logger)
    except IngestError as exc:
        logger.error(f"Ingestão abortada: {exc}")
        logger.close()
        return 1

    if not targets:
        logger.error("Nenhum alvo válido para auditar.")
        logger.close()
        return 1

    # --- Épicos 2-4: pipeline automático ---
    try:
        paths = run_pipeline(targets, cfg, logger)
    except KeyboardInterrupt:
        logger.error("Interrompido pelo usuário.")
        logger.close()
        return 130

    logger.info("Consolidação concluída com sucesso.")
    logger.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
