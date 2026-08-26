#!/usr/bin/env bash
# =============================================================================
# draco — lançador único do Draco-Workstation.
#
#   draco                     # alvo padrão scanme.nmap.org
#   draco scanme.nmap.org     # um alvo
#   draco 45.33.32.156        # um IP
#   draco -f targets.txt      # arquivo de alvos
#
# Faz tudo sozinho: usa o venv automaticamente (sem 'activate') e sobe para root
# via sudo (pergunta a senha 1x). Root é OBRIGATÓRIO — a varredura sênior (SYN
# furtivo + masscan + OS fingerprint + evasão) depende de raw sockets.
# =============================================================================
set -euo pipefail

# Resolve o diretório real mesmo quando chamado via symlink em /usr/local/bin.
SRC="$(readlink -f "${BASH_SOURCE[0]}")"
DIR="$(cd "$(dirname "$SRC")" && pwd)"
cd "$DIR"                                  # garante que o pacote e o config resolvam

PY="$DIR/venv/bin/python"
[ -x "$PY" ] || PY="$(command -v python3)"

# PATH que inclui /usr/local/bin (nuclei/searchsploit) mesmo sob sudo.
SAFE_PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"

# --help/-h: mostra ajuda sem pedir sudo.
case " $* " in
  *" -h "*|*" --help "*) exec "$PY" -m draco.cli "$@" ;;
esac

# Root é obrigatório: se não somos root, elevamos via sudo (pede a senha 1x).
if [ "$(id -u)" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1; then
    echo "[DRACO] Elevando para root (obrigatório para a varredura sênior)."
    exec sudo env "PATH=$SAFE_PATH" "$PY" -m draco.cli "$@"
  fi
  echo "[DRACO] Root é obrigatório e 'sudo' não está disponível. Rode como root." >&2
  exit 2
fi

exec env "PATH=$SAFE_PATH" "$PY" -m draco.cli "$@"
