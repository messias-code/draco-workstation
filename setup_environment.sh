#!/usr/bin/env bash
# =============================================================================
# Draco-Workstation — setup do ambiente (Ubuntu/Debian, inclusive WSL2)
# -----------------------------------------------------------------------------
# Instala os binários orquestrados, prepara o venv Python e registra o comando
# global `draco`. Idempotente: pode rodar várias vezes.
#
#   Uso:  ./setup_environment.sh            # instala tudo (usa sudo quando preciso)
#         ./setup_environment.sh --no-sudo  # só o venv Python (pula binários/comando)
#
# NÃO instala exploits nem payloads — apenas orquestradores de auditoria.
# =============================================================================
set -euo pipefail

TAG="[DRACO-SETUP]"
info()  { echo "${TAG} [INFO] $*"; }
warn()  { echo "${TAG} [WARN] $*" >&2; }

USE_SUDO=1
[[ "${1:-}" == "--no-sudo" ]] && USE_SUDO=0
SUDO=""
[[ "${USE_SUDO}" -eq 1 ]] && SUDO="sudo"

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${DIR}"

# ---- 1. Binários via apt (nmap, masscan, ping) ------------------------------
install_apt() {
  [[ "${USE_SUDO}" -eq 0 ]] && { warn "--no-sudo: pulando binários apt."; return 0; }
  if ! command -v apt-get >/dev/null 2>&1; then
    warn "apt-get ausente — instale manualmente: nmap masscan iputils-ping."
    return 0
  fi
  info "Instalando nmap, masscan, iputils-ping..."
  ${SUDO} apt-get update -y || warn "apt-get update falhou (seguindo)."
  ${SUDO} DEBIAN_FRONTEND=noninteractive apt-get install -y nmap masscan iputils-ping \
    || warn "Falha ao instalar alguns pacotes apt."
}

# ---- 2. searchsploit via git (o pacote 'exploitdb' saiu dos repos novos) -----
install_searchsploit() {
  if command -v searchsploit >/dev/null 2>&1; then
    info "searchsploit já presente."
    return 0
  fi
  [[ "${USE_SUDO}" -eq 0 ]] && { warn "--no-sudo: pulando searchsploit."; return 0; }
  info "Instalando searchsploit (clone raso do Exploit-DB ~360MB)..."
  if ${SUDO} git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb 2>/dev/null; then
    ${SUDO} ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit
    info "searchsploit instalado em /usr/local/bin/searchsploit."
  else
    warn "Clone do Exploit-DB falhou — correlação usará NVD/Nuclei (offline degrada)."
  fi
}

# ---- 3. Nuclei (binário oficial do GitHub) ----------------------------------
install_nuclei() {
  if command -v nuclei >/dev/null 2>&1; then
    info "nuclei já presente."
  elif [[ "${USE_SUDO}" -eq 1 ]] && command -v curl >/dev/null 2>&1; then
    info "Baixando binário do nuclei (GitHub releases)..."
    local url
    url="$(curl -sL https://api.github.com/repos/projectdiscovery/nuclei/releases/latest \
           | grep -o 'https://[^\"]*linux_amd64.zip' | head -1)"
    if [[ -n "${url}" ]]; then
      curl -sL -o /tmp/nuclei.zip "${url}" \
        && unzip -o /tmp/nuclei.zip nuclei -d /tmp/nucleibin >/dev/null \
        && ${SUDO} mv /tmp/nucleibin/nuclei /usr/local/bin/nuclei \
        && ${SUDO} chmod +x /usr/local/bin/nuclei \
        && info "nuclei instalado."
    else
      warn "Não achei o release do nuclei — instale manualmente (a fase web será pulada)."
    fi
  else
    warn "nuclei ausente e sem curl/sudo — a fase web será pulada."
  fi
  command -v nuclei >/dev/null 2>&1 && { info "Atualizando templates do nuclei..."; nuclei -update-templates >/dev/null 2>&1 || true; }
}

# ---- 4. Ambiente Python (venv + deps + pacote) ------------------------------
setup_python() {
  [[ -d venv ]] || { info "Criando virtualenv em ./venv"; python3 -m venv venv; }
  info "Instalando dependências Python..."
  ./venv/bin/pip install --quiet --upgrade pip
  ./venv/bin/pip install --quiet -r requirements.txt
  ./venv/bin/pip install --quiet -e .    # instala o pacote 'draco'
}

# ---- 5. Registrar o comando global `draco` ----------------------------------
register_command() {
  chmod +x "${DIR}/draco.sh"
  if [[ "${USE_SUDO}" -eq 1 ]]; then
    ${SUDO} ln -sf "${DIR}/draco.sh" /usr/local/bin/draco \
      && info "Comando 'draco' registrado em /usr/local/bin/draco." \
      || warn "Não consegui criar /usr/local/bin/draco — use ./draco.sh"
  else
    warn "--no-sudo: comando global não registrado. Use ./draco.sh"
  fi
}

# ---- 6. Verificação ---------------------------------------------------------
verify() {
  info "Binários disponíveis:"
  for b in nmap masscan nuclei searchsploit ping; do
    if command -v "$b" >/dev/null 2>&1; then echo "${TAG}   [OK]    $b"; else echo "${TAG}   [FALTA] $b (degrada com log)"; fi
  done
}

main() {
  info "Iniciando setup do Draco-Workstation..."
  install_apt
  install_searchsploit
  install_nuclei
  setup_python
  register_command
  verify
  info "Setup concluído. Rode:  draco scanme.nmap.org"
}

main "$@"
