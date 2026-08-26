"""Draco-Workstation — backend CLI de auditoria de redes.

Orquestra binários nativos (nmap, masscan, nuclei, searchsploit), faz o parsing
estruturado das saídas, aplica lógica condicional (o "Cérebro") e gera relatórios
Markdown didáticos.

Organização por Épico (ver PDFs de planejamento):
    ingest       — Épico 1: ingestão e validação de alvos + escopo
    discovery    — Épico 2a: descoberta de host (UP/DOWN) com fallback
    scanner      — Épico 2b/2c: masscan + nmap
    parser       — Épico 2: XML(nmap)/JSONL(nuclei)/JSON(searchsploit) -> structs
    brain        — Épico 3: árvore de decisão condicional
    correlation  — Épico 3: searchsploit (offline) + NVD/Vulners (online)
    reporter     — Épico 4: dados -> relatório Markdown
    engine       — o "maestro" que orquestra o pipeline ponta a ponta

Cada função (scan, parse, correlação, relatório) é modular e chamável de forma
independente, para permitir uma futura GUI/API sem reescrita.
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
