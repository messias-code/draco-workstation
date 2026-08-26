"""Épico 4 — Gerador de Relatório Markdown.

Consolida discovery + portas (nmap) + vulnerabilidades (nuclei/searchsploit/NVD)
num documento .md didático, seguindo o layout do PDF "segunda fase explicativa":

  1. Status Geral do Host
  2. Mapeamento Estruturado de Portas (com Estado E Razão)
  3. Vulnerabilidades Identificadas e CVEs (severidade + CVSS)
  4. Vetores Recomendados

O objetivo é um documento completo e explicado, para o profissional começar a
defender (ou, em pentest autorizado, atacar de forma ética).
"""

from __future__ import annotations

import datetime
import os
import re

from .models import (
    PORT_STATE_EMOJI,
    PORT_STATE_LABEL_PT,
    SEVERITY_EMOJI,
    SEVERITY_LABEL_PT,
    HostReport,
)
from .ai import translate_and_summarize


def _emoji(cfg, table: dict, key: str, default: str = "") -> str:
    if not cfg["report"].get("use_emoji", True):
        return ""
    return table.get(key, default)


def _fmt_response_time(ms) -> str:
    if ms is None:
        return "N/D"
    return f"{ms:.0f}ms"


def _reason_pt(reason: str) -> str:
    """Anota a razão técnica da porta (didático)."""
    mapping = {
        "syn-ack": "syn-ack (respondeu com SYN-ACK)",
        "reset": "reset (RST — rejeição ativa)",
        "no-response": "no-response (sem resposta — provável firewall)",
        "conn-refused": "conn-refused (conexão recusada)",
        "host-unreach": "host-unreach (host inalcançável)",
        "": "-",
    }
    return mapping.get(reason, reason)


def render_markdown(report: HostReport, cfg) -> str:
    """Renderiza o HostReport como string Markdown."""
    rep = cfg["report"]
    sections = rep.get("include_sections", {})
    lines: list[str] = []

    target = report.target
    ip = target.ip or "N/D"
    host = target.raw
    date_str = report.started_at or datetime.datetime.now().strftime("%d/%m/%Y")

    # ---- Cabeçalho ----
    lines.append("# Relatório de Auditoria Técnica — Draco-Workstation")
    lines.append("")
    lines.append(f"- **Alvo:** {host}")
    lines.append(f"- **IP:** {ip}")
    lines.append(f"- **Data da Auditoria:** {date_str}")
    lines.append(f"- **Estratégia Utilizada:** {report.strategy_label or rep.get('strategy_label', '')}")
    if report.duration_seconds is not None:
        lines.append(f"- **Duração da Varredura:** {report.duration_seconds:.1f}s")
    lines.append("")

    # ---- 1. Status Geral do Host ----
    if sections.get("host_overview", True):
        status_emoji = _emoji(cfg, {"UP": "🟢", "DOWN": "🔴"}, report.discovery.status)
        status_txt = f"{status_emoji} {report.discovery.status}".strip()
        
        if report.os_matches:
            # Sort by accuracy descending to ensure we get the best guesses
            sorted_matches = sorted(report.os_matches, key=lambda m: (m.accuracy or 0), reverse=True)
            # Take only the top 3 matches to avoid breaking the markdown table visually
            top_matches = sorted_matches[:3]
            os_parts = [f"{m.name} ({m.accuracy}%)" if m.accuracy else m.name for m in top_matches]
            if len(sorted_matches) > 3:
                os_parts.append(f"... (+{len(sorted_matches) - 3} palpites)")
            os_txt = "<br>".join(os_parts)
        else:
            os_txt = "Indeterminado"
            
        lines.append("## 1. Status Geral do Host")
        lines.append("")
        lines.append("| Endereço IP | Status | Sistema Operacional Detectado | Tempo de Resposta | Método de Checagem |")
        lines.append("|---|---|---|---|---|")
        lines.append(
            f"| {ip} | {status_txt} | {os_txt} | "
            f"{_fmt_response_time(report.discovery.response_time_ms)} | "
            f"{report.discovery.method_label} |"
        )
        lines.append("")
        if not report.is_up:
            lines.append(
                "> **Nota do Auditor:** host marcado como **DOWN** — não respondeu a nenhum "
                "método de descoberta (ICMP e TCP-connect). As tabelas seguintes ficam vazias "
                "por design, evitando varredura de um host inativo."
            )
            lines.append("")

    # ---- 2. Mapeamento Estruturado de Portas ----
    if sections.get("ports", True):
        lines.append("## 2. Mapeamento Estruturado de Portas")
        lines.append("")
        lines.append(
            "Estado real de cada porta auditada, incluindo o motivo retornado pela "
            "pilha TCP/IP do alvo (flag `--reason` do Nmap)."
        )
        lines.append("")
        lines.append("| Porta | Protocolo | Estado | Razão do Estado | Serviço | Versão do Serviço |")
        lines.append("|---|---|---|---|---|---|")
        # Mostra abertas primeiro, depois fechadas/filtradas; ordena por porta.
        ordered = sorted(
            report.ports,
            key=lambda p: (0 if p.state == "open" else 1, p.number, p.protocol),
        )
        for p in ordered:
            st_emoji = _emoji(cfg, PORT_STATE_EMOJI, p.state, "")
            st_label = PORT_STATE_LABEL_PT.get(p.state, p.state)
            state_cell = f"{st_emoji} {st_label}".strip()
            svc = p.service_name.upper() if p.service_name else "-"
            ver = p.service_version_str
            lines.append(
                f"| {p.number} | {p.protocol.upper()} | {state_cell} | "
                f"{_reason_pt(p.reason)} | {svc} | {ver} |"
            )
        if not report.ports:
            lines.append("| — | — | — | — | — | — |")
        lines.append("")
        lines.append(
            "> **Nota do Auditor:** portas **Filtradas** indicam regras de firewall "
            "com _drop_ de pacotes (sem resposta). Portas **Fechadas** responderam "
            "ativamente com flag RST, confirmando que a pilha de rede está acessível."
        )
        lines.append("")

    # ---- 3. Vulnerabilidades e CVEs ----
    if sections.get("vulnerabilities", True):
        lines.append("## 3. Vulnerabilidades Identificadas e CVEs")
        lines.append("")
        lines.append(
            "Correlação gerada cruzando os banners dos serviços com a base local do "
            "Exploit-DB (searchsploit), a API do NIST/NVD, o Vulners e a execução de "
            "templates do Nuclei."
        )
        vulns = report.sorted_vulnerabilities()
        
        # Summary counts
        if vulns:
            counts = {}
            for v in vulns:
                sev = v.normalized_severity()
                counts[sev] = counts.get(sev, 0) + 1
            summary = ", ".join(f"**{count} {sev.upper()}**" for sev, count in sorted(counts.items()))
            lines.append(f"\n**Resumo de Impacto**: Foram identificadas {len(vulns)} vulnerabilidades ({summary}).")
            
        lines.append("")
        lines.append("| Porta / Serviço | Código da Falha | Severidade | Fonte | Descrição Técnica |")
        lines.append("|---|---|---|---|---|")
        gemini_cfg = cfg["report"].get("gemini", {})
        gemini_key = gemini_cfg.get("api_key")
        
        # Opcional: barra de progresso se tiver Gemini e tiver muitas vulns
        
        for v in vulns:
            sev = v.normalized_severity()
            sev_emoji = _emoji(cfg, SEVERITY_EMOJI, sev, "")
            sev_label = SEVERITY_LABEL_PT.get(sev, sev)
            cvss_txt = f" (CVSS {v.cvss})" if v.cvss is not None else ""
            sev_cell = f"{sev_emoji} {sev_label}{cvss_txt}".strip()
            port_lbl = f"{v.port} / {v.service}" if v.port else (v.service or "-")
            
            raw_desc = v.description or v.title or "-"
            if gemini_key and len(raw_desc) > 10:
                raw_desc = translate_and_summarize(raw_desc, gemini_key, gemini_cfg.get("model", "gemini-flash-latest"))
                
            desc = _clean_cell(raw_desc)
            lines.append(
                f"| {port_lbl} | {v.identifier} | {sev_cell} | {v.source} | {desc} |"
            )
        if not vulns:
            if report.is_up:
                lines.append("| — | Nenhuma correlacionada | 🟢 Nenhuma | — | Sem CVEs conhecidos para os serviços identificados. |")
            else:
                lines.append("| — | — | — | — | Host DOWN — sem varredura de vulnerabilidades. |")
        lines.append("")

    # ---- 4. Vetores Recomendados ----
    if sections.get("recommended_vectors", True):
        lines.append("## 4. Vetores Recomendados para Auditoria")
        lines.append("")
        lines.append(
            "Próximos passos de **enumeração e verificação** (nível de recomendação, "
            "sem código de ataque). Devem ser executados apenas dentro do escopo autorizado."
        )
        lines.append("")
        if report.recommended_vectors:
            for i, vec in enumerate(report.recommended_vectors, 1):
                lines.append(f"{i}. {vec}")
        else:
            lines.append("_Sem vetores recomendados (host inativo ou sem superfície exposta)._")
        lines.append("")

    # ---- Apêndice: comandos executados ----
    if sections.get("raw_command_log", True) and report.commands:
        lines.append("## Apêndice — Comandos Executados (auditabilidade)")
        lines.append("")
        lines.append("```bash")
        for cmd in report.commands:
            lines.append(cmd)
        lines.append("```")
        lines.append("")
        if report.warnings:
            lines.append("### Avisos / Degradações")
            lines.append("")
            for w in report.warnings:
                lines.append(f"- {w}")
            lines.append("")

    lines.append("---")
    lines.append(
        f"_Relatório gerado pelo Draco-Workstation em "
        f"{datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')}._"
    )
    lines.append("")
    return "\n".join(lines)


def _clean_cell(text: str) -> str:
    """Sanitiza texto para célula de tabela Markdown (sem quebrar o pipe)."""
    text = re.sub(r"\s+", " ", text or "").strip()
    text = text.replace("|", "\\|")
    if len(text) > 300:
        text = text[:297] + "..."
    return text or "-"


# ---------------------------------------------------------------------------
# Escrita em arquivo
# ---------------------------------------------------------------------------
def report_path(report: HostReport, cfg) -> str:
    """Resolve o caminho de saída a partir do template configurado."""
    outputs_dir = cfg["paths"]["outputs_dir"]
    template = cfg["paths"].get("report_filename", "relatorio_draco_{ip}_{date}.md")
    now = datetime.datetime.now()
    ip = report.target.ip or report.target.raw
    safe_ip = re.sub(r"[^A-Za-z0-9._-]", "_", str(ip))
    safe_host = re.sub(r"[^A-Za-z0-9._-]", "_", report.target.raw)
    filename = template.format(
        ip=safe_ip,
        host=safe_host,
        date=now.strftime("%Y-%m-%d"),
        datetime=now.strftime("%Y%m%d_%H%M%S"),
    )
    return os.path.join(outputs_dir, filename)


def write_report(report: HostReport, cfg, logger=None) -> str:
    """Renderiza e grava o relatório .md. Retorna o caminho do arquivo."""
    path = report_path(report, cfg)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    content = render_markdown(report, cfg)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return path
