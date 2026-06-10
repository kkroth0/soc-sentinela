"""
core/notifications/formatters/patch_tuesday_formatter.py — Mensagem-resumo HTML
do relatório mensal de Patch Tuesday (Microsoft) para o Telegram.

A listagem completa das CVEs vai como PDF anexo; esta mensagem traz só os KPIs.
"""

import html as html_mod
from typing import Any

# Meses em português para o título do relatório.
_MONTHS_PT = (
    "Janeiro", "Fevereiro", "Março", "Abril", "Maio", "Junho",
    "Julho", "Agosto", "Setembro", "Outubro", "Novembro", "Dezembro",
)

_SEVERITY_EMOJI = {"Critical": "🔴", "Important": "🟠", "Moderate": "🟡", "Low": "🟢"}


def _period_label(stats: dict[str, Any]) -> str:
    """Converte '2026-Jun' / data de release em 'Junho/2026'."""
    period = stats.get("period_label")
    if period:
        return period
    rd = stats.get("release_date", "")
    if len(rd) >= 7 and rd[4] == "-":
        try:
            year = int(rd[:4])
            month = int(rd[5:7])
            return f"{_MONTHS_PT[month - 1]}/{year}"
        except (ValueError, IndexError):
            pass
    return stats.get("doc_id", "N/A")


def build_patch_tuesday_summary(stats: dict[str, Any]) -> str:
    """Monta a mensagem HTML de resumo do Patch Tuesday para o Telegram."""
    period = html_mod.escape(_period_label(stats))
    total = stats.get("total", 0)
    total_all = stats.get("total_all", total)
    official = stats.get("official_date", "")
    buckets = stats.get("bucket_counts", {})
    severity = stats.get("severity_breakdown", {})
    impact = stats.get("impact_breakdown", {})
    exploited = stats.get("exploited", [])
    disclosed = stats.get("publicly_disclosed", [])
    top_products = stats.get("top_products", [])

    official_txt = f" (publicado em {html_mod.escape(official)})" if official else ""
    lines = [
        f"<b>🩹 Patch Tuesday — {period}</b>",
        "<i>Microsoft Security Updates (MSRC)</i>",
        "",
        f"<b>🔧 Vulnerabilidades que exigem ação: {total}</b>{official_txt}",
        "<i>(on-premise, publicadas na data oficial do patch)</i>",
        "",
        "<b>⚠️ Severidade</b>",
    ]
    for sev in ("Critical", "Important", "Moderate", "Low"):
        count = severity.get(sev, 0)
        if count:
            lines.append(f"{_SEVERITY_EMOJI[sev]} {sev}: <b>{count}</b>")

    # Exploradas ativamente (zero-day)
    lines.append("")
    if exploited:
        lines.append(f"<b>🚨 Exploradas ativamente (zero-day): {len(exploited)}</b>")
        for cve in exploited[:10]:
            lines.append(f"  • {html_mod.escape(cve)}")
    else:
        lines.append("✅ Nenhuma CVE explorada ativamente neste ciclo.")

    # Publicamente divulgadas
    if disclosed:
        lines.append("")
        lines.append(f"<b>📣 Publicamente divulgadas: {len(disclosed)}</b>")
        for cve in disclosed[:10]:
            lines.append(f"  • {html_mod.escape(cve)}")

    # Tipos de impacto
    if impact:
        lines.append("")
        lines.append("<b>🎯 Tipos de impacto</b>")
        for name, count in sorted(impact.items(), key=lambda kv: kv[1], reverse=True)[:6]:
            lines.append(f"• {html_mod.escape(name)}: {count}")

    # Top produtos afetados
    if top_products:
        lines.append("")
        lines.append("<b>📦 Produtos mais afetados</b>")
        for name, count in top_products[:6]:
            lines.append(f"• {html_mod.escape(name)}: {count} CVEs")

    # Fora do destaque (auto-update / cloud / out-of-band) — só contexto.
    excluded = {k: v for k, v in buckets.items() if k != "core" and v}
    if excluded:
        from reports.patch_tuesday import BUCKET_LABELS
        lines.append("")
        lines.append(f"<b>🔕 Fora do destaque ({total_all - total} de {total_all})</b>")
        order = ["edge", "cloud", "azure_linux", "out_of_band"]
        for key in order:
            if excluded.get(key):
                label = html_mod.escape(BUCKET_LABELS.get(key, key))
                lines.append(f"• {label}: {excluded[key]}")
        lines.append("<i>Sem ação de patch on-prem — incluídos na listagem completa.</i>")

    lines.append("")
    lines.append("📎 <i>Listagem completa de TODAS as CVEs no(s) arquivo(s) anexo(s).</i>")
    lines.append("🛡️ <i>SOC Sentinel — Monitoramento Automatizado</i>")

    return "\n".join(lines)
