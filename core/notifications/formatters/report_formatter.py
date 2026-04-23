"""
reports/formatter.py — Adaptive Cards executivos e mensagens Telegram para relatórios.
Layout rico: KPIs, distribuição de risco, Top 5 vendors/produtos/clientes, tendência temporal.
"""

import html as html_mod
from typing import Any

from core.logger import get_logger

logger = get_logger("core.notifications.formatters.report_formatter")


# ═══════════════════════════════════════════════════════════════════════
# ADAPTIVE CARDS (Microsoft Teams)
# ═══════════════════════════════════════════════════════════════════════

def build_weekly_report_card(stats: dict[str, Any]) -> dict[str, Any]:
    """Monta Adaptive Card de relatório semanal tático."""
    return _build_report_card(stats, title="📊 Relatório Semanal — SOC Sentinel")


def build_monthly_report_card(stats: dict[str, Any]) -> dict[str, Any]:
    """Monta Adaptive Card de relatório mensal estratégico."""
    return _build_report_card(stats, title="📈 Relatório Mensal — SOC Sentinel")


def _build_report_card(stats: dict[str, Any], title: str) -> dict[str, Any]:
    """Constrói o Adaptive Card completo com KPIs, rankings e tendência."""
    period = stats.get("period", "N/A")
    period_label = stats.get("period_label", period)
    cve_count = stats.get("cve_count", 0)
    news_count = stats.get("news_count", 0)
    avg_cvss = stats.get("avg_cvss", 0.0)
    risk = stats.get("risk_breakdown", {})
    trend_cve = stats.get("trend_cve", "—")
    trend_news = stats.get("trend_news", "—")
    trend_critical = stats.get("trend_critical", "—")

    body: list[dict] = []

    # ── Header ────────────────────────────────────────────────────────
    body.append({
        "type": "TextBlock",
        "text": title,
        "weight": "Bolder",
        "size": "Large",
        "wrap": True,
    })
    body.append({
        "type": "TextBlock",
        "text": f"Período: {period_label}",
        "spacing": "None",
        "isSubtle": True,
    })

    # ── KPIs (3 colunas) ──────────────────────────────────────────────
    body.append({"type": "ColumnSet", "columns": [
        {"type": "Column", "width": "stretch", "items": [
            {"type": "TextBlock", "text": "CVEs Alertadas", "weight": "Bolder", "size": "Small"},
            {"type": "TextBlock", "text": str(cve_count), "size": "ExtraLarge", "color": "accent"},
            {"type": "TextBlock", "text": f"Tendência: {trend_cve}", "size": "Small", "isSubtle": True, "spacing": "None"},
        ]},
        {"type": "Column", "width": "stretch", "items": [
            {"type": "TextBlock", "text": "Notícias CTI", "weight": "Bolder", "size": "Small"},
            {"type": "TextBlock", "text": str(news_count), "size": "ExtraLarge", "color": "accent"},
            {"type": "TextBlock", "text": f"Tendência: {trend_news}", "size": "Small", "isSubtle": True, "spacing": "None"},
        ]},
        {"type": "Column", "width": "stretch", "items": [
            {"type": "TextBlock", "text": "CVSS Médio", "weight": "Bolder", "size": "Small"},
            {"type": "TextBlock", "text": f"{avg_cvss:.1f}", "size": "ExtraLarge", "color": "warning" if avg_cvss >= 7.0 else "accent"},
        ]},
    ]})

    # ── Distribuição de Risco ─────────────────────────────────────────
    body.append({
        "type": "TextBlock",
        "text": "Distribuição de Risco",
        "weight": "Bolder",
        "spacing": "Medium",
    })
    body.append({"type": "FactSet", "facts": [
        {"title": f"🔴 CRITICAL ({trend_critical})", "value": str(risk.get("CRITICAL", 0))},
        {"title": "🟠 HIGH", "value": str(risk.get("HIGH", 0))},
        {"title": "🔵 MEDIUM", "value": str(risk.get("MEDIUM", 0))},
        {"title": "🟢 LOW", "value": str(risk.get("LOW", 0))},
    ]})

    # ── Top 5 Vendors ─────────────────────────────────────────────────
    top_vendors = stats.get("top_vendors", [])
    if top_vendors:
        body.append({
            "type": "TextBlock",
            "text": "🏭 Top 5 Vendors",
            "weight": "Bolder",
            "spacing": "Medium",
        })
        vendor_facts = []
        for i, v in enumerate(top_vendors[:5], 1):
            name = str(v.get("vendor", "N/A")).title()
            total = v.get("total", 0)
            critical = v.get("critical", 0)
            high = v.get("high", 0)
            vendor_facts.append({
                "title": f"{i}. {name}",
                "value": f"{total} CVEs ({critical} 🔴, {high} 🟠)",
            })
        body.append({"type": "FactSet", "facts": vendor_facts})

    # ── Top 5 Produtos ────────────────────────────────────────────────
    top_products = stats.get("top_products", [])
    if top_products:
        body.append({
            "type": "TextBlock",
            "text": "📦 Top 5 Produtos",
            "weight": "Bolder",
            "spacing": "Medium",
        })
        prod_facts = []
        for i, p in enumerate(top_products[:5], 1):
            name = str(p.get("product", "N/A")).title()
            total = p.get("total", 0)
            avg = p.get("avg_cvss", 0)
            prod_facts.append({
                "title": f"{i}. {name}",
                "value": f"{total} CVEs (CVSS médio: {avg})",
            })
        body.append({"type": "FactSet", "facts": prod_facts})

    # ── Top 5 Clientes Impactados ─────────────────────────────────────
    top_clients = stats.get("top_clients", [])
    if top_clients:
        body.append({
            "type": "TextBlock",
            "text": "🏢 Clientes Mais Impactados",
            "weight": "Bolder",
            "spacing": "Medium",
        })
        client_facts = []
        for c in top_clients[:5]:
            client_facts.append({
                "title": f"🏢 {c.get('client', 'N/A')}",
                "value": f"{c.get('count', 0)} CVEs",
            })
        body.append({"type": "FactSet", "facts": client_facts})

    # ── Top 5 Fontes CTI (apenas mensal) ──────────────────────────────
    top_sources = stats.get("top_news_sources", [])
    if top_sources and stats.get("report_type") == "monthly":
        body.append({
            "type": "TextBlock",
            "text": "📰 Top Fontes de Inteligência",
            "weight": "Bolder",
            "spacing": "Medium",
        })
        source_facts = []
        for s in top_sources[:5]:
            source_facts.append({
                "title": str(s.get("source", "N/A")),
                "value": f"{s.get('total', 0)} artigos",
            })
        body.append({"type": "FactSet", "facts": source_facts})

    # ── Footer ────────────────────────────────────────────────────────
    body.append({
        "type": "TextBlock",
        "text": "🛡️ SOC Sentinel — Monitoramento Automatizado",
        "size": "Small",
        "isSubtle": True,
        "spacing": "Large",
        "horizontalAlignment": "Center",
    })

    card: dict[str, Any] = {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.4",
        "body": body,
        "msteams": {
            "width": "Full"
        }
    }

    logger.info("Card de relatório montado: %s (%s)", title, period)
    return card


# ═══════════════════════════════════════════════════════════════════════
# TELEGRAM (HTML)
# ═══════════════════════════════════════════════════════════════════════

def build_weekly_report_telegram(stats: dict[str, Any]) -> str:
    """Monta mensagem HTML do relatório semanal para Telegram."""
    return _build_report_telegram(stats, title="📊 Relatório Semanal — SOC Sentinel")


def build_monthly_report_telegram(stats: dict[str, Any]) -> str:
    """Monta mensagem HTML do relatório mensal para Telegram."""
    return _build_report_telegram(stats, title="📈 Relatório Mensal — SOC Sentinel")


def _build_report_telegram(stats: dict[str, Any], title: str) -> str:
    """Constrói mensagem HTML de relatório para Telegram."""
    period_label = html_mod.escape(stats.get("period_label", stats.get("period", "N/A")))
    cve_count = stats.get("cve_count", 0)
    news_count = stats.get("news_count", 0)
    avg_cvss = stats.get("avg_cvss", 0.0)
    risk = stats.get("risk_breakdown", {})
    trend_cve = html_mod.escape(stats.get("trend_cve", "—"))
    trend_news = html_mod.escape(stats.get("trend_news", "—"))
    trend_critical = html_mod.escape(stats.get("trend_critical", "—"))

    lines = [
        f"<b>{title}</b>",
        f"Período: {period_label}",
        "",
        f"<b>📌 KPIs</b>",
        f"CVEs Alertadas: <b>{cve_count}</b> ({trend_cve})",
        f"Notícias CTI: <b>{news_count}</b> ({trend_news})",
        f"CVSS Médio: <b>{avg_cvss:.1f}</b>",
        "",
        f"<b>⚠️ Distribuição de Risco</b>",
        f"🔴 CRITICAL: {risk.get('CRITICAL', 0)} ({trend_critical})",
        f"🟠 HIGH: {risk.get('HIGH', 0)}",
        f"🔵 MEDIUM: {risk.get('MEDIUM', 0)}",
        f"🟢 LOW: {risk.get('LOW', 0)}",
    ]

    # Top Vendors
    top_vendors = stats.get("top_vendors", [])
    if top_vendors:
        lines.append("")
        lines.append("<b>🏭 Top 5 Vendors</b>")
        for i, v in enumerate(top_vendors[:5], 1):
            name = html_mod.escape(str(v.get("vendor", "N/A")).title())
            total = v.get("total", 0)
            critical = v.get("critical", 0)
            high = v.get("high", 0)
            lines.append(f"{i}. {name} — {total} CVEs ({critical}🔴, {high}🟠)")

    # Top Produtos
    top_products = stats.get("top_products", [])
    if top_products:
        lines.append("")
        lines.append("<b>📦 Top 5 Produtos</b>")
        for i, p in enumerate(top_products[:5], 1):
            name = html_mod.escape(str(p.get("product", "N/A")).title())
            total = p.get("total", 0)
            avg = p.get("avg_cvss", 0)
            lines.append(f"{i}. {name} — {total} CVEs (CVSS médio: {avg})")

    # Top Clientes
    top_clients = stats.get("top_clients", [])
    if top_clients:
        lines.append("")
        lines.append("<b>🏢 Clientes Mais Impactados</b>")
        for c in top_clients[:5]:
            client = html_mod.escape(c.get("client", "N/A"))
            lines.append(f"🏢 {client}: {c.get('count', 0)} CVEs")

    # Top Fontes (mensal)
    top_sources = stats.get("top_news_sources", [])
    if top_sources and stats.get("report_type") == "monthly":
        lines.append("")
        lines.append("<b>📰 Top Fontes de Inteligência</b>")
        for s in top_sources[:5]:
            source = html_mod.escape(str(s.get("source", "N/A")))
            lines.append(f"• {source}: {s.get('total', 0)} artigos")

    lines.append("")
    lines.append("🛡️ <i>SOC Sentinel — Monitoramento Automatizado</i>")

    return "\n".join(lines)
