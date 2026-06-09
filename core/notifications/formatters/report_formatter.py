"""
reports/formatter.py — Mensagens Telegram HTML para relatórios semanais e mensais.
Layout rico: KPIs, distribuição de risco, Top 5 vendors/produtos/clientes.
"""

import html as html_mod
from typing import Any
from core.logger import get_logger

logger = get_logger("core.notifications.formatters.report_formatter")

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
