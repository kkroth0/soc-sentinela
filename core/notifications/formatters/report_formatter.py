"""
reports/formatter.py — Mensagens Telegram HTML para relatórios semanais e mensais.
Layout rico: KPIs, distribuição de risco, Top 5 vendors/produtos/clientes.
"""

import html as html_mod
from typing import Any
import config
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
    lines.append(f"<i>{html_mod.escape(config.SIGNATURE)}</i>")

    return "\n".join(lines)


def build_feeds_telegram(rows: list[dict[str, Any]]) -> str:
    """Monta o painel de saúde das fontes (comando /feeds)."""
    total = len(rows)
    healthy = [r for r in rows if r["status"] in ("OK", "WAF-BYPASS", "STATIC")]
    bypass = [r for r in rows if r["status"] == "WAF-BYPASS"]
    problems = [r for r in rows if r["status"] in ("FAIL", "EMPTY")]

    lines = [
        "<b>FEED HEALTH</b>",
        "━━━━━━━━━━━━━━━━━━━━━━━━",
        f"Operational: <b>{len(healthy)}/{total}</b>",
        "",
    ]
    if bypass:
        lines.append("<b>[ WAF bypass active ]</b>")
        for r in bypass:
            lines.append(f"• {html_mod.escape(str(r['source']))} ({r['entries']})")
        lines.append("")
    if problems:
        lines.append("<b>[ Needs attention ]</b>")
        for r in problems:
            lines.append(f"• {html_mod.escape(str(r['source']))} — {r['status']}")
    else:
        lines.append("All feeds operational.")
    lines.append("")
    lines.append(f"<i>{html_mod.escape(config.SIGNATURE)}</i>")
    return "\n".join(lines)


def build_stats_telegram(stats: dict[str, Any], period_label: str) -> str:
    """Monta o painel de métricas (comando /stats), a partir de get_report_stats."""
    risk = stats.get("risk_distribution", {})
    lines = [
        "<b>SOC SENTINEL · METRICS</b>",
        "━━━━━━━━━━━━━━━━━━━━━━━━",
        f"Period: <b>{html_mod.escape(period_label)}</b>",
        "",
        "<b>[ Volume ]</b>",
        f"CVEs alerted: <b>{stats.get('total_cves', 0)}</b>",
        f"CTI reports: <b>{stats.get('total_news', 0)}</b>",
        f"Avg CVSS: <b>{stats.get('avg_cvss', 0.0)}</b>",
        "",
        "<b>[ Risk Distribution ]</b>",
        f"🔴 CRITICAL: {risk.get('CRITICAL', 0)}",
        f"🟠 HIGH: {risk.get('HIGH', 0)}",
        f"🟡 MEDIUM: {risk.get('MEDIUM', 0)}",
        f"🟢 LOW: {risk.get('LOW', 0)}",
    ]
    top_vendors = stats.get("top_vendors", [])
    if top_vendors:
        lines += ["", "<b>[ Top Vendors ]</b>"]
        for i, v in enumerate(top_vendors[:5], 1):
            lines.append(f"{i}. {html_mod.escape(str(v.get('vendor', '?')).upper())} — {v.get('total', 0)}")
    top_clients = stats.get("top_clients", [])
    if top_clients:
        lines += ["", "<b>[ Most Impacted Assets ]</b>"]
        for c in top_clients[:5]:
            lines.append(f"• {html_mod.escape(str(c.get('client', '?')))} — {c.get('count', 0)}")
    top_sources = stats.get("top_sources", [])
    if top_sources:
        lines += ["", "<b>[ Top Sources ]</b>"]
        for s in top_sources[:5]:
            lines.append(f"• {html_mod.escape(str(s.get('source', '?')))} — {s.get('total', 0)}")
    lines += ["", f"<i>{html_mod.escape(config.SIGNATURE)}</i>"]
    return "\n".join(lines)
