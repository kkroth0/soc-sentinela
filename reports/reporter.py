"""
reports/reporter.py — Motor de relatórios analíticos do SOC Sentinel.
Gera relatórios semanais (táticos) e mensais (estratégicos) com:
- KPIs: total CVEs, notícias, CVSS médio
- Distribuição de risco (CRITICAL/HIGH/MEDIUM/LOW)
- Top 5 vendors, produtos, clientes impactados
- Top 5 fontes CTI
- Tendência temporal vs período anterior
"""

from datetime import datetime, timedelta, timezone
from typing import Any

from core import storage
from core.notifications import global_dispatcher
from core.logger import get_logger

logger = get_logger("reports.reporter")


# ─── Cálculo de períodos ──────────────────────────────────────────────

def _get_week_range() -> tuple[str, str, str]:
    """Retorna (period_key, start_iso, end_iso) da semana anterior."""
    now = datetime.now(timezone.utc)
    last_monday = now - timedelta(days=now.weekday() + 7)
    last_sunday = last_monday + timedelta(days=6, hours=23, minutes=59, seconds=59)

    year, week, _ = last_monday.isocalendar()
    period_key = f"{year}-W{week:02d}"

    return period_key, last_monday.isoformat(), last_sunday.isoformat()


def _get_previous_week_range() -> tuple[str, str, str]:
    """Retorna (period_key, start_iso, end_iso) de DUAS semanas atrás (para tendência)."""
    now = datetime.now(timezone.utc)
    prev_monday = now - timedelta(days=now.weekday() + 14)
    prev_sunday = prev_monday + timedelta(days=6, hours=23, minutes=59, seconds=59)

    year, week, _ = prev_monday.isocalendar()
    period_key = f"{year}-W{week:02d}"

    return period_key, prev_monday.isoformat(), prev_sunday.isoformat()


def _get_month_range() -> tuple[str, str, str]:
    """Retorna (period_key, start_iso, end_iso) do mês ANTERIOR."""
    now = datetime.now(timezone.utc)
    first_of_current = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    last_of_previous = first_of_current - timedelta(seconds=1)
    first_of_previous = last_of_previous.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

    period_key = first_of_previous.strftime("%Y-%m")
    return period_key, first_of_previous.isoformat(), last_of_previous.isoformat()


def _get_previous_month_range() -> tuple[str, str, str]:
    """Retorna (period_key, start_iso, end_iso) de DOIS meses atrás (para tendência)."""
    now = datetime.now(timezone.utc)
    first_of_current = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    last_of_previous = first_of_current - timedelta(seconds=1)
    first_of_previous = last_of_previous.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    last_of_two_ago = first_of_previous - timedelta(seconds=1)
    first_of_two_ago = last_of_two_ago.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

    period_key = first_of_two_ago.strftime("%Y-%m")
    return period_key, first_of_two_ago.isoformat(), last_of_two_ago.isoformat()


# ─── Agregação de dados ──────────────────────────────────────────────

def _build_period_label(start_iso: str, end_iso: str) -> str:
    """Formata o intervalo como '14/04 — 20/04/2026'."""
    try:
        start_dt = datetime.fromisoformat(start_iso)
        end_dt = datetime.fromisoformat(end_iso)
        return f"{start_dt.strftime('%d/%m')} — {end_dt.strftime('%d/%m/%Y')}"
    except Exception:
        return ""


def _calc_trend(current: int, previous: int) -> str:
    """Calcula variação percentual entre dois valores."""
    if previous == 0:
        return "—" if current == 0 else "↑ novo"
    diff = ((current - previous) / previous) * 100
    if diff > 0:
        return f"↑ {diff:.0f}%"
    elif diff < 0:
        return f"↓ {abs(diff):.0f}%"
    return "→ 0%"


def _aggregate_full_stats(since: str, until: str) -> dict[str, Any]:
    """Monta o objeto completo de estatísticas para um período."""
    risk_breakdown = storage.get_cve_stats(since, until)
    cve_count = sum(risk_breakdown.values())
    news_count = storage.get_news_count(since, until)
    avg_cvss = storage.get_avg_cvss(since, until)
    top_vendors = storage.get_cves_by_vendor(since, until)
    top_products = storage.get_cves_by_product(since, until)
    top_clients = storage.get_most_impacted_clients(since, until)
    top_news_sources = storage.get_news_by_source(since, until)

    return {
        "cve_count": cve_count,
        "news_count": news_count,
        "avg_cvss": avg_cvss,
        "risk_breakdown": {
            "CRITICAL": risk_breakdown.get("CRITICAL", 0),
            "HIGH": risk_breakdown.get("HIGH", 0),
            "MEDIUM": risk_breakdown.get("MEDIUM", 0),
            "LOW": risk_breakdown.get("LOW", 0),
        },
        "top_vendors": top_vendors,
        "top_products": top_products,
        "top_clients": top_clients,
        "top_news_sources": top_news_sources,
    }


def _add_trend(stats: dict[str, Any], prev_stats: dict[str, Any]) -> None:
    """Adiciona indicadores de tendência temporal ao stats."""
    stats["trend_cve"] = _calc_trend(stats["cve_count"], prev_stats["cve_count"])
    stats["trend_news"] = _calc_trend(stats["news_count"], prev_stats["news_count"])
    stats["trend_critical"] = _calc_trend(
        stats["risk_breakdown"]["CRITICAL"], prev_stats["risk_breakdown"]["CRITICAL"]
    )


# ─── Execução dos relatórios ─────────────────────────────────────────

def run_weekly_report() -> bool:
    """Gera e envia relatório semanal tático."""
    logger.info("═══ Relatório Semanal iniciado ═══")

    try:
        period_key, start, end = _get_week_range()
        _, prev_start, prev_end = _get_previous_week_range()

        stats = _aggregate_full_stats(start, end)
        prev_stats = _aggregate_full_stats(prev_start, prev_end)

        stats["period"] = period_key
        stats["period_label"] = _build_period_label(start, end)
        stats["report_type"] = "weekly"
        _add_trend(stats, prev_stats)

        # Salvar no banco
        storage.save_weekly_summary(
            period_key=period_key,
            cve_count=stats["cve_count"],
            news_count=stats["news_count"],
            critical_count=stats["risk_breakdown"]["CRITICAL"],
            high_count=stats["risk_breakdown"]["HIGH"],
        )

        # Enviar via dispatcher (Teams + Telegram)
        global_dispatcher.dispatch_report(stats, "weekly")

        logger.info(
            "Relatório semanal %s enviado — CVEs=%d, Notícias=%d",
            period_key, stats["cve_count"], stats["news_count"],
        )
        return True

    except Exception as exc:
        logger.error("Erro no relatório semanal: %s", exc)
        return False


def run_monthly_report() -> bool:
    """Gera e envia relatório mensal estratégico."""
    logger.info("═══ Relatório Mensal iniciado ═══")

    try:
        period_key, start, end = _get_month_range()
        _, prev_start, prev_end = _get_previous_month_range()

        stats = _aggregate_full_stats(start, end)
        prev_stats = _aggregate_full_stats(prev_start, prev_end)

        stats["period"] = period_key
        stats["period_label"] = _build_period_label(start, end)
        stats["report_type"] = "monthly"
        _add_trend(stats, prev_stats)

        # Salvar resumo analítico no banco
        storage.save_monthly_summary(stats)

        # Enviar via dispatcher (Teams + Telegram)
        global_dispatcher.dispatch_report(stats, "monthly")

        logger.info(
            "Relatório mensal %s enviado — CVEs=%d, Notícias=%d",
            period_key, stats["cve_count"], stats["news_count"],
        )
        return True

    except Exception as exc:
        logger.error("Erro no relatório mensal: %s", exc)
        return False
