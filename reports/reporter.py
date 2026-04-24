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
from core.utils.dates import parse_iso, format_brazilian

logger = get_logger("reports.reporter")


# ─── Cálculo de períodos ──────────────────────────────────────────────

def _get_date_range(period_type: str, offset: int = 0) -> tuple[str, str, str]:
    """
    Retorna (period_key, start_iso, end_iso) para um período e offset.
    period_type: 'weekly' ou 'monthly'
    offset: 0 (atual/anterior imediato), 1 (um antes desse), etc.
    """
    now = datetime.now(timezone.utc)
    
    if period_type == "weekly":
        # Início desta semana (segunda-feira 00:00)
        this_monday = now.replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=now.weekday())
        start_dt = this_monday - timedelta(days=7 * (offset + 1))
        end_dt = start_dt + timedelta(days=7)
        
        year, week, _ = start_dt.isocalendar()
        period_key = f"{year}-W{week:02d}"
        
    else: # monthly
        # Primeiro dia deste mês
        this_month = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        
        # Retroceder offset + 1 meses
        start_dt = this_month
        for _ in range(offset + 1):
            if start_dt.month == 1:
                start_dt = start_dt.replace(year=start_dt.year - 1, month=12)
            else:
                start_dt = start_dt.replace(month=start_dt.month - 1)
        
        # Fim do período é o início do próximo mês
        if start_dt.month == 12:
            end_dt = start_dt.replace(year=start_dt.year + 1, month=1)
        else:
            end_dt = start_dt.replace(month=start_dt.month + 1)
            
        period_key = start_dt.strftime("%Y-%m")

    return period_key, start_dt.isoformat(), end_dt.isoformat()


# ─── Agregação de dados ──────────────────────────────────────────────

def _build_period_label(start_iso: str, end_iso: str) -> str:
    """Formata o intervalo como '14/04 — 20/04/2026'."""
    start_dt = parse_iso(start_iso)
    end_dt = parse_iso(end_iso)
    if not start_dt or not end_dt: return ""
    
    return f"{start_dt.strftime('%d/%m')} — {end_dt.strftime('%d/%m/%Y')}"


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
    """Coleta todas as estatísticas do período em uma única chamada ao storage (Performance)."""
    data = storage.get_report_stats(since, until)
    
    # Mapeia os dados brutos do banco para a estrutura esperada pelo formatador
    return {
        "cve_count": data["total_cves"],
        "news_count": data["total_news"],
        "avg_cvss": data["avg_cvss"],
        "risk_breakdown": data["risk_distribution"],
        "top_vendors": data["top_vendors"],
        "top_products": data["top_products"],
        "top_clients": data["top_clients"],
        "top_news_sources": data["top_sources"],
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
        period_key, start, end = _get_date_range("weekly", offset=0)
        _, prev_start, prev_end = _get_date_range("weekly", offset=1)

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
        period_key, start, end = _get_date_range("monthly", offset=0)
        _, prev_start, prev_end = _get_date_range("monthly", offset=1)

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
