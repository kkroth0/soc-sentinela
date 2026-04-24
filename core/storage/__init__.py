"""
core/storage/__init__.py — Fachada unificada para o módulo de storage.
Mantém a compatibilidade com imports antigos (ex: from core import storage).
"""
from core.storage.database import init_db, close_db
from core.storage.persistence import (
    acquire_cve_lock, release_cve_lock, is_cve_sent, save_cve,
    acquire_news_lock, release_news_lock, is_news_sent, save_news,
    save_weekly_summary, save_monthly_summary,
    get_state, set_state, cleanup_old_data
)
from core.storage.analytics import (
    get_report_stats, get_recent_cves, get_recent_news, get_cves_for_month
)

__all__ = [
    "init_db", "close_db",
    "acquire_cve_lock", "release_cve_lock", "is_cve_sent", "save_cve",
    "acquire_news_lock", "release_news_lock", "is_news_sent", "save_news",
    "save_weekly_summary", "save_monthly_summary",
    "get_state", "set_state", "cleanup_old_data",
    "get_report_stats", "get_recent_cves", "get_recent_news", "get_cves_for_month"
]
