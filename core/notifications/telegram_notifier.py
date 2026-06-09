"""
core/notifications/telegram_notifier.py — Notificador Telegram (único canal de saída).
"""

from dataclasses import asdict
from typing import Any

import config
from core.models import StandardCVEAlert, StandardCTINews
from core.clients.telegram_client import send_message, send_document
from core.logger import get_logger

from core.notifications.formatters.cve_formatter import build_cve_telegram_message
from core.notifications.formatters.cti_formatter import build_news_telegram_message
from core.notifications.formatters.report_formatter import (
    build_weekly_report_telegram,
    build_monthly_report_telegram,
)
from core.notifications.formatters.patch_tuesday_formatter import (
    build_patch_tuesday_summary,
)

logger = get_logger("core.notifications.telegram_notifier")


class TelegramNotifier:
    """Canal de notificação via Telegram Bot API."""

    def send_cve_alert(self, alert: StandardCVEAlert) -> bool:
        chat_id = config.TELEGRAM_CHAT_ID_CVE or config.TELEGRAM_CHAT_ID_CTI
        if not config.TELEGRAM_BOT_TOKEN or not chat_id:
            return False
        html_msg = build_cve_telegram_message(alert)
        return send_message(chat_id, html_msg, parse_mode="HTML")

    def send_cti_news(self, news: StandardCTINews) -> bool:
        if not config.TELEGRAM_BOT_TOKEN or not config.TELEGRAM_CHAT_ID_CTI:
            return False
        html_msg = build_news_telegram_message(news)
        return send_message(config.TELEGRAM_CHAT_ID_CTI, html_msg, parse_mode="HTML")

    def send_report(self, stats: dict[str, Any], report_type: str) -> bool:
        chat_id = config.TELEGRAM_CHAT_ID_CTI or config.TELEGRAM_CHAT_ID_CVE
        if not config.TELEGRAM_BOT_TOKEN or not chat_id:
            return False

        if report_type == "weekly":
            html_msg = build_weekly_report_telegram(stats)
        else:
            html_msg = build_monthly_report_telegram(stats)

        return send_message(chat_id, html_msg, parse_mode="HTML")

    def send_patch_tuesday_report(self, stats: dict[str, Any], attachments: list[str]) -> bool:
        """Envia o resumo do Patch Tuesday + os anexos (PDF/CSV/XLSX)."""
        chat_id = config.TELEGRAM_CHAT_ID_PATCH
        if not config.TELEGRAM_BOT_TOKEN or not chat_id:
            return False

        html_msg = build_patch_tuesday_summary(stats)
        ok = send_message(chat_id, html_msg, parse_mode="HTML")

        period = stats.get("period_label", stats.get("doc_id", ""))
        for path in attachments:
            caption = f"🩹 Patch Tuesday — {period} — listagem completa de CVEs"
            if not send_document(chat_id, path, caption=caption):
                ok = False
        return ok
