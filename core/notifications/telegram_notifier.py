"""
core/notifications/telegram_notifier.py — Adapter para o Telegram.
"""

from dataclasses import asdict
from typing import Any

import config
from core.models import StandardCVEAlert, StandardCTINews
from core.notifications.base import BaseNotifier
from core.clients.telegram_client import send_message

from core.notifications.formatters.cve_formatter import build_cve_telegram_message
from core.notifications.formatters.cti_formatter import build_news_telegram_message
from core.notifications.formatters.report_formatter import (
    build_weekly_report_telegram,
    build_monthly_report_telegram,
)


class TelegramNotifier(BaseNotifier):
    @property
    def name(self) -> str:
        return "Telegram"

    def send_cve_alert(self, alert: StandardCVEAlert) -> bool:
        if not config.TELEGRAM_BOT_TOKEN or not config.TELEGRAM_CHAT_ID_CVE:
            return False
            
        cve_dict = asdict(alert)
        html_msg = build_cve_telegram_message(cve_dict)
        return send_message(config.TELEGRAM_CHAT_ID_CVE, html_msg, parse_mode="HTML")

    def send_cti_news(self, news: StandardCTINews) -> bool:
        if not config.TELEGRAM_BOT_TOKEN or not config.TELEGRAM_CHAT_ID_CTI:
            return False
            
        news_dict = asdict(news)
        html_msg = build_news_telegram_message(news_dict)
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
