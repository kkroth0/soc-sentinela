"""
core/notifications/teams_notifier.py — Adapter para o Microsoft Teams.
"""

from dataclasses import asdict
from typing import Any

import config
from core.models import StandardCVEAlert, StandardCTINews
from core.notifications.base import BaseNotifier
from core.clients.teams_client import send_card

from core.notifications.formatters.cve_formatter import build_cve_card
from core.notifications.formatters.cti_formatter import build_news_card
from core.notifications.formatters.report_formatter import (
    build_weekly_report_card,
    build_monthly_report_card,
)


class TeamsNotifier(BaseNotifier):
    @property
    def name(self) -> str:
        return "Microsoft Teams"

    def send_cve_alert(self, alert: StandardCVEAlert) -> bool:
        if not config.TEAMS_WEBHOOK_URL_CVE:
            return False
            
        cve_dict = asdict(alert)
        card_payload = build_cve_card(cve_dict)
        return send_card(config.TEAMS_WEBHOOK_URL_CVE, card_payload)

    def send_cti_news(self, news: StandardCTINews) -> bool:
        if not config.TEAMS_WEBHOOK_URL_CTI:
            return False
            
        news_dict = asdict(news)
        card_payload = build_news_card(news_dict)
        return send_card(config.TEAMS_WEBHOOK_URL_CTI, card_payload)

    def send_report(self, stats: dict[str, Any], report_type: str) -> bool:
        # Relatórios genéricos vão para CTI primariamente, ou CVE como fallback
        webhook_url = config.TEAMS_WEBHOOK_URL_CTI or config.TEAMS_WEBHOOK_URL_CVE
        if not webhook_url:
            return False

        if report_type == "weekly":
            card = build_weekly_report_card(stats)
        else:
            card = build_monthly_report_card(stats)

        return send_card(webhook_url, card)
