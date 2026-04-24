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
        card_payload = build_cve_card(alert)
        # Tenta canal específico, senão fallback para o global
        webhook = config.TEAMS_WEBHOOK_CVE or config.TEAMS_WEBHOOK_URL
        return send_card(card_payload, webhook_url=webhook)

    def send_cti_news(self, news: StandardCTINews) -> bool:
        card_payload = build_news_card(news)
        # Tenta canal específico, senão fallback para o global
        webhook = config.TEAMS_WEBHOOK_CTI or config.TEAMS_WEBHOOK_URL
        return send_card(card_payload, webhook_url=webhook)

    def send_report(self, stats: dict[str, Any], report_type: str) -> bool:
        if report_type == "weekly":
            card = build_weekly_report_card(stats)
        else:
            card = build_monthly_report_card(stats)

        # Relatórios vão para o canal global (ou CTI se global não existir)
        webhook = config.TEAMS_WEBHOOK_URL or config.TEAMS_WEBHOOK_CTI
        return send_card(card, webhook_url=webhook)
