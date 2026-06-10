"""
core/notifications/telegram_notifier.py — Notificador Telegram (único canal de saída).
"""

import hashlib
import os
from dataclasses import asdict
from typing import Any

import config
from core.models import StandardCVEAlert, StandardCTINews
from core.clients.telegram_client import send_message, send_document
from core.logger import get_logger

from core.notifications.formatters.cve_formatter import build_cve_telegram_message
from core.notifications.formatters.cti_formatter import (
    build_news_telegram_message,
    build_hunting_telegram_message,
)
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

    def _pptx_keyboard(self, news: StandardCTINews) -> dict[str, Any] | None:
        """Botão 'Gerar PPTX' do card: persiste o payload e devolve o teclado.

        Só aparece se o recurso está habilitado e o template existe. O token é
        derivado da URL (idempotente) e cabe folgado no limite de 64 bytes do
        callback_data.
        """
        if not config.PPTX_ENABLED or not os.path.exists(config.PPTX_TEMPLATE_PATH):
            return None
        from core import storage
        key = news.url or news.title or ""
        if not key:
            return None
        token = hashlib.sha1(key.encode("utf-8")).hexdigest()[:12]
        try:
            storage.save_pptx_payload(token, asdict(news))
        except Exception as exc:
            logger.warning("Falha ao persistir payload PPTX: %s", exc)
            return None
        return {"inline_keyboard": [[{"text": "📊 Gerar PPTX", "callback_data": f"ppt:{token}"}]]}

    def send_cti_news(self, news: StandardCTINews) -> bool:
        if not config.TELEGRAM_BOT_TOKEN or not config.TELEGRAM_CHAT_ID_CTI:
            return False
        html_msg = build_news_telegram_message(news)
        keyboard = self._pptx_keyboard(news)
        ok = send_message(config.TELEGRAM_CHAT_ID_CTI, html_msg, parse_mode="HTML", reply_markup=keyboard)

        # Card complementar de Threat Hunting (KQL p/ Microsoft Sentinel), se houver
        hunt_msg = build_hunting_telegram_message(news)
        if hunt_msg:
            send_message(config.TELEGRAM_CHAT_ID_CTI, hunt_msg, parse_mode="HTML")
        return ok

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
