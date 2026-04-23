"""
core/clients/telegram_client.py — Módulo para envio de mensagens via Telegram Bot API.
"""

import requests
import config
from core.clients.http_client import get_session
from core.logger import get_logger

logger = get_logger("core.clients.telegram_client")

def send_message(text: str, parse_mode: str = "HTML") -> bool:
    """
    Envia uma mensagem para o chat do Telegram configurado.
    Retorna True se sucesso, False caso contrário.
    """
    if not config.TELEGRAM_BOT_TOKEN or not config.TELEGRAM_CHAT_ID:
        logger.debug("Telegram credentials not configured. Skipping Telegram alert.")
        return False

    url = f"https://api.telegram.org/bot{config.TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": config.TELEGRAM_CHAT_ID,
        "text": text,
        "parse_mode": parse_mode,
        "disable_web_page_preview": True
    }

    try:
        session = get_session()
        response = session.post(url, json=payload, timeout=10)
        response.raise_for_status()
        logger.info("Alert sent successfully via Telegram.")
        return True
    except requests.exceptions.RequestException as e:
        logger.error("Failed to send message to Telegram: %s", e)
        return False
