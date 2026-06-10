"""
core/clients/telegram_client.py — Módulo para envio de mensagens via Telegram Bot API.
"""

import requests
import config
from core.clients.http_client import get_session
from core.logger import get_logger

logger = get_logger("core.clients.telegram_client")

def send_message(chat_id: str, text: str, parse_mode: str = "HTML",
                 reply_markup: dict | None = None) -> bool:
    """
    Envia uma mensagem para o chat do Telegram especificado.
    `reply_markup` opcional permite anexar um teclado inline.
    Retorna True se sucesso, False caso contrário.
    """
    if not config.TELEGRAM_BOT_TOKEN or not chat_id:
        logger.debug("Telegram credentials not configured. Skipping Telegram alert.")
        return False

    url = f"https://api.telegram.org/bot{config.TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": parse_mode,
        "disable_web_page_preview": True
    }
    if reply_markup is not None:
        payload["reply_markup"] = reply_markup

    try:
        session = get_session()
        response = session.post(url, json=payload, timeout=10)
        response.raise_for_status()
        logger.info("Alert sent successfully via Telegram to %s.", chat_id)
        return True
    except requests.exceptions.RequestException as e:
        logger.error("Failed to send message to Telegram: %s", e)
        return False


def answer_callback_query(callback_query_id: str, text: str = "") -> bool:
    """Confirma um callback de teclado inline (remove o 'loading' no cliente)."""
    if not config.TELEGRAM_BOT_TOKEN:
        return False
    url = f"https://api.telegram.org/bot{config.TELEGRAM_BOT_TOKEN}/answerCallbackQuery"
    try:
        session = get_session()
        session.post(url, json={"callback_query_id": callback_query_id, "text": text}, timeout=10)
        return True
    except requests.exceptions.RequestException as e:
        logger.debug("Failed to answer callback query: %s", e)
        return False


def send_document(
    chat_id: str,
    file_path: str,
    caption: str = "",
    parse_mode: str = "HTML",
) -> bool:
    """
    Envia um arquivo (PDF, CSV, etc.) como documento para o chat do Telegram.
    Retorna True se sucesso, False caso contrário.
    """
    if not config.TELEGRAM_BOT_TOKEN or not chat_id:
        logger.debug("Telegram credentials not configured. Skipping document upload.")
        return False

    url = f"https://api.telegram.org/bot{config.TELEGRAM_BOT_TOKEN}/sendDocument"
    # Caption do Telegram tem limite de 1024 caracteres.
    data = {"chat_id": chat_id, "parse_mode": parse_mode}
    if caption:
        data["caption"] = caption[:1024]

    try:
        session = get_session()
        with open(file_path, "rb") as fh:
            files = {"document": (file_path.rsplit("/", 1)[-1], fh, "application/octet-stream")}
            response = session.post(url, data=data, files=files, timeout=60)
        response.raise_for_status()
        logger.info("Document sent successfully via Telegram to %s.", chat_id)
        return True
    except (requests.exceptions.RequestException, OSError) as e:
        logger.error("Failed to send document to Telegram: %s", e)
        return False
