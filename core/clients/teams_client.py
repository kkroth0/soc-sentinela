"""
core/clients/teams_client.py — Envio bruto de Adaptive Cards para o webhook do Microsoft Teams.
"""

import time
from typing import Any

import config
from core.clients import http_client
from core.logger import get_logger

logger = get_logger("core.clients.teams_client")


def send_card(card_payload: dict[str, Any]) -> bool:
    """
    Envia um Adaptive Card para o webhook do Teams.
    Retorna True se o envio foi bem-sucedido (HTTP 200), False caso contrário.
    """
    if not config.TEAMS_WEBHOOK_URL:
        logger.error("TEAMS_WEBHOOK_URL não configurado — card descartado")
        return False

    envelope = {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "contentUrl": None,
                "content": card_payload,
            }
        ],
    }

    try:
        response = http_client.post(config.TEAMS_WEBHOOK_URL, json=envelope)
        if response.status_code in (200, 202):
            logger.info("Card enviado ao Teams com sucesso (HTTP %d)", response.status_code)
            return True

        logger.error(
            "Falha ao enviar card ao Teams — HTTP %d: %s",
            response.status_code,
            response.text[:200],
        )
        return False

    except Exception as exc:
        logger.error("Exceção ao enviar card ao Teams: %s", exc)
        return False


def send_multiple_cards(cards: list[dict[str, Any]], delay_seconds: float = 1.0) -> int:
    """
    Envia múltiplos Adaptive Cards ao Teams com delay entre eles.
    Retorna a quantidade de envios bem-sucedidos.
    """

    success_count = 0
    for i, card in enumerate(cards):
        if send_card(card):
            success_count += 1
        if i < len(cards) - 1:
            time.sleep(delay_seconds)

    logger.info("Enviados %d/%d cards ao Teams", success_count, len(cards))
    return success_count
