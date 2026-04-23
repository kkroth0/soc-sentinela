"""
cti/formatter.py — Monta Adaptive Cards de notícias CTI para o Microsoft Teams.
"""

import html

from typing import Any

from core.logger import get_logger

logger = get_logger("core.notifications.formatters.cti_formatter")

_LAYER_LABELS: dict[int, str] = {
    1: "🔴 CVE / Exploit DB",
    2: "🟠 Vendor Advisory",
    3: "🔵 Threat Intelligence",
    4: "🟢 Radar Regional (BR/LATAM)",
}


def build_news_card(article: dict[str, Any]) -> dict[str, Any]:
    """Monta Adaptive Card para um artigo de notícia CTI."""
    title = article.get("title_pt") or article.get("title", "Sem título")
    summary = article.get("summary_pt") or article.get("summary", "")
    source = article.get("source", "Desconhecido")
    layer = article.get("layer", 3)
    url = article.get("url", "")
    date = article.get("date", "")

    layer_label = _LAYER_LABELS.get(layer, "📰 Notícia")

    body: list[dict] = [
        {
            "type": "TextBlock",
            "text": f"{layer_label}",
            "weight": "Bolder",
            "size": "Small",
            "color": "accent",
        },
        {
            "type": "TextBlock",
            "text": title,
            "weight": "Bolder",
            "size": "Medium",
            "wrap": True,
        },
        {
            "type": "FactSet",
            "facts": [
                {"title": "Fonte", "value": source},
                {"title": "Data", "value": date[:10] if date else "N/A"},
            ],
        },
    ]

    if summary:
        body.append({
            "type": "TextBlock",
            "text": summary[:400],
            "wrap": True,
            "spacing": "Medium",
        })

    actions: list[dict] = []
    if url:
        actions.append({
            "type": "Action.OpenUrl",
            "title": "Ler artigo completo",
            "url": url,
        })

    card: dict[str, Any] = {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.4",
        "body": body,
    }
    if actions:
        card["actions"] = actions

    logger.info("Card de notícia montado: %s (%s)", source, title[:40])
    return card

def build_news_telegram_message(article: dict[str, Any]) -> str:
    """Monta a mensagem HTML para o Telegram escapando campos."""

    title = html.escape(article.get("title_pt") or article.get("title", "Sem título"))
    summary = html.escape(article.get("summary_pt") or article.get("summary", ""))
    source = html.escape(article.get("source", "Desconhecido"))
    layer = article.get("layer", 3)
    url = html.escape(article.get("url", ""))

    layer_label = _LAYER_LABELS.get(layer, "📰 Notícia")

    msg = f"<b>{layer_label}</b>\n\n"
    msg += f"<b>{title}</b>\n\n"
    msg += f"<b>Fonte:</b> {source}\n\n"
    if summary:
        msg += f"{summary[:400]}\n\n"

    if url:
        msg += f"<a href='{url}'>Ler artigo completo</a>"

    return msg
