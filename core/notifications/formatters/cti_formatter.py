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
    """Monta Adaptive Card para um artigo de notícia CTI com design Premium."""
    title = article.get("title_pt") or article.get("title", "Sem título")
    summary = article.get("summary_pt") or article.get("summary", "")
    source = article.get("source", "Desconhecido")
    layer = article.get("layer", 3)
    url = article.get("url", "")
    date = article.get("date", "")
    clients = article.get("impacted_clients", [])

    layer_label = _LAYER_LABELS.get(layer, "📰 Notícia")

    body: list[dict] = [
        # 1. Header Banner
        {
            "type": "Container",
            "style": "accent",
            "bleed": True,
            "items": [
                {
                    "type": "TextBlock",
                    "text": f"🚨 CTI Report - {title}",
                    "weight": "Bolder",
                    "size": "Medium",
                    "wrap": True,
                    "color": "Light"
                },
                {
                    "type": "TextBlock",
                    "text": layer_label,
                    "size": "Small",
                    "isSubtle": True,
                    "spacing": "None",
                    "color": "Light"
                }
            ]
        },
        # 2. Source Info
        {
            "type": "FactSet",
            "facts": [
                {"title": "Fonte", "value": source},
                {"title": "Data", "value": date[:10] if date else "N/A"},
            ],
            "spacing": "Medium"
        }
    ]

    # 3. Impacted Clients (Targeting)
    if clients:
        body.append({
            "type": "Container",
            "style": "attention",
            "spacing": "Medium",
            "items": [{
                "type": "TextBlock",
                "text": f"🎯 **Ativos Correspondentes:** {' | '.join(clients)}",
                "weight": "Bolder",
                "wrap": True,
                "size": "Small"
            }]
        })

    # 4. Summary
    if summary:
        text = summary[:800]
        if url:
            text += f"\n\n**Fonte:** [{url}]({url})"
            
        body.extend([
            {
                "type": "TextBlock",
                "text": "Resumo Profissional",
                "weight": "Bolder",
                "spacing": "Medium",
                "size": "Small",
                "separator": True
            },
            {
                "type": "TextBlock",
                "text": text,
                "wrap": True,
                "spacing": "Small",
                "size": "Small",
                "isSubtle": True
            }
        ])

    card: dict[str, Any] = {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.4",
        "body": body,
        "msteams": {"width": "Full"}
    }
    
    actions: list[dict] = []
    if url:
        actions.append({
            "type": "Action.OpenUrl",
            "title": "Ler artigo completo",
            "url": url,
        })
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
