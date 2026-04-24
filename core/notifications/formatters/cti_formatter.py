"""
cti/formatter.py — Monta Adaptive Cards de notícias CTI para o Microsoft Teams.
"""

import html

from typing import Any

from core.utils.security import escape_adaptive_card_markdown, sanitize_url
from core.logger import get_logger

logger = get_logger("core.notifications.formatters.cti_formatter")

_LAYER_LABELS: dict[int, str] = {
    1: "🔴 CVE / Exploit DB",
    2: "🟠 Vendor Advisory",
    3: "🔵 Threat Intelligence",
    4: "🟢 Radar Regional (BR/LATAM)",
}


from core.notifications.formatters.component_factory import (
    build_header, build_fact_set, build_section_title, wrap_card
)

def build_news_card(news: Any) -> dict[str, Any]:
    """Monta Adaptive Card para um artigo de notícia CTI com design Premium."""
    # Suporte a objeto ou dicionário
    title = news.title if hasattr(news, "title") else news.get("title_pt", news.get("title", "Sem título"))
    summary = news.summary if hasattr(news, "summary") else news.get("summary_pt", news.get("summary", ""))
    source = news.source if hasattr(news, "source") else news.get("source", "Desconhecido")
    layer = news.layer if hasattr(news, "layer") else news.get("layer", 3)
    url = news.url if hasattr(news, "url") else news.get("url", "")
    date = news.date if hasattr(news, "date") else news.get("date", "")
    clients = news.matched_assets if hasattr(news, "matched_assets") else news.get("impacted_clients", [])

    title_esc = escape_adaptive_card_markdown(title)
    summary_esc = escape_adaptive_card_markdown(summary)
    source_esc = escape_adaptive_card_markdown(source)
    url_san = sanitize_url(url)
    
    layer_label = _LAYER_LABELS.get(layer, "📰 Notícia")

    body = [
        build_header(f"🚨 CTI Report - {title_esc}", layer_label, color="accent"),
        build_fact_set([
            ("Fonte", source_esc),
            ("Data", date[:10] if date else "N/A")
        ])
    ]

    if clients:
        body.append({
            "type": "Container",
            "style": "attention",
            "spacing": "Medium",
            "items": [{
                "type": "TextBlock",
                "text": f"🎯 **Ativos Correspondentes:** {' | '.join(clients)}",
                "weight": "Bolder", "wrap": True, "size": "Small"
            }]
        })

    if summary_esc:
        text = summary_esc[:800]
        if url_san: text += f"\n\n**Fonte:** [{url_san}]({url_san})"
        body.extend([
            build_section_title("Resumo Profissional"),
            {"type": "TextBlock", "text": text, "wrap": True, "spacing": "Small", "size": "Small", "isSubtle": True}
        ])

    actions = [{"type": "Action.OpenUrl", "title": "Ler artigo completo", "url": url_san}] if url_san else None
    
    logger.info("Card de notícia montado: %s (%s)", source_esc, title_esc[:40])
    return wrap_card(body, actions)

def build_news_telegram_message(news: Any) -> str:
    """Monta a mensagem HTML para o Telegram escapando campos."""
    # Suporte a objeto ou dicionário
    title = news.title if hasattr(news, "title") else news.get("title_pt", news.get("title", "Sem título"))
    summary = news.summary if hasattr(news, "summary") else news.get("summary_pt", news.get("summary", ""))
    source = news.source if hasattr(news, "source") else news.get("source", "Desconhecido")
    layer = news.layer if hasattr(news, "layer") else news.get("layer", 3)
    url = news.url if hasattr(news, "url") else news.get("url", "")

    title = html.escape(title)
    summary = html.escape(summary)
    source = html.escape(source)
    url = html.escape(url)

    layer_label = _LAYER_LABELS.get(layer, "📰 Notícia")

    msg = f"<b>{layer_label}</b>\n\n"
    msg += f"<b>{title}</b>\n\n"
    msg += f"<b>Fonte:</b> {source}\n\n"
    if summary:
        msg += f"{summary[:400]}\n\n"

    if url:
        msg += f"<a href='{url}'>Ler artigo completo</a>"

    return msg
