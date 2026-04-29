"""
cti/formatter.py — Monta Adaptive Cards de notícias CTI para o Microsoft Teams.
"""

import html

from typing import Any

from core.utils.security import escape_adaptive_card_markdown, sanitize_url
from core.logger import get_logger

logger = get_logger("core.notifications.formatters.cti_formatter")

_CATEGORY_LABEL = "🔵 Threat Intelligence"


from core.notifications.formatters.component_factory import (
    build_header, build_fact_set, build_section_title, wrap_card
)

from core.models import StandardCTINews

def build_news_card(news_input: Any) -> dict[str, Any]:
    """Monta Adaptive Card para um artigo de notícia CTI com design Premium."""
    # Garante que temos um objeto StandardCTINews (DTO)
    if isinstance(news_input, dict):
        news = StandardCTINews(
            title=news_input.get("title_pt") or news_input.get("title", "Sem título"),
            summary=news_input.get("summary_pt") or news_input.get("summary", ""),
            source=news_input.get("source", "Desconhecido"),
            layer=int(news_input.get("layer", 3)),
            url=news_input.get("url", ""),
            date=news_input.get("date", ""),
            matched_assets=news_input.get("impacted_clients") or news_input.get("matched_assets", [])
        )
    else:
        news = news_input

    title_esc = escape_adaptive_card_markdown(news.title)
    summary_esc = escape_adaptive_card_markdown(news.summary)
    source_esc = escape_adaptive_card_markdown(news.source)
    url_san = sanitize_url(news.url)
    
    body = [
        build_header(f"🚨 CTI Report - {title_esc}", "", color="accent"),
        build_fact_set([
            ("Categoria", _CATEGORY_LABEL),
            ("Fonte", source_esc),
            ("Data", news.date[:10] if news.date else "N/A")
        ])
    ]

    if news.matched_assets:
        body.append({
            "type": "Container",
            "style": "attention",
            "spacing": "Medium",
            "items": [{
                "type": "TextBlock",
                "text": f"🎯 **Ativos Correspondentes:** {' | '.join(news.matched_assets)}",
                "weight": "Bolder", "wrap": True, "size": "Small"
            }]
        })

    if summary_esc:
        text = summary_esc[:800]
        if url_san: text += f"\n\n**Fonte:** [{url_san}]({url_san})"
        body.extend([
            build_section_title("Descrição"),
            {"type": "TextBlock", "text": text, "wrap": True, "spacing": "Small", "size": "Small", "isSubtle": True}
        ])

    actions = [{"type": "Action.OpenUrl", "title": "Ler artigo completo", "url": url_san}] if url_san else None
    
    logger.info("Card de notícia montado: %s (%s)", source_esc, title_esc[:40])
    return wrap_card(body, actions)

def build_news_telegram_message(news_input: Any) -> str:
    """Monta a mensagem HTML para o Telegram escapando campos."""
    # Garante que temos um objeto StandardCTINews (DTO)
    if isinstance(news_input, dict):
        news = StandardCTINews(
            title=news_input.get("title_pt") or news_input.get("title", "Sem título"),
            summary=news_input.get("summary_pt") or news_input.get("summary", ""),
            source=news_input.get("source", "Desconhecido"),
            layer=int(news_input.get("layer", 3)),
            url=news_input.get("url", ""),
            date=news_input.get("date", ""),
            matched_assets=news_input.get("impacted_clients") or news_input.get("matched_assets", [])
        )
    else:
        news = news_input

    title = html.escape(news.title)
    summary = html.escape(news.summary)
    source = html.escape(news.source)
    url = html.escape(news.url)

    layer_label = _LAYER_LABELS.get(news.layer, "📰 Notícia")

    msg = f"<b>{layer_label}</b>\n\n"
    msg += f"<b>{title}</b>\n\n"
    msg += f"<b>Fonte:</b> {source}\n\n"
    if summary:
        msg += f"{summary[:400]}\n\n"

    if url:
        msg += f"<a href='{url}'>Ler artigo completo</a>"

    return msg
