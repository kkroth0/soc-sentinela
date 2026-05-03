"""
cti/formatter.py — Monta Adaptive Cards de notícias CTI para o Microsoft Teams.
"""

import html

from typing import Any

from core.utils.security import escape_adaptive_card_markdown, sanitize_url
from core.logger import get_logger

logger = get_logger("core.notifications.formatters.cti_formatter")

_CATEGORY_LABEL = "🔵 Threat Intelligence"

_LAYER_LABELS: dict[int, str] = {
    1: "🔴 CVE / Exploit DB",
    2: "🟠 Vendor Advisory",
    3: "🔵 Threat Intelligence",
    4: "🟢 Radar Regional (BR/LATAM)",
}


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
            matched_assets=news_input.get("impacted_clients") or news_input.get("matched_assets", []),
            iocs=news_input.get("iocs", "")
        )
    else:
        news = news_input

    title_esc = escape_adaptive_card_markdown(news.title)
    summary_esc = escape_adaptive_card_markdown(news.summary)
    source_esc = escape_adaptive_card_markdown(news.source)
    url_san = sanitize_url(news.url)
    iocs_raw = news.iocs
    iocs_md = ""
    if isinstance(iocs_raw, dict):
        lines = []
        for key, values in iocs_raw.items():
            if not values or "nenhum" in str(values).lower(): continue
            lines.append(f"**{key}:**")
            if isinstance(values, list):
                for v in values:
                    if isinstance(v, dict):
                        for k2, v2 in v.items():
                            if v2 and "nenhum" not in str(v2).lower(): lines.append(f"- `{v2}` ({k2})")
                    else:
                        lines.append(f"- `{v}`")
            else:
                lines.append(f"- `{values}`")
        iocs_md = "\n".join(lines)
    elif isinstance(iocs_raw, list):
        iocs_md = "\n".join([f"- `{v}`" for v in iocs_raw])
    else:
        iocs_md = f"`{str(iocs_raw)}`" if iocs_raw else ""
    
    layer_label = _LAYER_LABELS.get(news.layer, "📰 Notícia")

    body = [
        build_header(f"🚨 CTI Report - {title_esc}", "", color="accent"),
        build_fact_set([
            ("Categoria", _CATEGORY_LABEL),
            ("Fonte", source_esc),
            ("Camada", layer_label),
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

    if iocs_md and "Nenhum IoC" not in iocs_md:
        body.extend([
            build_section_title("🛡️ Indicadores (IoCs)"),
            {
                "type": "Container",
                "style": "emphasis",
                "items": [{"type": "TextBlock", "text": iocs_md, "wrap": True, "size": "Small", "fontType": "Monospace"}]
            }
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
            matched_assets=news_input.get("impacted_clients") or news_input.get("matched_assets", []),
            iocs=news_input.get("iocs", "")
        )
    else:
        news = news_input

    title = html.escape(news.title)
    summary = html.escape(news.summary)
    source = html.escape(news.source)
    url = html.escape(news.url)
    iocs_raw = news.iocs
    iocs_text = ""
    
    if isinstance(iocs_raw, dict):
        lines = []
        for key, values in iocs_raw.items():
            if not values or "nenhum" in str(values).lower(): continue
            lines.append(f"<b>{key}:</b>")
            if isinstance(values, list):
                for v in values:
                    if isinstance(v, dict): # Caso de hashes aninhados
                        for k2, v2 in v.items():
                            if v2 and "nenhum" not in str(v2).lower(): lines.append(f"• {k2}: <code>{v2}</code>")
                    else:
                        lines.append(f"• <code>{v}</code>")
            else:
                lines.append(f"• <code>{values}</code>")
        iocs_text = "\n".join(lines)
    elif isinstance(iocs_raw, list):
        iocs_text = "\n".join([f"• <code>{v}</code>" for v in iocs_raw])
    else:
        iocs_text = f"<code>{html.escape(str(iocs_raw))}</code>" if iocs_raw else ""

    layer_label = _LAYER_LABELS.get(news.layer, "📰 Notícia")

    msg = f"🚨 <b>{layer_label}</b>\n"
    msg += f"━━━━━━━━━━━━━━\n"
    msg += f"🔥 <b>{title}</b>\n\n"
    
    msg += f"🏢 <b>Fonte:</b> {source}\n"
    if news.date:
        msg += f"📅 <b>Data:</b> {news.date[:10]}\n"
    
    if news.matched_assets:
        msg += f"🎯 <b>Ativos:</b> {', '.join(news.matched_assets)}\n"
    
    msg += f"\n"

    if summary:
        paragraphs = [p.strip() for p in summary.split("\n\n") if p.strip()]
        if len(paragraphs) >= 2:
            msg += f"📝 <b>RESUMO DO EVENTO</b>\n{paragraphs[0]}\n\n"
            msg += f"🛡️ <b>ANÁLISE E MITIGAÇÃO</b>\n{paragraphs[1]}\n\n"
        else:
            msg += f"📝 <b>RESUMO PROFISSIONAL</b>\n{summary}\n\n"

    if iocs_text:
        msg += f"🛡️ <b>INDICADORES (IoCs)</b>\n"
        msg += f"{iocs_text}\n\n"

    if url:
        msg += f"🔗 <a href='{url}'>Acesse o artigo completo</a>"

    return msg
