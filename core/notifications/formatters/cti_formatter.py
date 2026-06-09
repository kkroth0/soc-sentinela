"""
core/notifications/formatters/cti_formatter.py — Monta cartões HTML de notícias CTI
para o Telegram.

Cartão *adaptável por camada* (layer): o cabeçalho, a cor de severidade e o título
da seção de análise mudam conforme o tipo do conteúdo. Notícias de ameaça (camadas
1–3) recebem a seção "Impacto & Mitigação"; o Radar Regional/mercado (camada 4)
recebe "Por que importa" — evitando o antigo template de segurança forçado em
notícias que não são incidentes técnicos.
"""

import html
from typing import Any

from core.logger import get_logger
from core.models import StandardCTINews
from core.notifications.formatters import TELEGRAM_MAX_LEN, clamp_telegram

logger = get_logger("core.notifications.formatters.cti_formatter")

# Metadados por camada: a camada agora identifica o TIPO de fonte (não a
# severidade). O rótulo é honesto quanto à origem; `title_icon` e o rótulo da
# segunda seção (ameaça vs. contexto) seguem adaptando-se à camada.
_LAYER_META: dict[int, dict[str, str]] = {
    1: {"label": "🛡️ Vendor Advisory",          "title_icon": "🚨", "analysis": "🛡️ IMPACTO &amp; MITIGAÇÃO"},
    2: {"label": "📰 Security News",             "title_icon": "🚨", "analysis": "🛡️ IMPACTO &amp; MITIGAÇÃO"},
    3: {"label": "🔬 Threat Research",           "title_icon": "🚨", "analysis": "🛡️ IMPACTO &amp; MITIGAÇÃO"},
    4: {"label": "📡 Radar Regional (BR/LATAM)", "title_icon": "📡", "analysis": "🎯 POR QUE IMPORTA"},
}
_DEFAULT_META: dict[str, str] = {
    "label": "📰 Notícia", "title_icon": "📰", "analysis": "📝 ANÁLISE",
}

_SEV_EMOJI: dict[str, str] = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}

# Faixas de severidade derivadas do score de relevância (0-100). A COR do cartão
# segue a urgência real, não a camada — um item regional crítico fica vermelho.
_SEVERITY_BANDS: list[tuple[int, str, str]] = [
    (80, "🔴", "CRÍTICO"),
    (60, "🟠", "ALTO"),
    (40, "🟡", "MÉDIO"),
    (0,  "🟢", "BAIXO"),
]


def _severity(score: int) -> tuple[str, str]:
    """Retorna (emoji, rótulo) da faixa de severidade para o score dado."""
    for threshold, emoji, label in _SEVERITY_BANDS:
        if score >= threshold:
            return emoji, label
    return "🟢", "BAIXO"


def _coerce_news(news_input: Any) -> StandardCTINews:
    """Aceita tanto um dict bruto quanto um DTO StandardCTINews."""
    if isinstance(news_input, StandardCTINews):
        return news_input
    if isinstance(news_input, dict):
        return StandardCTINews(
            title=news_input.get("title_pt") or news_input.get("title", "Sem título"),
            summary=news_input.get("summary_pt") or news_input.get("summary", ""),
            source=news_input.get("source", "Desconhecido"),
            layer=int(news_input.get("layer", 3) or 3),
            url=news_input.get("url", ""),
            date=news_input.get("date", ""),
            matched_assets=news_input.get("impacted_clients") or news_input.get("matched_assets", []),
            iocs=news_input.get("iocs", ""),
            score=int(news_input.get("score", 0) or 0),
            risk_reasons=news_input.get("risk_reasons", []),
            cwes=news_input.get("cwes", []),
            threats=news_input.get("threats", []),
            cves=news_input.get("cves", []),
            sectors=news_input.get("sectors", []),
            countries=news_input.get("countries", []),
            ttps=news_input.get("ttps", []),
        )
    raise TypeError(f"Entrada inválida para o formatter CTI: {type(news_input)!r}")


def _render_iocs(iocs_raw: Any) -> str:
    """Renderiza os IoCs (dict categorizado ou string) como linhas HTML."""
    def _is_empty(v: Any) -> bool:
        return not v or "nenhum" in str(v).lower()

    if isinstance(iocs_raw, dict):
        lines: list[str] = []
        for key, values in iocs_raw.items():
            if _is_empty(values):
                continue
            lines.append(f"<b>{html.escape(str(key))}:</b>")
            items = values if isinstance(values, list) else [values]
            for v in items:
                if isinstance(v, dict):  # hashes aninhados {algoritmo: valor}
                    for k2, v2 in v.items():
                        if not _is_empty(v2):
                            lines.append(f"• {html.escape(str(k2))}: <code>{html.escape(str(v2))}</code>")
                elif not _is_empty(v):
                    lines.append(f"• <code>{html.escape(str(v))}</code>")
        return "\n".join(lines)

    iocs_str = str(iocs_raw).strip()
    if iocs_str and "nenhum" not in iocs_str.lower():
        return f"<code>{html.escape(iocs_str)}</code>"
    return ""


def build_news_telegram_message(news_input: Any) -> str:
    """Monta o cartão HTML adaptável da notícia CTI para o Telegram."""
    news = _coerce_news(news_input)
    meta = _LAYER_META.get(news.layer, _DEFAULT_META)

    title = html.escape(news.title)
    source = html.escape(news.source)
    url = html.escape(news.url)

    parts: list[str] = []

    # ── Cabeçalho: cor = severidade (score), rótulo = tipo de fonte (camada) ──
    sev_emoji, sev_label = _severity(news.score)
    parts.append(f"{sev_emoji} <b>{sev_label}</b> · {meta['label']}")
    parts.append("━━━━━━━━━━━━━━")
    parts.append(f"{meta['title_icon']} <b>{title}</b>\n")

    # ── Metadados ──
    parts.append(f"🏢 <b>Fonte:</b> {source}")
    if news.date:
        parts.append(f"📅 <b>Data:</b> {html.escape(news.date[:10])}")
    if news.matched_assets:
        assets = ", ".join(html.escape(str(a)) for a in news.matched_assets)
        parts.append(f"🎯 <b>Ativos Monitorados:</b> {assets}")
    if news.cwes:
        parts.append(f"🏷️ <b>CWE:</b> {', '.join(html.escape(c) for c in news.cwes)}")
    if news.threats:
        parts.append(f"👾 <b>Ameaças:</b> {', '.join(html.escape(t) for t in news.threats)}")
    if news.sectors:
        parts.append(f"🏭 <b>Setores Visados:</b> {', '.join(html.escape(s) for s in news.sectors)}")
    if news.countries:
        parts.append(f"🌍 <b>Países/Regiões:</b> {', '.join(html.escape(c) for c in news.countries)}")
    if news.ttps:
        ttp_lines = ["🎯 <b>TTPs (MITRE ATT&amp;CK):</b>"]
        ttp_lines += [f"  • {html.escape(t)}" for t in news.ttps[:6]]
        parts.append("\n".join(ttp_lines))
    if news.cves:
        cve_lines = ["🔍 <b>CVEs Relacionadas:</b>"]
        for c in news.cves[:5]:
            c_id = html.escape(str(c.get("cve_id", "")))
            cvss = c.get("cvss_score")
            cvss_txt = f"CVSS {cvss}" if cvss is not None else "CVSS N/A"
            sev = str(c.get("risk_tag", "LOW"))
            emoji = _SEV_EMOJI.get(sev, "⚪")
            cve_lines.append(f"  • {emoji} <code>{c_id}</code> ({cvss_txt} · {sev})")
        parts.append("\n".join(cve_lines))

    parts.append("")  # linha em branco antes do corpo

    # ── Resumo / Análise (rótulo da 2ª seção adapta-se à camada) ──
    if news.summary:
        paragraphs = [p.strip() for p in news.summary.split("\n\n") if p.strip()]
        if len(paragraphs) >= 2:
            parts.append(f"📝 <b>RESUMO</b>\n{html.escape(paragraphs[0])}\n")
            body = "\n\n".join(html.escape(p) for p in paragraphs[1:])
            parts.append(f"{meta['analysis']}\n{body}\n")
        else:
            parts.append(f"📝 <b>RESUMO</b>\n{html.escape(news.summary)}\n")

    # ── IoCs ──
    iocs_text = _render_iocs(news.iocs)
    if iocs_text:
        parts.append(f"🛡️ <b>INDICADORES (IoCs)</b>\n{iocs_text}\n")

    # ── Link (hyperlink limpo em vez de URL crua) ──
    if news.url:
        parts.append(f'🔗 <a href="{url}">Abrir fonte original</a>')

    # ── Rodapé de relevância ──
    if news.score and news.score > 0:
        footer = f"\n📊 <b>Relevância:</b> {news.score}/100"
        if news.risk_reasons:
            reasons = ", ".join(html.escape(r) for r in news.risk_reasons[:4])
            footer += f" — {reasons}"
        parts.append(footer)

    return clamp_telegram("\n".join(parts))
