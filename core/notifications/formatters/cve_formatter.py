"""
core/notifications/formatters/cve_formatter.py — Monta Adaptive Cards de CVE para o Microsoft Teams.
Refatorado v8.0 para usar a component_factory e design unificado.
"""
from typing import Any
from core.utils.security import escape_adaptive_card_markdown, sanitize_url
from core.logger import get_logger
from core.notifications.formatters.component_factory import (
    build_header, build_fact_set, build_section_title, wrap_card
)

logger = get_logger("core.notifications.formatters.cve_formatter")

_SEVERITY_COLORS: dict[str, str] = {
    "CRITICAL": "attention",
    "HIGH": "warning",
    "MEDIUM": "accent",
    "LOW": "good",
    "LOG_ONLY": "default",
}

_CATEGORY_LABEL = "🟠 Análise de Vulnerabilidade"

from core.models import StandardCVEAlert

def build_cve_card(cve_input: Any) -> dict[str, Any]:
    """Monta Adaptive Card para uma CVE usando a component_factory."""
    # Garante que temos um objeto StandardCVEAlert (DTO)
    if isinstance(cve_input, dict):
        # Mapeia campos do dict para o construtor da Dataclass se necessário
        cve = StandardCVEAlert(
            cve_id=cve_input.get("cve_id", "N/A"),
            cvss_score=cve_input.get("cvss_score"),
            severity=cve_input.get("severity", "UNKNOWN"),
            risk_tag=cve_input.get("risk_tag", "UNKNOWN"),
            vendor=cve_input.get("vendor", "N/A"),
            product=cve_input.get("product", "N/A"),
            description=cve_input.get("description_pt") or cve_input.get("description", ""),
            url=cve_input.get("url", ""),
            date=cve_input.get("date", ""),
            impacted_clients=cve_input.get("impacted_clients", []),
            in_cisa_kev=cve_input.get("in_cisa_kev", False),
            has_exploit_db=cve_input.get("has_exploit_db", False),
            headline=cve_input.get("headline_pt", ""),
            raw_payload=cve_input.get("raw", {})
        )
    else:
        cve = cve_input

    # Sanitização simplificada usando os atributos do DTO
    cve_id_esc = escape_adaptive_card_markdown(cve.cve_id)
    cvss_str = f"{cve.cvss_score:.1f}" if cve.cvss_score is not None else "N/A"
    vendor_esc = escape_adaptive_card_markdown(cve.vendor.title())
    product_esc = escape_adaptive_card_markdown(cve.product.title())
    url_san = sanitize_url(cve.url)
    date_str = cve.date[:10] if cve.date else "N/A"
    headline_esc = escape_adaptive_card_markdown(cve.headline or f"Alerta de Segurança para {cve_id_esc}")
    description_esc = escape_adaptive_card_markdown(cve.description)
    
    references = cve.raw_payload.get("references", [])
    
    color = _SEVERITY_COLORS.get(cve.risk_tag, "default")

    body = [
        build_header(f"🚨 Alerta de Segurança - {product_esc} ({cve_id_esc})", headline_esc, color=color)
    ]

    # Badges (KEV / Exploit)
    in_kev = cve.in_cisa_kev if hasattr(cve, "in_cisa_kev") else cve.get("in_cisa_kev")
    if in_kev:
        body.append({
            "type": "Container", "style": "attention", "spacing": "Small",
            "items": [{"type": "TextBlock", "text": "🔥 CISA KEV — Exploração Ativa Confirmada", "weight": "Bolder", "horizontalAlignment": "Center", "size": "Small"}]
        })
        
    has_db = cve.has_exploit_db if hasattr(cve, "has_exploit_db") else cve.get("has_exploit_db")
    if has_db:
        body.append({
            "type": "Container", "style": "warning", "spacing": "Small",
            "items": [{"type": "TextBlock", "text": "☢️ Exploit-DB — PoC Disponível", "weight": "Bolder", "horizontalAlignment": "Center", "size": "Small"}]
        })

    # Fatos principais
    body.append(build_fact_set([
        ("Categoria", _CATEGORY_LABEL),
        ("Produto", product_esc),
        ("Vendor", vendor_esc),
        ("CVE", cve_id_esc),
        ("Severidade", f"{cve.risk_tag} | CVSS: {cvss_str}"),
        ("Data de Divulgação", date_str),
    ]))

    # Descrição separada em parágrafos (IA gera 2 parágrafos)
    paragraphs = [p.strip() for p in description_esc.split("\n\n") if p.strip()]
    if len(paragraphs) >= 2:
        body.extend([
            build_section_title("📝 Resumo Profissional"),
            {"type": "TextBlock", "text": paragraphs[0], "wrap": True, "spacing": "Small", "size": "Small", "isSubtle": True},
            build_section_title("🔍 Escopo e Impacto Técnico"),
            {"type": "TextBlock", "text": paragraphs[1], "wrap": True, "spacing": "Small", "size": "Small", "isSubtle": True}
        ])
    else:
        body.extend([
            build_section_title("📝 Descrição Técnica"),
            {"type": "TextBlock", "text": description_esc, "wrap": True, "spacing": "Small", "size": "Small", "isSubtle": True}
        ])

    # Impacto de Clientes
    if cve.impacted_clients:
        body.append({
            "type": "Container", "style": "emphasis", "spacing": "Medium",
            "items": [{"type": "TextBlock", "text": f"🎯 **Ativos Correspondentes:** {' | '.join(cve.impacted_clients)}", "weight": "Bolder", "wrap": True, "size": "Small"}]
        })

    # Referências
    if references:
        body.append(build_section_title("🌐 Referências Oficiais"))
        for ref in references[:3]:
            ref_url = ref.get("url", "")
            if ref_url:
                body.append({"type": "TextBlock", "text": f"• [{ref_url}]({ref_url})", "wrap": True, "size": "Small", "spacing": "None", "isSubtle": True})

    actions = [{"type": "Action.OpenUrl", "title": "Consulte Fonte NVD", "url": url_san}] if url_san else None
    
    logger.info("Card montado para CVE %s (%s)", cve_id_esc, cve.risk_tag)
    return wrap_card(body, actions)

def build_cve_telegram_message(cve: Any) -> str:
    """Monta mensagem rica para o Telegram."""
    import html
    
    cve_id = html.escape(cve.cve_id)
    cvss = f"{cve.cvss_score:.1f}" if cve.cvss_score is not None else "N/A"
    vendor = html.escape(cve.vendor.upper())
    product = html.escape(cve.product.upper())
    headline = html.escape(cve.headline or f"Alerta de Segurança {cve_id}")
    description = html.escape(cve.description)
    url = html.escape(cve.url)
    
    # Emojis de severidade
    severity_map = {"CRITICAL": "🔴 CRÍTICA", "HIGH": "🟠 ALTA", "MEDIUM": "🟡 MÉDIA", "LOW": "🟢 BAIXA"}
    sev_label = severity_map.get(cve.risk_tag, f"⚪ {cve.risk_tag}")
    
    msg = f"🔥 <b>{headline}</b>\n"
    msg += f"━━━━━━━━━━━━━━\n"
    msg += f"🆔 <b>CVE:</b> {cve_id}\n"
    msg += f"📊 <b>Risco:</b> {sev_label} (CVSS {cvss})\n"
    msg += f"🏢 <b>Vendor:</b> {vendor}\n"
    msg += f"📦 <b>Produto:</b> {product}\n\n"
    
    paragraphs = [p.strip() for p in description.split("\n\n") if p.strip()]
    if len(paragraphs) >= 2:
        msg += f"📝 <b>RESUMO</b>\n{paragraphs[0]}\n\n"
        msg += f"🔍 <b>IMPACTO TÉCNICO</b>\n{paragraphs[1]}\n\n"
    else:
        msg += f"📝 <b>DESCRIÇÃO</b>\n{description}\n\n"
        
    if cve.impacted_clients:
        msg += f"🎯 <b>ATIVOS:</b> <code>{', '.join(cve.impacted_clients)}</code>\n\n"
        
    if url:
        msg += f"🔗 <a href='{url}'>Ver detalhes na NVD</a>"
        
    return msg
