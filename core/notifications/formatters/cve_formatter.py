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

def build_cve_card(cve: Any) -> dict[str, Any]:
    """Monta Adaptive Card para uma CVE usando a component_factory."""
    # Extração de dados (Objeto ou Dict)
    cve_id = cve.cve_id if hasattr(cve, "cve_id") else cve.get("cve_id", "N/A")
    risk_tag = cve.risk_tag if hasattr(cve, "risk_tag") else cve.get("risk_tag", "UNKNOWN")
    cvss = cve.cvss_score if hasattr(cve, "cvss_score") else cve.get("cvss_score")
    vendor = cve.vendor if hasattr(cve, "vendor") else cve.get("vendor", "N/A")
    product = cve.product if hasattr(cve, "product") else cve.get("product", "N/A")
    url = cve.url if hasattr(cve, "url") else cve.get("url", "")
    date = cve.date if hasattr(cve, "date") else cve.get("date", "")
    headline = cve.headline if hasattr(cve, "headline") else cve.get("headline", "")
    description = cve.description if hasattr(cve, "description") else (cve.get("description_pt") or cve.get("description", ""))
    clients = cve.impacted_clients if hasattr(cve, "impacted_clients") else cve.get("impacted_clients", [])
    
    # Sanitização
    cve_id_esc = escape_adaptive_card_markdown(cve_id)
    cvss_str = f"{cvss:.1f}" if cvss is not None else "N/A"
    vendor_esc = escape_adaptive_card_markdown(vendor.title())
    product_esc = escape_adaptive_card_markdown(product.title())
    url_san = sanitize_url(url)
    date_str = date[:10] if date else "N/A"
    headline_esc = escape_adaptive_card_markdown(headline or f"Alerta de Segurança para {cve_id_esc}")
    description_esc = escape_adaptive_card_markdown(description)
    
    raw_data = cve.raw_payload if hasattr(cve, "raw_payload") else cve.get("raw", {})
    references = raw_data.get("references", [])
    
    color = _SEVERITY_COLORS.get(risk_tag, "default")

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
        ("Produto", product_esc),
        ("Vendor", vendor_esc),
        ("CVE", cve_id_esc),
        ("Severidade", f"{risk_tag} | CVSS: {cvss_str}"),
        ("Data de Divulgação", date_str),
    ]))

    # Descrição
    full_desc = description_esc[:800]
    if url_san: full_desc += f"\n\n**Fonte:** [{url_san}]({url_san})"
    body.extend([
        build_section_title("Descrição Técnica"),
        {"type": "TextBlock", "text": full_desc, "wrap": True, "spacing": "Small", "size": "Small", "isSubtle": True}
    ])

    # Impacto de Clientes
    if clients:
        body.append({
            "type": "Container", "style": "attention", "spacing": "Medium",
            "items": [{"type": "TextBlock", "text": f"🎯 **Ativos Correspondentes:** {' | '.join(clients)}", "weight": "Bolder", "wrap": True, "size": "Small"}]
        })

    # Referências
    if references:
        body.append(build_section_title("Referências e Mitigação"))
        for ref in references[:3]:
            ref_url = ref.get("url", "")
            if ref_url:
                body.append({"type": "TextBlock", "text": f"• [{ref_url}]({ref_url})", "wrap": True, "size": "Small", "spacing": "None", "isSubtle": True})

    actions = [{"type": "Action.OpenUrl", "title": "Consulte Fonte NVD", "url": url_san}] if url_san else None
    
    logger.info("Card montado para CVE %s (%s)", cve_id_esc, risk_tag)
    return wrap_card(body, actions)

def build_cve_telegram_message(cve: Any) -> str:
    """Mantém compatibilidade com Telegram."""
    # ... lógica simplificada para Telegram ...
    cve_id = cve.cve_id if hasattr(cve, "cve_id") else cve.get("cve_id", "N/A")
    return f"🚨 <b>Alerta CVE: {cve_id}</b>"
