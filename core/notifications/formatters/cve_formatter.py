"""
cve/formatter.py — Monta Adaptive Cards de CVE para o Microsoft Teams.
Layout estruturado com badges de severidade e seção de clientes impactados.
"""
import html

from typing import Any

from core.logger import get_logger

logger = get_logger("core.notifications.formatters.cve_formatter")

# Cores por risk_tag
_SEVERITY_COLORS: dict[str, str] = {
    "CRITICAL": "attention",   # Vermelho
    "HIGH": "warning",         # Laranja
    "MEDIUM": "accent",        # Azul
    "LOW": "good",             # Verde
    "LOG_ONLY": "default",     # Cinza
}


def build_cve_card(cve: dict[str, Any]) -> dict[str, Any]:
    """
    Monta Adaptive Card para uma CVE seguindo o novo template solicitado.
    """
    cve_id = cve.get("cve_id", "N/A")
    risk_tag = cve.get("risk_tag", "UNKNOWN")
    cvss = cve.get("cvss_score")
    cvss_str = f"{cvss:.1f}" if cvss is not None else "N/A"
    vendor = cve.get("vendor", "N/A").title()
    product = cve.get("product", "N/A").title()
    url = cve.get("url", "")
    date = cve.get("date", "")[:10] if cve.get("date") else "N/A"
    headline = cve.get("headline") or f"Alerta de Segurança para {cve_id}"
    description = cve.get("description_pt") or cve.get("description", "")
    
    raw_data = cve.get("raw", {})
    references = raw_data.get("references", [])
    
    # Extrair versões (simplificado)
    affected_versions = "Consulte referências"
    fixed_versions = "Consulte referências"
    
    color = _SEVERITY_COLORS.get(risk_tag, "default")

    body: list[dict] = [
        # 1. Headline Banner
        {
            "type": "Container",
            "style": color,
            "bleed": True,
            "items": [
                {
                    "type": "TextBlock",
                    "text": f"🚨 Alerta de Segurança - Vulnerabilidade {product} ({cve_id})",
                    "weight": "Bolder",
                    "size": "Medium",
                    "wrap": True,
                    "color": "Light" if color != "default" else "Default"
                },
                {
                    "type": "TextBlock",
                    "text": headline,
                    "size": "Small",
                    "wrap": True,
                    "isSubtle": True,
                    "spacing": "None",
                    "color": "Light" if color != "default" else "Default"
                }
            ]
        }
    ]

    # 2. Badges (KEV / Exploit)
    if cve.get("in_cisa_kev"):
        body.append({
            "type": "Container",
            "style": "attention",
            "spacing": "Small",
            "items": [{
                "type": "TextBlock",
                "text": "🔥 CISA KEV — Exploração Ativa Confirmada",
                "weight": "Bolder",
                "horizontalAlignment": "Center",
                "size": "Small"
            }]
        })
        
    if cve.get("has_exploit_db"):
        body.append({
            "type": "Container",
            "style": "warning",
            "spacing": "Small",
            "items": [{
                "type": "TextBlock",
                "text": "☢️ Exploit-DB — PoC Disponível",
                "weight": "Bolder",
                "horizontalAlignment": "Center",
                "size": "Small"
            }]
        })

    # 3. Key Facts
    body.append({
        "type": "FactSet",
        "facts": [
            {"title": "Produto", "value": product},
            {"title": "Vendor", "value": vendor},
            {"title": "CVE", "value": cve_id},
            {"title": "Severidade", "value": f"{risk_tag} | CVSS: {cvss_str}"},
            {"title": "Data de Divulgação", "value": date},
        ],
        "spacing": "Medium"
    })

    # 4. Descrição
    full_desc = description[:800]
    if url:
        full_desc += f"\n\n**Fonte:** [{url}]({url})"

    body.extend([
        {
            "type": "TextBlock",
            "text": "Descrição Técnica",
            "weight": "Bolder",
            "spacing": "Large",
            "size": "Small",
            "separator": True
        },
        {
            "type": "TextBlock",
            "text": full_desc,
            "wrap": True,
            "spacing": "Small",
            "size": "Small",
            "isSubtle": True
        }
    ])

    # 5. Clientes Impactados (Premium Look)
    clients = cve.get("impacted_clients", [])
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

    # 6. CVE Identificada Table
    body.extend([
        {
            "type": "TextBlock",
            "text": "CVE Identificada",
            "weight": "Bolder",
            "spacing": "Large",
            "size": "Small",
            "separator": True
        },
        {
            "type": "ColumnSet",
            "columns": [
                {"type": "Column", "width": "1", "items": [{"type": "TextBlock", "text": "**CVE**", "weight": "Bolder", "size": "Small"}]},
                {"type": "Column", "width": "1", "items": [{"type": "TextBlock", "text": "**CVSS**", "weight": "Bolder", "size": "Small"}]},
                {"type": "Column", "width": "1", "items": [{"type": "TextBlock", "text": "**Risco**", "weight": "Bolder", "size": "Small"}]},
                {"type": "Column", "width": "2", "items": [{"type": "TextBlock", "text": "**Produto**", "weight": "Bolder", "size": "Small"}]}
            ]
        },
        {
            "type": "ColumnSet",
            "spacing": "None",
            "columns": [
                {"type": "Column", "width": "1", "items": [{"type": "TextBlock", "text": cve_id, "size": "Small"}]},
                {"type": "Column", "width": "1", "items": [{"type": "TextBlock", "text": cvss_str, "size": "Small"}]},
                {"type": "Column", "width": "1", "items": [{"type": "TextBlock", "text": risk_tag, "size": "Small"}]},
                {"type": "Column", "width": "2", "items": [{"type": "TextBlock", "text": product, "size": "Small"}]}
            ]
        }
    ])

    # 7. Versões Table
    body.extend([
        {
            "type": "TextBlock",
            "text": "Versões Afetadas e Corrigidas",
            "weight": "Bolder",
            "spacing": "Large",
            "size": "Small",
            "separator": True
        },
        {
            "type": "ColumnSet",
            "columns": [
                {"type": "Column", "width": "1", "items": [{"type": "TextBlock", "text": "**Versão Afetada**", "weight": "Bolder", "size": "Small"}]},
                {"type": "Column", "width": "1", "items": [{"type": "TextBlock", "text": "**Versão Corrigida**", "weight": "Bolder", "size": "Small"}]}
            ]
        },
        {
            "type": "ColumnSet",
            "spacing": "None",
            "columns": [
                {"type": "Column", "width": "1", "items": [{"type": "TextBlock", "text": affected_versions, "size": "Small", "isSubtle": True}]},
                {"type": "Column", "width": "1", "items": [{"type": "TextBlock", "text": fixed_versions, "size": "Small", "isSubtle": True}]}
            ]
        }
    ])

    # 8. Referências
    if references:
        body.append({
            "type": "TextBlock",
            "text": "Referências e Mitigação",
            "weight": "Bolder",
            "spacing": "Large",
            "size": "Small",
            "separator": True
        })
        for ref in references[:3]:
            ref_url = ref.get("url", "")
            if ref_url:
                body.append({
                    "type": "TextBlock",
                    "text": f"• [{ref_url}]({ref_url})",
                    "wrap": True,
                    "size": "Small",
                    "spacing": "None",
                    "isSubtle": True
                })

    card: dict[str, Any] = {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.4",
        "body": body,
        "msteams": {"width": "Full"}
    }
    
    # Botões de ação
    actions = []
    actions.append({
        "type": "Action.OpenUrl",
        "title": "Consulte Fonte NVD",
        "url": url
    })
    
    card["actions"] = actions

    logger.info("Card montado para CVE %s (%s)", cve_id, risk_tag)
    return card

def build_cve_telegram_message(cve: dict[str, Any]) -> str:
    """Monta a mensagem HTML para o Telegram escapando dados."""

    cve_id = html.escape(cve.get("cve_id", "N/A"))
    risk_tag = html.escape(cve.get("risk_tag", "UNKNOWN"))
    cvss = cve.get("cvss_score")
    cvss_str = f"{cvss:.1f}" if cvss is not None else "N/A"
    vendor = html.escape(cve.get("vendor", "N/A"))
    product = html.escape(cve.get("product", "N/A"))
    url = html.escape(cve.get("url", ""))
    
    raw_desc = cve.get("description_pt") or cve.get("description", "")
    description = html.escape(raw_desc)
    
    # Clientes não precisam escapar individualmente se forem nomes seguros, mas é prudente
    clients = [html.escape(c) for c in cve.get("impacted_clients", [])]

    emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🔵", "LOW": "🟢", "LOG_ONLY": "⚪"}.get(risk_tag, "⚪")

    msg = f"<b>{emoji} {cve_id}</b> ({risk_tag})\n\n"
    msg += f"<b>Vendor:</b> {vendor.title()}\n"
    msg += f"<b>Product:</b> {product.title()}\n"
    msg += f"<b>CVSS:</b> {cvss_str}\n\n"
    if description:
        msg += f"{description[:500]}\n\n"

    if clients:
        msg += f"🏢 <b>Clientes impactados:</b> {', '.join(clients)}\n\n"

    if url:
        msg += f"<a href='{url}'>Ver no NVD</a>"

    return msg
