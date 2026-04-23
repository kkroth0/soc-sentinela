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
    Monta Adaptive Card para uma CVE.
    Retorna payload pronto para envio via teams_webhook.
    """
    cve_id = cve.get("cve_id", "N/A")
    risk_tag = cve.get("risk_tag", "UNKNOWN")
    cvss = cve.get("cvss_score")
    cvss_str = f"{cvss:.1f}" if cvss is not None else "N/A"
    epss = cve.get("epss_score")
    epss_str = f"{epss:.2%}" if epss is not None else "N/A"
    vendor = cve.get("vendor", "N/A")
    product = cve.get("product", "N/A")
    url = cve.get("url", "")
    in_kev = cve.get("in_cisa_kev", False)
    clients = cve.get("impacted_clients", [])
    description = cve.get("description_pt") or cve.get("description", "")

    color = _SEVERITY_COLORS.get(risk_tag, "default")

    # ── Header ────────────────────────────────────────────────────────
    header_items: list[dict] = [
        {
            "type": "TextBlock",
            "text": f"🛡️ {cve_id}",
            "weight": "Bolder",
            "size": "Large",
            "wrap": True,
        },
        {
            "type": "TextBlock",
            "text": risk_tag,
            "weight": "Bolder",
            "color": color,
            "spacing": "None",
        },
    ]

    # ── Facts ─────────────────────────────────────────────────────────
    facts: list[dict] = [
        {"title": "Vendor", "value": vendor.title()},
        {"title": "Product", "value": product.title()},
        {"title": "CVSS", "value": cvss_str},
        {"title": "EPSS", "value": epss_str},
        {"title": "CISA KEV", "value": "✅ Sim" if in_kev else "❌ Não"},
    ]

    body: list[dict] = [
        {
            "type": "ColumnSet",
            "columns": [
                {
                    "type": "Column",
                    "width": "stretch",
                    "items": header_items,
                }
            ],
        },
        {
            "type": "FactSet",
            "facts": facts,
        },
    ]

    # ── Description ───────────────────────────────────────────────────
    if description:
        body.append({
            "type": "TextBlock",
            "text": description[:500],
            "wrap": True,
            "spacing": "Medium",
        })

    # ── Impacted Clients ──────────────────────────────────────────────
    if clients:
        clients_text = ", ".join(clients)
        body.append({
            "type": "TextBlock",
            "text": f"🏢 **Clientes impactados:** {clients_text}",
            "wrap": True,
            "spacing": "Medium",
            "color": "attention",
        })

    # ── Action button ─────────────────────────────────────────────────
    actions: list[dict] = []
    if url:
        actions.append({
            "type": "Action.OpenUrl",
            "title": "Ver no NVD",
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
