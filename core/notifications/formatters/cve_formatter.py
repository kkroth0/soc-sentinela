"""
core/notifications/formatters/cve_formatter.py — Monta mensagens HTML de CVE para o Telegram.
"""
import html
from typing import Any
from core.logger import get_logger
from core.notifications.formatters import clamp_telegram

logger = get_logger("core.notifications.formatters.cve_formatter")

def build_cve_telegram_message(cve: Any) -> str:
    """Monta mensagem rica para o Telegram."""
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
    
    msg = f"🚨 <b>{headline}</b>\n"
    msg += f"━━━━━━━━━━━━━━\n"
    msg += f"🆔 <b>CVE:</b> {cve_id}\n"
    msg += f"📊 <b>Risco:</b> {sev_label} (CVSS {cvss})\n"
    msg += f"🏢 <b>Vendor:</b> {vendor}\n"
    msg += f"📦 <b>Produto:</b> {product}\n"
    
    if hasattr(cve, "cwes") and cve.cwes:
        msg += f"🏷️ <b>CWE:</b> {', '.join(html.escape(c) for c in cve.cwes)}\n"
    if hasattr(cve, "threats") and cve.threats:
        msg += f"👾 <b>Ameaças:</b> {', '.join(html.escape(t) for t in cve.threats)}\n"
        
    msg += "\n"
    
    paragraphs = [p.strip() for p in description.split("\n\n") if p.strip()]
    if len(paragraphs) >= 2:
        msg += f"📝 <b>RESUMO</b>\n{paragraphs[0]}\n\n"
        msg += f"🔍 <b>IMPACTO TÉCNICO</b>\n{paragraphs[1]}\n\n"
    else:
        msg += f"📝 <b>DESCRIÇÃO</b>\n{description}\n\n"
        
    if cve.impacted_clients:
        msg += f"🎯 <b>ATIVOS:</b> <code>{', '.join(cve.impacted_clients)}</code>\n\n"
        
    links: list[str] = []
    if url:
        links.append(f'🔗 <a href="{url}">Ver detalhes na NVD</a>')
    advisory_url = getattr(cve, "advisory_url", None)
    if advisory_url:
        links.append(f'🏛️ <a href="{html.escape(advisory_url)}">Advisory {vendor}</a>')
    if links:
        msg += "\n".join(links)

    return clamp_telegram(msg)
