"""
cve/asset_matcher.py — Cruza CVEs com o inventário de ativos de cada cliente.
Correspondência case-insensitive entre vendor/product do CVE e valores do asset_map.
"""

from typing import Any
from core.logger import get_logger
from cve.aliases import get_aliases_for_vendor

logger = get_logger("cve.asset_matcher")


def match_cve_to_clients(
    cve: dict[str, Any],
    asset_map: dict[str, dict[str, Any]],
) -> list[str]:
    """
    Verifica se o vendor/product de uma CVE corresponde a ativos de clientes.
    Retorna lista de clientes impactados (pode ser vazia).
    
    O cruzamento é case-insensitive e tenta correspondência exata
    e parcial (substring) no vendor e product.
    """
    vendor = cve.get("vendor", "").strip().lower()
    product = cve.get("product", "").strip().lower()

    if not vendor and not product:
        logger.debug("CVE %s sem vendor/product — sem match", cve.get("cve_id"))
        return []

    # Expande o vendor do NVD usando os Aliases
    vendor_aliases = get_aliases_for_vendor(vendor)

    matched_clients: set[str] = set()

    for key, data in asset_map.items():
        asset_vendor, _, asset_product = key.partition(":")
        clients = data.get("clients", [])
        product_aliases = data.get("aliases", [])

        # Verifica se o vendor do Excel cruza com algum alias (ou se não tem vendor no Excel)
        vendor_match = False
        if not asset_vendor:
            vendor_match = True
        else:
            for alias in vendor_aliases:
                if alias == asset_vendor or alias in asset_vendor or asset_vendor in alias:
                    vendor_match = True
                    break
        
        if not vendor_match:
            continue

        # Verifica se o produto da CVE (do NVD) bate com o produto do cliente OU seus aliases
        if product:
            # Lista compreensiva de todos os termos aceitáveis do produto do lado do cliente
            all_client_terms = [asset_product] + product_aliases
            
            product_match = False
            norm_product = product.replace("_", " ")
            for term in all_client_terms:
                norm_term = term.replace("_", " ")
                if norm_term and (norm_product == norm_term or norm_term in norm_product or norm_product in norm_term):
                    product_match = True
                    break
            
            if product_match:
                matched_clients.update(clients)

    result = sorted(matched_clients)
    if result:
        logger.info(
            "CVE %s — match com %d cliente(s): %s",
            cve.get("cve_id"), len(result), ", ".join(result),
        )
    else:
        logger.debug("CVE %s — sem match de ativos", cve.get("cve_id"))

    return result
