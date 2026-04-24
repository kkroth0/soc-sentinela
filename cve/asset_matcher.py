"""
cve/asset_matcher.py — Cruzamento performático entre CVEs e Inventário de Ativos.
Otimizado para evitar recompilações de Regex e imports em loops.
"""
import re
from typing import Any
from core.logger import get_logger
from cve.aliases import get_aliases_for_vendor

logger = get_logger("cve.asset_matcher")

# Cache de Regex para evitar recompilações idênticas entre CVEs
_REGEX_CACHE: dict[str, re.Pattern] = {}

def _get_pattern(term: str) -> re.Pattern:
    """Retorna um padrão de Regex pré-compilado com word boundaries."""
    if term not in _REGEX_CACHE:
        _REGEX_CACHE[term] = re.compile(r'\b' + re.escape(term) + r'\b', re.IGNORECASE)
    return _REGEX_CACHE[term]

def match_cve_to_clients(
    cve: dict[str, Any],
    asset_map: dict[str, dict[str, Any]],
) -> list[str]:
    """
    Verifica se o vendor/product de uma CVE corresponde a ativos de clientes.
    Otimizado para performance O(N*M) com minimização de overhead.
    """
    cve_id = cve.get("cve_id", "UNKNOWN")
    affected_items = cve.get("affected_products", [])
    
    if not affected_items:
        # Fallback para vendor/product principal se a lista estiver vazia
        v = cve.get("vendor")
        p = cve.get("product")
        if v or p:
            affected_items = [(v or "", p or "")]
        else:
            return []

    matched_clients: set[str] = set()
    
    # 1. Normalizar o asset_map para evitar processamento repetitivo
    normalized_assets = []
    for key, data in asset_map.items():
        v_asset, _, p_asset = key.partition(":")
        
        # Suporte polimórfico: aceita dict (novo) ou list (legado/testes)
        if isinstance(data, dict):
            aliases = [str(a).strip().lower().replace("_", " ") for a in data.get("aliases", [])]
            clients = data.get("clients", [])
        else:
            aliases = []
            clients = data if isinstance(data, list) else [str(data)]

        normalized_assets.append({
            "v": v_asset.strip().lower(),
            "p": p_asset.strip().lower().replace("_", " "),
            "aliases": aliases,
            "clients": clients
        })

    # 2. Cruzamento
    for v_nvd, p_nvd in affected_items:
        v_nvd_clean = str(v_nvd).strip().lower()
        p_nvd_clean = str(p_nvd).strip().lower().replace("_", " ")
        
        vendor_aliases = get_aliases_for_vendor(v_nvd_clean)

        for asset in normalized_assets:
            # Match de Vendor
            vendor_match = False
            if not asset["v"]:
                vendor_match = True
            else:
                for alias in vendor_aliases:
                    if not alias: continue
                    if alias == asset["v"] or \
                       _get_pattern(alias).search(asset["v"]) or \
                       _get_pattern(asset["v"]).search(alias):
                        vendor_match = True
                        break
            
            if not vendor_match:
                continue

            # Match de Produto
            if not asset["p"]: # Se produto no Excel for vazio, aceita qualquer produto do vendor
                matched_clients.update(asset["clients"])
                continue

            if p_nvd_clean:
                # Compara termo principal e aliases do produto no Excel
                for term in [asset["p"]] + asset["aliases"]:
                    if not term: continue
                    if term == p_nvd_clean or _get_pattern(term).search(p_nvd_clean):
                        matched_clients.update(asset["clients"])
                        break

    result = sorted(matched_clients)
    if result:
        logger.info("CVE %s — match com %d cliente(s): %s", cve_id, len(result), ", ".join(result))
    return result
