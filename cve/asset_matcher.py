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

def normalize_asset_map(asset_map: dict[str, dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """
    Indexa os ativos por vendor para buscas ultra-rápidas.
    Retorna: { 'microsoft': [ {asset1}, {asset2} ], 'cisco': [...] }
    """
    vendor_index = {}
    for key, data in asset_map.items():
        v_asset, _, p_asset = key.partition(":")
        vendor_clean = v_asset.strip().lower()
        
        # Extração limpa
        aliases = [str(a).strip().lower().replace("_", " ") for a in data.get("aliases", [])]
        clients = data.get("clients", [])
        
        asset_info = {
            "v": vendor_clean,
            "p": p_asset.strip().lower().replace("_", " "),
            "aliases": aliases,
            "clients": clients
        }
        
        if vendor_clean not in vendor_index:
            vendor_index[vendor_clean] = []
        vendor_index[vendor_clean].append(asset_info)
        
    return vendor_index

def match_cve_to_clients(
    cve: dict[str, Any],
    vendor_index: dict[str, list[dict[str, Any]]],
) -> list[str]:
    """
    Verifica se o vendor/product de uma CVE corresponde a ativos de clientes.
    Otimizado para performance O(N) via Vendor Indexing.
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

    # Cruzamento otimizado
    for v_nvd, p_nvd in affected_items:
        v_nvd_clean = str(v_nvd).strip().lower()
        p_nvd_clean = str(p_nvd).strip().lower().replace("_", " ")
        
        # OBTEM TODOS OS ALIASES DO VENDOR QUE VEM DA NVD
        # Ex: Se a NVD diz 'Microsoft', pegamos ['microsoft', 'msft', 'microsoft corp']
        vendor_aliases = get_aliases_for_vendor(v_nvd_clean)

        # BUSCA NO ÍNDICE: Apenas os ativos que batem com esses vendors
        for alias in vendor_aliases:
            if not alias: continue
            
            # 1. Match exato no índice (O(1))
            assets_to_check = vendor_index.get(alias, [])
            
            # 2. Se não deu match exato, fazemos uma busca "fuzzy" mas limitada aos vendors conhecidos
            if not assets_to_check:
                # Loop apenas nas CHAVES do índice (vendors únicos), não em todos os ativos
                for v_indexed in vendor_index.keys():
                    if alias == v_indexed or \
                       _get_pattern(alias).search(v_indexed) or \
                       _get_pattern(v_indexed).search(alias):
                        assets_to_check.extend(vendor_index[v_indexed])

            if not assets_to_check:
                continue

            # Se chegamos aqui, temos ativos de um vendor que bateu. Verificamos os produtos.
            for asset in assets_to_check:
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
