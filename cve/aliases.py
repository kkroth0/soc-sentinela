"""
cve/aliases.py — Mapeamento de Aliases para Vendors e Produtos.
Carrega mapeamentos de um arquivo JSON externo para economizar memória e facilitar manutenção.
"""
import json
import os
import config
from core.logger import get_logger

logger = get_logger("cve.aliases")

# Índice Invertido para Busca O(1)
# Mapeia cada termo individual para sua lista completa de aliases.
_INVERTED_ALIASES: dict[str, list[str]] = {}

def _initialize_index():
    """Lê o JSON de aliases e constrói o índice invertido em memória."""
    global _INVERTED_ALIASES
    
    path = config.VENDOR_ALIASES_PATH
    if not os.path.exists(path):
        logger.warning("Arquivo de aliases não encontrado em %s. Usando base vazia.", path)
        return

    try:
        with open(path, "r", encoding="utf-8") as f:
            vendor_data = json.load(f)
            
        new_index = {}
        for primary_key, names in vendor_data.items():
            # Normalizamos tudo para lower case e garantimos que a chave primária esteja na lista
            full_list = list(set([n.lower() for n in names] + [primary_key.lower()]))
            for name in full_list:
                new_index[name] = full_list
        
        _INVERTED_ALIASES = new_index
        logger.debug("Índice de aliases inicializado com %d termos.", len(_INVERTED_ALIASES))
        
    except Exception as exc:
        logger.error("Falha ao carregar aliases do JSON: %s", exc)

# Inicialização imediata na carga do módulo
_initialize_index()

def get_aliases_for_vendor(nvd_vendor: str) -> list[str]:
    """
    Retorna a lista de aliases para um vendor do NVD.
    A busca é instantânea (O(1)) e funciona com qualquer variação do nome.
    """
    if not nvd_vendor:
        return []
    
    vendor_clean = nvd_vendor.lower().strip().replace("_", " ")
    # Retorna a lista de aliases ou apenas o próprio nome se não houver mapeamento
    return _INVERTED_ALIASES.get(vendor_clean, [vendor_clean])

def reload_aliases():
    """Recarrega o índice de aliases (útil se o JSON for atualizado via nuvem)."""
    _initialize_index()
