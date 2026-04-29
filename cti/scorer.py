"""
cti/scorer.py — Motor de inteligência para classificar a relevância de notícias CTI.
Carrega categorias e pesos de um JSON externo para máxima flexibilidade.
"""
import re
import json
import os
from typing import Any
import config
from core.logger import get_logger

logger = get_logger("cti.scorer")

# --- Estruturas de Cache em Memória ---
_CATEGORIES: dict[str, Any] = {}
_COMPILED_REGEX: dict[str, re.Pattern] = {}
_ASSET_CACHE: dict[str, re.Pattern | None] = {}

def _initialize_scorer():
    """Carrega o JSON de categorias e pré-compila as Regex."""
    global _CATEGORIES, _COMPILED_REGEX
    
    path = config.CTI_CATEGORIES_PATH
    if not os.path.exists(path):
        logger.error("Arquivo de categorias CTI não encontrado: %s", path)
        return

    try:
        with open(path, "r", encoding="utf-8") as f:
            _CATEGORIES = json.load(f)
        
        # Compila regex para cada categoria
        for cat_id, data in _CATEGORIES.items():
            if cat_id == "REGIONAL":
                _COMPILED_REGEX["REGIONAL_EXACT"] = re.compile(
                    r'\b(' + '|'.join(map(re.escape, data.get("exact_terms", []))) + r')\b', re.IGNORECASE
                )
                _COMPILED_REGEX["REGIONAL_SUB"] = re.compile(
                    '|'.join(map(re.escape, data.get("substring_terms", []))), re.IGNORECASE
                )
            else:
                terms = data.get("terms", [])
                if not terms: continue
                
                if data.get("exact_match"):
                    _COMPILED_REGEX[cat_id] = re.compile(
                        r'\b(' + '|'.join(map(re.escape, terms)) + r')\b', re.IGNORECASE
                    )
                else:
                    _COMPILED_REGEX[cat_id] = re.compile(
                        '|'.join(map(re.escape, terms)), re.IGNORECASE
                    )
        
        logger.debug("Motor de Scoring CTI inicializado com %d categorias.", len(_COMPILED_REGEX))
    except Exception as exc:
        logger.error("Falha ao inicializar Scorer CTI: %s", exc)

# Inicialização imediata
_initialize_scorer()

def score_article(article: dict[str, Any], asset_map: dict[str, dict[str, Any]]) -> tuple[int, list[str]]:
    """Avalia um artigo e retorna um score (int) e os motivos."""
    score: int = 0
    reasons: list[str] = []
    text_to_search = f"{article.get('title', '')} {article.get('summary', '')}".lower().replace("_", " ")

    # 1. REGIONAL (+50)
    reg_data = _CATEGORIES.get("REGIONAL", {})
    m_reg_ex = _COMPILED_REGEX.get("REGIONAL_EXACT", re.compile("")).search(text_to_search)
    m_reg_sub = _COMPILED_REGEX.get("REGIONAL_SUB", re.compile("")).search(text_to_search)
    if m_reg_ex or m_reg_sub:
        score += reg_data.get("score", 50)
        term = m_reg_ex.group(0) if m_reg_ex else (m_reg_sub.group(0) if m_reg_sub else "Local")
        reasons.append(f"{reg_data.get('label', 'Regional')} ({term.upper()})")

    # 2. ATIVOS DO CLIENTE (+50)
    matched_assets: list[str] = []
    for key, data in asset_map.items():
        if key not in _ASSET_CACHE:
            vendor, _, product = key.partition(":")
            aliases = data.get("aliases", [])
            all_terms = [t for t in [vendor, product] + aliases if t]
            if not all_terms:
                _ASSET_CACHE[key] = None
                continue
            _ASSET_CACHE[key] = re.compile(r'\b(' + '|'.join(map(re.escape, all_terms)) + r')\b', re.IGNORECASE)
        
        pattern = _ASSET_CACHE[key]
        if pattern and pattern.search(text_to_search):
            match_term = pattern.search(text_to_search).group(0)
            score += 50
            reasons.append(f"Ativo Monitorado ({match_term})")
            matched_assets.append(match_term.lower())
            break

    # 3. CATEGORIAS DINÂMICAS (CAT 1-8 e NOISE)
    for cat_id, pattern in _COMPILED_REGEX.items():
        if cat_id.startswith("REGIONAL"): continue
        
        m = pattern.search(text_to_search)
        if m:
            cat_data = _CATEGORIES.get(cat_id, {})
            # Especial para Cat 7 (Vendors Críticos): não duplica se já deu match no ativo
            if cat_id == "CAT7_CRITICAL_VENDORS" and m.group(0).lower() in matched_assets:
                continue
                
            score += cat_data.get("score", 0)
            reasons.append(f"{cat_data.get('label', cat_id)} ({m.group(0)})")

    # 4. CVSS DINÂMICO
    cvss_matches = re.findall(r'(?:cvss|score)[^\d]{0,15}(\d+\.\d+)', text_to_search)
    for match_val in cvss_matches:
        val = float(match_val)
        if val >= 7.0:
            pts = 30 if val >= 9.0 else (20 if val >= 8.0 else 10)
            label = "Crítico" if val >= 9.0 else ("Alto" if val >= 8.0 else "Médio")
            score += pts
            reasons.append(f"CVSS {label} ({val})")
            break

    # 5. EXTRAS (Layer 4 e CVE Mention)
    if int(article.get("layer", 0)) == 4:
        score += 30
        reasons.append("Radar Local (Fonte L4)")

    if "cve-" in text_to_search:
        score += 10
        reasons.append("CVE Identificada")

    return score, reasons

def reload_categories():
    """Recarrega as categorias do JSON sem reiniciar o bot."""
    _initialize_scorer()
