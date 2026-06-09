"""
cti/scorer.py — Motor de relevância para notícias CTI.
Sistema funcional com regras em dicionário e score normalizado (0-100).
"""
import re
import json
import os
from typing import Any

import config
from core.logger import get_logger

logger = get_logger("cti.scorer")

# ─── Pesos estruturais (não vêm do JSON de categorias) ───────────────
# O JSON `cti_categories.json` é a ÚNICA fonte de verdade para os pesos das
# CATEGORIAS. Estas constantes valem para sinais estruturais independentes.
#
# Filosofia: sinais CONCRETOS (ativo monitorado, CVSS aferido) pesam mais que
# palavras-chave fuzzy do JSON. Um CVE realmente crítico deve superar um artigo
# que apenas menciona a palavra "crítico".
ASSET_MATCH_SCORE: int = 40      # Ativo monitorado citado (sinal mais forte)
CVE_MENTION_SCORE: int = 10      # Menção a um ID CVE
CVSS_CRITICAL_SCORE: int = 30    # CVSS >= 9.0 citado no texto
CVSS_HIGH_SCORE: int = 20        # CVSS >= 7.0 citado no texto

# Confiança da fonte (vinda do feed via `weight_boost`). Aplicada de forma
# limitada para que um feed prioritário não aprove ruído sozinho.
WEIGHT_BOOST_CAP: int = 20

# ─── Cache de Regex compiladas + pesos vindos do JSON ────────────────
_CATEGORIES: dict[str, Any] = {}
_COMPILED_REGEX: dict[str, re.Pattern] = {}
_CATEGORY_SCORES: dict[str, int] = {}
_ASSET_CACHE: dict[str, re.Pattern | None] = {}


def _initialize_scorer():
    """Carrega o JSON de categorias, lê os pesos e pré-compila as Regex."""
    global _CATEGORIES, _COMPILED_REGEX, _CATEGORY_SCORES

    path = config.CTI_CATEGORIES_PATH
    if not os.path.exists(path):
        logger.error("Arquivo de categorias CTI não encontrado: %s", path)
        return

    try:
        with open(path, "r", encoding="utf-8") as f:
            _CATEGORIES = json.load(f)

        # Pesos: fonte de verdade única é o campo `score` de cada categoria.
        _CATEGORY_SCORES = {
            cat_id: int(data.get("score", 0))
            for cat_id, data in _CATEGORIES.items()
        }

        for cat_id, data in _CATEGORIES.items():
            if cat_id == "REGIONAL":
                exact = data.get("exact_terms", [])
                substr = data.get("substring_terms", [])
                if exact:
                    _COMPILED_REGEX["REGIONAL_EXACT"] = re.compile(
                        r'\b(' + '|'.join(map(re.escape, exact)) + r')\b', re.IGNORECASE
                    )
                if substr:
                    _COMPILED_REGEX["REGIONAL_SUB"] = re.compile(
                        '|'.join(map(re.escape, substr)), re.IGNORECASE
                    )
            else:
                terms = data.get("terms", [])
                if not terms:
                    continue
                if data.get("exact_match"):
                    _COMPILED_REGEX[cat_id] = re.compile(
                        r'\b(' + '|'.join(map(re.escape, terms)) + r')\b', re.IGNORECASE
                    )
                else:
                    _COMPILED_REGEX[cat_id] = re.compile(
                        '|'.join(map(re.escape, terms)), re.IGNORECASE
                    )

        logger.debug("Scorer CTI inicializado com %d categorias.", len(_COMPILED_REGEX))
    except Exception as exc:
        logger.error("Falha ao inicializar Scorer CTI: %s", exc)


# Inicialização imediata
_initialize_scorer()


# Consome a versão do vetor CVSS (ex.: ":3.1", "v4.0") ANTES de capturar o base
# score 0-10 — caso contrário "CVSS:3.1 ... 9.0" capturaria 3.1 (a versão) e
# classificaria errado um crítico. Também aceita scores inteiros ("CVSS 10").
_CVSS_RE = re.compile(
    r'cvss\b[:\s]*'
    r'(?:v?[234](?:\.\d)?\b[:/\s]*)?'           # versão opcional do vetor
    r'[a-z\s:()/_-]*?'                           # conector curto ('base score of')
    r'(10(?:\.\d+)?|[0-9](?:\.\d+)?)\b',         # base score 0-10
    re.IGNORECASE,
)
# Fallback ancorado só em "score": exige decimal para evitar falsos positivos.
_CVSS_FALLBACK_RE = re.compile(r'score[^\d]{0,15}(\d{1,2}\.\d+)', re.IGNORECASE)
_CVE_RE = re.compile(r'\bcve-\d{4}-\d+\b', re.IGNORECASE)


# ─── Regras individuais (funções puras) ──────────────────────────────

def _rule_asset_match(text: str, asset_map: dict[str, dict[str, Any]], matched_assets: list[str]) -> list[tuple[int, str]]:
    """Verifica se o artigo menciona algum ativo monitorado dos clientes."""
    for key, data in asset_map.items():
        if key not in _ASSET_CACHE:
            vendor, _, product = key.partition(":")
            aliases = data.get("aliases", [])
            all_terms = [t for t in [vendor, product] + aliases if t]
            if not all_terms:
                _ASSET_CACHE[key] = None
                continue
            _ASSET_CACHE[key] = re.compile(
                r'\b(' + '|'.join(map(re.escape, all_terms)) + r')\b', re.IGNORECASE
            )

        pattern = _ASSET_CACHE[key]
        if pattern:
            m = pattern.search(text)
            if m:
                term = m.group(0)
                matched_assets.append(term.lower())
                return [(ASSET_MATCH_SCORE, f"Ativo Monitorado ({term})")]
    return []


def _rule_categories(text: str, matched_assets: list[str]) -> list[tuple[int, str]]:
    """Aplica pontuações das categorias dinâmicas do JSON."""
    matches = []
    for cat_id, pattern in _COMPILED_REGEX.items():
        if cat_id.startswith("REGIONAL"):
            continue

        m = pattern.search(text)
        if not m:
            continue

        term = m.group(0)

        # Não duplicar score se o vendor já deu match como ativo monitorado
        if cat_id == "CAT7_CRITICAL_VENDORS" and term.lower() in matched_assets:
            continue

        score = _CATEGORY_SCORES.get(cat_id, 0)
        label = _CATEGORIES.get(cat_id, {}).get("label", cat_id)
        matches.append((score, f"{label} ({term})"))

    return matches


def _rule_regional(text: str) -> list[tuple[int, str]]:
    """Verifica se o artigo tem relevância regional (BR/LATAM)."""
    exact_re = _COMPILED_REGEX.get("REGIONAL_EXACT")
    sub_re = _COMPILED_REGEX.get("REGIONAL_SUB")

    m_exact = exact_re.search(text) if exact_re else None
    m_sub = sub_re.search(text) if sub_re else None

    if m_exact or m_sub:
        term = m_exact.group(0) if m_exact else m_sub.group(0)
        score = _CATEGORY_SCORES.get("REGIONAL", 20)
        return [(score, f"Regional ({term.upper()})")]
    return []


def _rule_cve_mention(text: str) -> list[tuple[int, str]]:
    """Pontua se o artigo menciona um ID CVE."""
    if _CVE_RE.search(text):
        return [(CVE_MENTION_SCORE, "CVE Identificada")]
    return []


def _rule_cvss(text: str) -> list[tuple[int, str]]:
    """Pontua o MAIOR CVSS score citado explicitamente no texto."""
    cvss_matches = _CVSS_RE.findall(text) or _CVSS_FALLBACK_RE.findall(text)
    if not cvss_matches:
        return []

    # Considera o maior score citado: um artigo que menciona "7.5 ... 9.8" deve
    # ser classificado como Crítico, não Alto (a ordem no texto não importa).
    val = max(float(m) for m in cvss_matches)
    if val >= 9.0:
        return [(CVSS_CRITICAL_SCORE, f"CVSS Crítico ({val})")]
    if val >= 7.0:
        return [(CVSS_HIGH_SCORE, f"CVSS Alto ({val})")]
    return []


# ─── Função principal ────────────────────────────────────────────────

def score_article(article: dict[str, Any], asset_map: dict[str, dict[str, Any]]) -> tuple[int, list[str]]:
    """
    Avalia a relevância de um artigo CTI.
    Retorna (score_normalizado_0_100, lista_de_motivos).
    """
    raw_score = 0
    reasons: list[str] = []
    matched_assets: list[str] = []

    text = f"{article.get('title', '')} {article.get('summary', '')}".lower().replace("_", " ")

    # Executar todas as regras
    all_rules = [
        _rule_asset_match(text, asset_map, matched_assets),
        _rule_categories(text, matched_assets),
        _rule_regional(text),
        _rule_cve_mention(text),
        _rule_cvss(text),
    ]

    for results in all_rules:
        for pts, reason in results:
            raw_score += pts
            reasons.append(reason)

    # Confiança da fonte: feeds prioritários (ex.: FortiGuard, Mandiant) recebem
    # um bônus limitado — só conta se o artigo já tiver algum sinal de conteúdo,
    # evitando que o boost da fonte aprove um artigo irrelevante sozinho.
    boost = int(article.get("weight_boost", 0) or 0)
    if boost > 0 and raw_score > 0:
        applied = min(boost, WEIGHT_BOOST_CAP)
        raw_score += applied
        reasons.append(f"Fonte Prioritária (+{applied})")

    # Normalizar: score mínimo 0, máximo 100
    final_score = max(0, min(raw_score, 100))

    article["matched_assets"] = matched_assets
    return final_score, reasons


def reload_categories():
    """Recarrega as categorias do JSON sem reiniciar o bot."""
    _initialize_scorer()
