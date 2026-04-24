"""
cti/scorer.py — Motor de inteligência para classificar a relevância de notícias CTI.
O foco regional é o Brasil e a América do Sul com categorias ultra granulares.
"""

import re
from typing import Any

# ==============================================================================
# DICIONÁRIOS DE CATEGORIAS E PONTUAÇÃO
# ==============================================================================

# 1. IMPACTO CRÍTICO (+50 pts)
CAT1_CRITICAL_IMPACT = [
    "zero-day", "0-day", "actively exploited", "exploitada ativamente",
    "exploração ativa", "under active attack", "supply chain attack",
    "emergency patch", "hotfix", "vulnerabilidade crítica", "exploit"
]

# 2. MALWARES E AMEAÇAS DIRETAS (+40 pts)
CAT2_MALWARE_THREATS = [
    "malware", "ransomware", "backdoor", "wiper", "trojan", "keylogger",
    "stealer", "infostealer", "double extortion"
]

# 3. VAZAMENTOS E COMPROMETIMENTO (+35 pts)
CAT3_BREACH_COMPROMISE = [
    "data breach", "vazamento de dados", "compromised", "breach", "vazamento"
]

# 4. TTPs E CAMPANHAS (+30 pts)
CAT4_TTPS_CAMPAIGNS = [
    "phishing", "command and control", "botnet",
    "credential harvesting", "credential theft"
]
# Termos curtos que precisam de word boundary para evitar falsos positivos
CAT4_EXACT = ["c2", "c&c", "campanha"]

# 5. GRUPOS DE AMEAÇA (+20 pts)
CAT5_GROUPS = [
    "lockbit", "ransomhub", "medusa", "blackcat", "alphv", "cl0p", "clop",
    "scattered spider", "lazarus", "volt typhoon", "salt typhoon", "sandworm",
    "revil", "fin7", "ta505"
]
CAT5_GROUP_PREFIXES = ["storm-", "unc"]

# 6. ESCALA E ALCANCE (+20 pts)
CAT6_SCALE = [
    "1000+", "mass exploitation", "milhares", "global scale", "mass attack"
]

# 7. VENDORES CRÍTICOS (+15 pts)
CAT7_CRITICAL_VENDORS = [
    "microsoft", "aws", "azure", "google cloud", "gcp",
    "vmware", "fortinet", "cisco", "palo alto"
]

# 8. SETORES CRÍTICOS BRASILEIROS (+25 pts)
CAT8_SECTORS = [
    "banco", "financeiro", "saúde", "hospital", "energia elétrica",
    "infraestrutura crítica", "utilities", "governo", "órgão público",
    "seguro", "seguradora", "fintech", "telecomunicações", "operadora"
]

# 9. RUÍDO E DESCARTE (-100 pts)
CAT_IGNORE_NOISE = [
    "carreira", "vaga", "emprego", "salário", "demanda", "profissão", "mercado de trabalho",
    "startup", "investimento", "rodada", "aporte", "fundo", "financiamento",
    "curiosidade", "tutorial", "como fazer", "dica", "webinar", "palestra", "curso"
]

# REGIONAL MATRIZ (+50 pts)
REGIONAL_EXACT = ["br", "pf", "sus", "stf", "stj", "tse", "bcb", "cvm"]
REGIONAL_SUBSTRING = [
    "brasil", "brazil", "latam", "américa latina", "america latina",
    "américa do sul", "america do sul", "são paulo", "rio de janeiro",
    "brasília", "distrito federal", ".com.br", ".gov.br", ".edu.br", ".jus.br"
]

# Pré-compilação para Performance (Match único para múltiplos termos)
_RE_REGIONAL_EXACT = re.compile(r'\b(' + '|'.join(map(re.escape, REGIONAL_EXACT)) + r')\b', re.IGNORECASE)
_RE_REGIONAL_SUB = re.compile('|'.join(map(re.escape, REGIONAL_SUBSTRING)), re.IGNORECASE)
_RE_CAT1 = re.compile('|'.join(map(re.escape, CAT1_CRITICAL_IMPACT)), re.IGNORECASE)
_RE_CAT2 = re.compile('|'.join(map(re.escape, CAT2_MALWARE_THREATS)), re.IGNORECASE)
_RE_CAT3 = re.compile(r'\b(' + '|'.join(map(re.escape, CAT3_BREACH_COMPROMISE)) + r')\b', re.IGNORECASE)
_RE_CAT4_SUB = re.compile('|'.join(map(re.escape, CAT4_TTPS_CAMPAIGNS)), re.IGNORECASE)
_RE_CAT4_EXACT = re.compile(r'\b(' + '|'.join(map(re.escape, CAT4_EXACT)) + r')\b', re.IGNORECASE)
_RE_CAT5_SUB = re.compile('|'.join(map(re.escape, CAT5_GROUPS)), re.IGNORECASE)
_RE_CAT5_PREFIX = re.compile('|'.join(map(re.escape, CAT5_GROUP_PREFIXES)), re.IGNORECASE)
_RE_CAT6 = re.compile('|'.join(map(re.escape, CAT6_SCALE)), re.IGNORECASE)
_RE_CAT7 = re.compile(r'\b(' + '|'.join(map(re.escape, CAT7_CRITICAL_VENDORS)) + r')\b', re.IGNORECASE)
_RE_CAT8 = re.compile('|'.join(map(re.escape, CAT8_SECTORS)), re.IGNORECASE)
_RE_NOISE = re.compile(r'\b(' + '|'.join(map(re.escape, CAT_IGNORE_NOISE)) + r')\b', re.IGNORECASE)

# Cache persistente para evitar recompilação de Regex de ativos por artigo
_ASSET_CACHE: dict[str, re.Pattern | None] = {}


def score_article(article: dict[str, Any], asset_map: dict[str, dict[str, Any]]) -> tuple[int, list[str]]:
    """
    Avalia um artigo e retorna um score (int) e os motivos do score (list[str]).
    Otimizado com Regex pré-compiladas.
    """
    score: int = 0
    reasons: list[str] = []

    text_to_search = f"{article.get('title', '')} {article.get('summary', '')}".lower().replace("_", " ")

    # --- REGIONAL (+50) ---
    m_reg_ex = _RE_REGIONAL_EXACT.search(text_to_search)
    m_reg_sub = _RE_REGIONAL_SUB.search(text_to_search)
    if m_reg_ex or m_reg_sub:
        score += 50
        term = m_reg_ex.group(0) if m_reg_ex else m_reg_sub.group(0)
        reasons.append(f"Regional ({term.upper()})")

    # --- ATIVOS DO CLIENTE (+50) ---
    # Otimização: Usa o cache de módulo para evitar recompilação de Regex
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
        if pattern:
            match = pattern.search(text_to_search)
            if match:
                term = match.group(0)
                score += 50
                reasons.append(f"Ativo Monitorado ({term})")
                matched_assets.append(term.lower())
                break

    # --- CATEGORIAS (CAT 1-8) ---
    checks = [
        (_RE_CAT1, 50, "Impacto Crítico"),
        (_RE_CAT2, 40, "Malware/Ransomware"),
        (_RE_CAT3, 35, "Data Breach"),
        (_RE_CAT4_SUB, 30, "TTPs/Campanha"),
        (_RE_CAT4_EXACT, 30, "TTPs/Campanha"),
        (_RE_CAT5_SUB, 25, "Grupo Cibercriminoso"),
        (_RE_CAT5_PREFIX, 25, "Grupo Cibercriminoso"),
        (_RE_CAT6, 20, "Escala/Alcance"),
        (_RE_CAT7, 15, "Vendor Crítico"),
        (_RE_CAT8, 25, "Setor Estratégico"),
    ]

    for pattern, pts, label in checks:
        m = pattern.search(text_to_search)
        if m:
            # Especial para Cat 7: não pontua se já deu match no ativo
            if label == "Vendor Crítico" and m.group(0).lower() in matched_assets:
                continue
            score += pts
            reasons.append(f"{label} ({m.group(0)})")

    # --- CVSS DINÂMICO ---
    # Tenta extrair menções a scores CVSS no texto
    cvss_matches = re.findall(r'(?:cvss|score)[^\d]{0,15}(\d+\.\d+)', text_to_search)
    for match_val in cvss_matches:
        val = float(match_val)
        if val >= 7.0:
            pts = 30 if val >= 9.0 else (20 if val >= 8.0 else 10)
            label = "Crítico" if val >= 9.0 else ("Alto" if val >= 8.0 else "Médio")
            score += pts
            reasons.append(f"CVSS {label} ({val})")
            break

    # --- FONTE REGIONAL (Layer 4) (+30 pts) ---
    if int(article.get("layer", 0)) == 4:
        score += 30
        reasons.append("Radar Local (Fonte L4)")

    # --- CVE MENTION (+10 pts) ---
    if "cve-" in text_to_search:
        score += 10
        reasons.append("CVE Identificada")

    # --- PENALIDADE DE RUÍDO (-100 pts) ---
    m_noise = _RE_NOISE.search(text_to_search)
    if m_noise:
        score -= 100
        reasons.append(f"Ruído Detectado ({m_noise.group(0)})")

    return score, reasons
