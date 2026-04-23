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
    "emergency patch", "hotfix"
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

# REGIONAL MATRIZ (+50 pts)
REGIONAL_EXACT = ["br", "pf", "sus", "stf", "stj", "tse", "bcb", "cvm"]
REGIONAL_SUBSTRING = [
    "brasil", "brazil", "latam", "américa latina", "america latina",
    "américa do sul", "america do sul", "são paulo", "rio de janeiro",
    "brasília", "distrito federal", ".com.br", ".gov.br", ".edu.br", ".jus.br"
]


def score_article(article: dict[str, Any], asset_map: dict[str, dict[str, Any]]) -> tuple[int, list[str]]:
    """
    Avalia um artigo e retorna um score (int) e os motivos do score (list[str]).
    """
    score: int = 0
    reasons: list[str] = []

    text_to_search = f"{article.get('title', '')} {article.get('summary', '')}".lower().replace("_", " ")

    # --- REGIONAL (+50) ---
    matched_regional = []
    for word in REGIONAL_SUBSTRING:
        if word in text_to_search:
            matched_regional.append(word)
    for word in REGIONAL_EXACT:
        if re.search(r'\b' + re.escape(word) + r'\b', text_to_search):
            matched_regional.append(word.upper())
    if matched_regional:
        score += 50
        reasons.append(f"Regional ({matched_regional[0]})")

    # --- ATIVOS DO CLIENTE (+50) ---
    matched_my_assets = []
    for key, data in asset_map.items():
        vendor, _, product = key.partition(":")
        aliases = data.get("aliases", [])
        
        # Lista todos os termos possíveis que identificam este ativo
        all_terms = [vendor, product] + aliases
        
        found = False
        for term in all_terms:
            if term and len(term) > 2: # Evitar match de termos muito curtos
                # QC-01 Normalize spaces/underscores
                norm_term = term.lower().replace("_", " ")
                if re.search(r'\b' + re.escape(norm_term) + r'\b', text_to_search):
                    matched_my_assets.append(term)
                    found = True
                    break
        if found:
            break
            
    if matched_my_assets:
        score += 50
        reasons.append(f"Ativo Monitorado ({matched_my_assets[0]})")

    # --- CAT 1: IMPACTO CRÍTICO (+50) ---
    matched_cat1 = [w for w in CAT1_CRITICAL_IMPACT if w in text_to_search]
    if matched_cat1:
        score += 50
        reasons.append(f"Impacto Crítico ({matched_cat1[0]})")

    # --- CAT 2: MALWARE/THREATS (+40) ---
    matched_cat2 = [w for w in CAT2_MALWARE_THREATS if w in text_to_search]
    if matched_cat2:
        score += 40
        reasons.append(f"Malware/Ransomware ({matched_cat2[0]})")

    # --- CAT 3: BREACH (+35) — com word boundary para evitar 'breaching' ---
    matched_cat3 = [w for w in CAT3_BREACH_COMPROMISE if re.search(r'\b' + re.escape(w) + r'\b', text_to_search)]
    if matched_cat3:
        score += 35
        reasons.append(f"Data Breach ({matched_cat3[0]})")

    # --- CAT 4: TTPs/C2/PHISHING (+30) — termos curtos usam word boundary ---
    matched_cat4 = [w for w in CAT4_TTPS_CAMPAIGNS if w in text_to_search]
    for w in CAT4_EXACT:
        if re.search(r'\b' + re.escape(w) + r'\b', text_to_search):
            matched_cat4.append(w)
    if matched_cat4:
        score += 30
        reasons.append(f"TTP/Campanha ({matched_cat4[0]})")

    # --- CVSS DINÂMICO ---
    text_clean_cvss = re.sub(r'\bv\d+(\.\d+)?', '', text_to_search)
    cvss_matches = re.findall(r'(?:cvss|score)[^\d]{0,15}(\d+\.\d+)', text_clean_cvss)
    cvss_value_added = False
    for match_val in cvss_matches:
        try:
            val = float(match_val)
            if val >= 9.0:
                score += 30
                reasons.append(f"CVSS Crítico ({val})")
                cvss_value_added = True
            elif val >= 8.0:
                score += 20
                reasons.append(f"CVSS Alto ({val})")
                cvss_value_added = True
            elif val >= 7.0:
                score += 10
                reasons.append(f"CVSS Médio ({val})")
                cvss_value_added = True
            if cvss_value_added:
                break
        except ValueError:
            pass

    if not cvss_value_added and ("critical vulnerability" in text_to_search or "vulnerabilidade crítica" in text_to_search):
        score += 10
        reasons.append("Menção a Crítico no Texto")

    # --- CAT 5: GRUPOS (+20) ---
    matched_cat5 = [w for w in CAT5_GROUPS if w in text_to_search]
    for pfx in CAT5_GROUP_PREFIXES:
        if re.search(r'\b' + re.escape(pfx) + r'\d+', text_to_search):
            matched_cat5.append(pfx + "XX")
    if matched_cat5:
        score += 20
        reasons.append(f"Atores Famosos ({matched_cat5[0]})")

    # --- CAT 6: ESCALA (+20) ---
    matched_cat6 = [w for w in CAT6_SCALE if w in text_to_search]
    if matched_cat6:
        score += 20
        reasons.append(f"Grande Escala ({matched_cat6[0]})")

    # --- CAT 7: VENDORES CRÍTICOS (+15) ---
    # Não pontua se o vendor já foi contado como Ativo Monitorado (evita dupla contagem)
    matched_cat7 = [w for w in CAT7_CRITICAL_VENDORS if w in text_to_search and w not in [t.lower() for t in matched_my_assets]]
    if matched_cat7:
        score += 15
        reasons.append(f"Vendor Crítico ({matched_cat7[0]})")

    # --- CAT 8: SETORES BRASILEIROS (+25) — com word boundary ---
    matched_cat8 = [w for w in CAT8_SECTORS if re.search(r'\b' + re.escape(w) + r'\b', text_to_search)]
    if matched_cat8:
        score += 25
        reasons.append(f"Setor Nacional ({matched_cat8[0]})")


    # --- FONTE REGIONAL (Layer 4) (+30 pts) ---
    layer = int(article.get("layer", 0))
    if layer == 4:
        score += 30
        reasons.append("Radar Local (Fonte L4)")

    # --- CVE MENTION (+10 pts) ---
    if "cve-" in text_to_search:
        score += 10
        reasons.append("CVE Identificada")

    return score, reasons
