"""
cve/risk_scorer.py — EPSS, CISA KEV, calcula risk_tag final.

Ordem sagrada de scoring (NÃO alterar):
  1. Blacklist  → LOG_ONLY imediato (prioridade absoluta)
  2. CISA KEV   → CRITICAL
  3. EPSS > 50% → Bump de severidade
  4. CVSS score → CRITICAL ≥ 9.0 | HIGH 7.0–8.9 | MEDIUM 4.0–6.9 | LOW < 4.0

Bug fix #1: Blacklist não pode ser bypassada por CVSS alto.
Bug fix #2: Ordem do scoring é sagrada.
"""

import time
from typing import Any

import config
from core.clients import http_client
from core.logger import get_logger
from cve.aliases import get_aliases_for_vendor

logger = get_logger("cve.risk_scorer")

# ─── Cache do CISA KEV ────────────────────────────────────────────────
_kev_cache: dict[str, Any] = {
    "cve_ids": set(),
    "last_fetch": 0.0,
}


def _refresh_kev_cache() -> None:
    """Atualiza cache do CISA KEV se expirado."""
    cache_ttl = config.CISA_KEV_CACHE_HOURS * 3600
    if time.time() - _kev_cache["last_fetch"] < cache_ttl and _kev_cache["cve_ids"]:
        return

    logger.info("Atualizando cache CISA KEV...")
    try:
        response = http_client.get(config.CISA_KEV_URL)
        if response.status_code == 200:
            data = response.json()
            vulns = data.get("vulnerabilities", [])
            _kev_cache["cve_ids"] = {v.get("cveID") for v in vulns if v.get("cveID")}
            _kev_cache["last_fetch"] = time.time()
            logger.info("CISA KEV cache atualizado: %d CVEs", len(_kev_cache["cve_ids"]))
        else:
            logger.error("Falha ao buscar CISA KEV: HTTP %d", response.status_code)
    except Exception as exc:
        logger.error("Exceção ao buscar CISA KEV: %s", exc)


def _is_in_kev(cve_id: str) -> bool:
    """Verifica se a CVE está no catálogo CISA KEV."""
    _refresh_kev_cache()
    return cve_id in _kev_cache["cve_ids"]


def _fetch_epss(cve_id: str) -> float | None:
    """Consulta EPSS API para obter probabilidade de exploração."""
    try:
        response = http_client.get(config.EPSS_BASE_URL, params={"cve": cve_id})
        if response.status_code == 200:
            data = response.json()
            epss_data = data.get("data", [])
            if epss_data:
                score = float(epss_data[0].get("epss", 0))
                logger.info("EPSS para %s: %.4f", cve_id, score)
                return score
        else:
            logger.warning("EPSS API retornou HTTP %d para %s", response.status_code, cve_id)
    except Exception as exc:
        logger.warning("Falha ao buscar EPSS para %s: %s", cve_id, exc)
    return None


def _cvss_to_risk(score: float | None) -> str:
    """Classifica risco baseado apenas no CVSS score."""
    if score is None:
        return "LOW"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def _bump_severity(current_risk: str) -> str:
    """Incrementa severidade em um nível (usado quando EPSS > 50%)."""
    bump_map = {
        "LOW": "MEDIUM",
        "MEDIUM": "HIGH",
        "HIGH": "CRITICAL",
        "CRITICAL": "CRITICAL",
    }
    return bump_map.get(current_risk, current_risk)


def calculate_risk(cve: dict[str, Any], blacklist: list[dict[str, Any]]) -> str:
    """
    Calcula o risk_tag final de uma CVE.
    
    ORDEM SAGRADA — NÃO ALTERAR:
      1. Blacklist  → retorna LOG_ONLY imediatamente
      2. CISA KEV   → retorna CRITICAL
      3. EPSS > 50% → bump de severidade
      4. CVSS score → classificação final
    
    Retorna: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'LOG_ONLY'
    Nunca decide envio — apenas classifica.
    """
    cve_id = cve.get("cve_id", "")
    product = cve.get("product", "").strip().lower()
    cvss_score = cve.get("cvss_score")

    vendor = cve.get("vendor", "").strip().lower()

    # ── 1. BLACKLIST — prioridade ABSOLUTA ────────────────────────────
    if product:
        for bl_item in blacklist:
            bl_vendor = bl_item.get("vendor", "")
            bl_product = bl_item.get("product", "")
            bl_aliases = bl_item.get("aliases", [])
            
            # Match vendor se especificado na blacklist
            vendor_match = True
            if bl_vendor:
                cve_vendor_aliases = get_aliases_for_vendor(vendor)
                if not any((bl_vendor == a or bl_vendor in a or a in bl_vendor) for a in cve_vendor_aliases):
                    vendor_match = False
                    
            if not vendor_match:
                continue
                
            # Match product ou aliases (QC-01: Normalize spaces/underscores)
            all_bl_terms = [bl_product] + bl_aliases
            product_match = False
            norm_product = product.replace("_", " ")
            for term in all_bl_terms:
                norm_term = term.replace("_", " ")
                if norm_term and (norm_product == norm_term or norm_term in norm_product or norm_product in norm_term):
                    product_match = True
                    break
                    
            if product_match:
                logger.info("CVE %s — produto '%s' na blacklist → LOG_ONLY", cve_id, product)
                return "LOG_ONLY"

    # ── 2. CISA KEV — exploração ativa confirmada ─────────────────────
    in_kev = _is_in_kev(cve_id)
    cve["in_cisa_kev"] = in_kev
    if in_kev:
        logger.info("CVE %s — presente no CISA KEV → CRITICAL", cve_id)
        return "CRITICAL"

    # ── 3. EPSS > 50% — bump de severidade ───────────────────────────
    epss = _fetch_epss(cve_id)
    cve["epss_score"] = epss

    risk = _cvss_to_risk(cvss_score)

    if epss is not None and epss > 0.5:
        old_risk = risk
        risk = _bump_severity(risk)
        logger.info("CVE %s — EPSS=%.2f > 50%% → bump %s → %s", cve_id, epss, old_risk, risk)

    # ── 4. Resultado final baseado em CVSS ────────────────────────────
    logger.info("CVE %s — risk_tag final: %s (CVSS=%.1f, EPSS=%s)",
                cve_id, risk, cvss_score or 0, epss)
    return risk


def enrich_cve(cve: dict[str, Any], blacklist: list[dict[str, Any]]) -> dict[str, Any]:
    """Enriquece CVE com EPSS, CISA KEV e risk_tag. Retorna o dict atualizado."""
    cve["risk_tag"] = calculate_risk(cve, blacklist)
    return cve
