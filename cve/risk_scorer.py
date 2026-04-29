"""
cve/risk_scorer.py — EPSS, CISA KEV e cálculo de risk_tag com transparência.
"""
import re
import time
from typing import Any

import config
from core.clients import http_client
from core.logger import get_logger
from cve.aliases import get_aliases_for_vendor

logger = get_logger("cve.risk_scorer")

# Cache para evitar recompilação de Regex (Padrão de performance v7.0)
_REGEX_CACHE: dict[str, re.Pattern] = {}

def _get_pattern(term: str) -> re.Pattern:
    if term not in _REGEX_CACHE:
        _REGEX_CACHE[term] = re.compile(r'\b' + re.escape(term) + r'\b', re.IGNORECASE)
    return _REGEX_CACHE[term]

# Cache do CISA KEV
_kev_cache: dict[str, Any] = {"cve_ids": set(), "last_fetch": 0.0}

def _refresh_kev_cache() -> None:
    cache_ttl = config.CISA_KEV_CACHE_HOURS * 3600
    if time.time() - _kev_cache["last_fetch"] < cache_ttl and _kev_cache["cve_ids"]:
        return
    try:
        response = http_client.get(config.CISA_KEV_URL)
        if response.status_code == 200:
            data = response.json()
            vulns = data.get("vulnerabilities", [])
            _kev_cache["cve_ids"] = {v.get("cveID") for v in vulns if v.get("cveID")}
            _kev_cache["last_fetch"] = time.time()
    except Exception: pass

def _fetch_epss(cve_id: str) -> float | None:
    try:
        response = http_client.get(config.EPSS_BASE_URL, params={"cve": cve_id})
        if response.status_code == 200:
            data = response.json()
            epss_data = data.get("data", [])
            if epss_data:
                return float(epss_data[0].get("epss", 0))
    except Exception: pass
    return None

def calculate_risk(cve: dict[str, Any], blacklist: list[dict[str, Any]]) -> tuple[str, list[str]]:
    """Calcula risk_tag e retorna motivos (transparência)."""
    cve_id = cve.get("cve_id", "")
    cvss_score = cve.get("cvss_score")
    reasons = []
    
    # ── 1. BLACKLIST ──────────────────────────────────────────────────
    vendor = str(cve.get("vendor", "")).strip().lower()
    product = str(cve.get("product", "")).strip().lower().replace("_", " ")
    affected_items = cve.get("affected_products", [(vendor, product)])

    for v_cve, p_cve in affected_items:
        v_cve_clean = str(v_cve).strip().lower()
        p_cve_clean = str(p_cve).strip().lower().replace("_", " ")
        if not p_cve_clean: continue

        for bl_item in blacklist:
            bl_vendor = str(bl_item.get("vendor", "")).strip().lower()
            if bl_vendor:
                v_aliases = get_aliases_for_vendor(v_cve_clean)
                vendor_match = any(bl_vendor == a or _get_pattern(bl_vendor).search(a) or _get_pattern(a).search(bl_vendor) for a in v_aliases)
                if not vendor_match: continue
            
            bl_terms = [str(bl_item.get("product", "")).strip().lower()] + [str(a).strip().lower() for a in bl_item.get("aliases", [])]
            for term in bl_terms:
                if term and (p_cve_clean == term or _get_pattern(term).search(p_cve_clean)):
                    logger.info("CVE %s — Blacklist match (%s) → LOG_ONLY", cve_id, term)
                    return "LOG_ONLY", ["Produto na Blacklist (LOG_ONLY)"]

    # ── 2. CISA KEV ───────────────────────────────────────────────────
    _refresh_kev_cache()
    if cve_id in _kev_cache["cve_ids"]:
        reasons.append("Presente no CISA KEV (Exploração Ativa)")
        return "CRITICAL", reasons

    # ── 3. EPSS / CVSS ────────────────────────────────────────────────
    epss = _fetch_epss(cve_id)
    cve["epss_score"] = epss
    
    risk = "LOW"
    if cvss_score:
        if cvss_score >= 9.0: risk = "CRITICAL"
        elif cvss_score >= 7.0: risk = "HIGH"
        elif cvss_score >= 4.0: risk = "MEDIUM"
        reasons.append(f"CVSS Score: {cvss_score}")

    if epss and epss > 0.5:
        old_risk = risk
        bump_map = {"LOW": "MEDIUM", "MEDIUM": "HIGH", "HIGH": "CRITICAL", "CRITICAL": "CRITICAL"}
        risk = bump_map.get(risk, risk)
        reasons.append(f"EPSS elevado ({epss:.2f}) → Bump de severidade ({old_risk} para {risk})")

    return risk, reasons

def enrich_cve(cve: dict[str, Any], blacklist: list[dict[str, Any]]) -> dict[str, Any]:
    risk_tag, reasons = calculate_risk(cve, blacklist)
    cve["risk_tag"] = risk_tag
    cve["risk_reasons"] = reasons
    return cve
