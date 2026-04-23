"""
cve/nvd_client.py — Ingestão de CVEs via NVD API 2.0.
Respeita rate limits (50 req/30s com key, 5 req/30s sem key).
"""

import json
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import config
from core.clients import http_client
from core.logger import get_logger

logger = get_logger("cve.nvd_client")

_RESULTS_PER_PAGE: int = 30
_RATE_LIMIT_DELAY: float = 0.6  # ~50 req/30s com key


def fetch_recent_cves(time_window_minutes: int | None = None) -> list[dict[str, Any]]:
    """
    Consulta NVD API por CVEs publicadas na janela de tempo configurada.
    Retorna lista de dicts com dados normalizados de cada CVE.
    """
    # Bug fix de Performance (Pense sobre):
    # Em vez de fixar 48 horas e baixar ~700 CVEs repetidas a cada 5 minutos usando pubStartDate,
    # usamos o lastModStartDate. Isso garante que não perderemos publicações retroativas/atrasadas
    # (pois o lastMod muda quando a CVE sobe no site) e permite que a janela seja enxuta!
    # Buffer de segurança de 120 minutos (2 horas) em vez de 48 horas.
    base_window = time_window_minutes or config.TIME_WINDOW_MINUTES
    window = max(base_window, 120)  # Garante pelo menos 2h de fallback
    
    now = datetime.now(timezone.utc)
    start = now - timedelta(minutes=window)

    params: dict[str, Any] = {
        "lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "lastModEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": _RESULTS_PER_PAGE,
        "startIndex": 0,
    }

    headers: dict[str, str] = {}
    if config.NVD_API_KEY:
        headers["apiKey"] = config.NVD_API_KEY

    all_cves: list[dict[str, Any]] = []
    total_results = None

    while True:
        logger.info(
            "Consultando NVD — startIndex=%d, janela=%d min",
            params["startIndex"], window,
        )
        response = http_client.get(config.NVD_BASE_URL, params=params, headers=headers)

        if response.status_code != 200:
            logger.error("NVD API retornou HTTP %d: %s", response.status_code, response.text[:200])
            break

        try:
            data = response.json()
            total_results = data.get("totalResults", 0)
            vulnerabilities = data.get("vulnerabilities", [])
        except json.JSONDecodeError as exc:
            # Bug fix: NVD API occasionally drops connection or returns malformed JSON
            # We must skip this page but extract totalResults so we don't break pagination
            logger.error(
                "Falha ao decodificar JSON NVD (startIndex=%d): %s. Snippet: %s",
                params["startIndex"], exc, response.text[-200:]
            )
            
            # Tenta extrair o totalResults via regex para manter a paginação funcionando
            match = re.search(r'"totalResults":\s*(\d+)', response.text)
            if match:
                total_results = int(match.group(1))
            elif total_results is None:
                # Se for a primeira página e falhar, assume 0 para abortar gracefully
                total_results = 0
                
            params["startIndex"] += _RESULTS_PER_PAGE
            time.sleep(_RATE_LIMIT_DELAY)
            
            if params["startIndex"] >= total_results:
                break
                
            continue

        for vuln_wrapper in vulnerabilities:
            cve_data = vuln_wrapper.get("cve", {})
            parsed = _parse_cve(cve_data)
            if parsed:
                all_cves.append(parsed)

        logger.info("NVD retornou %d/%d resultados", len(all_cves), total_results)

        # Condição de parada: se já buscamos todos os índices disponíveis
        if params["startIndex"] + _RESULTS_PER_PAGE >= total_results:
            break

        params["startIndex"] += _RESULTS_PER_PAGE
        time.sleep(_RATE_LIMIT_DELAY)

    return all_cves


def _parse_cve(cve_data: dict[str, Any]) -> dict[str, Any] | None:
    """Normaliza dados brutos da NVD em estrutura interna."""
    cve_id = cve_data.get("id", "")
    if not cve_id:
        return None

    # Extrair CVSS score e severity
    cvss_score, severity = _extract_cvss(cve_data)

    # Filtrar por score mínimo
    if cvss_score is not None and cvss_score < config.MIN_CVSS_SCORE:
        logger.debug("CVE %s ignorada — CVSS %.1f < MIN %.1f", cve_id, cvss_score, config.MIN_CVSS_SCORE)
        return None

    # Extrair vendor e product do CPE
    vendor, product = _extract_cpe_info(cve_data)

    # Descrição em inglês
    descriptions = cve_data.get("descriptions", [])
    description_en = ""
    for desc in descriptions:
        if desc.get("lang") == "en":
            description_en = desc.get("value", "")
            break

    return {
        "cve_id": cve_id,
        "cvss_score": cvss_score,
        "severity": severity,
        "vendor": vendor,
        "product": product,
        "description": description_en,
        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        "date": cve_data.get("published", ""),
        "epss_score": None,
        "in_cisa_kev": False,
        "risk_tag": None,
        "impacted_clients": [],
        "translated": False,
        "raw": cve_data,
    }


def _extract_cvss(cve_data: dict[str, Any]) -> tuple[float | None, str]:
    """Extrai score CVSS e severity dos metrics da NVD."""
    metrics = cve_data.get("metrics", {})

    # Tentar CVSS v3.1, depois v3.0, depois v2.0
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(key, [])
        if metric_list:
            cvss_data = metric_list[0].get("cvssData", {})
            score = cvss_data.get("baseScore")
            severity = cvss_data.get("baseSeverity", "UNKNOWN")
            if score is not None:
                return float(score), severity.upper()

    return None, "UNKNOWN"


def _extract_cpe_info(cve_data: dict[str, Any]) -> tuple[str, str]:
    """Extrai vendor e product do primeiro CPE Match encontrado."""
    configurations = cve_data.get("configurations", [])
    for cfg in configurations:
        for node in cfg.get("nodes", []):
            for match in node.get("cpeMatch", []):
                cpe_uri = match.get("criteria", "")
                parts = cpe_uri.split(":")
                if len(parts) >= 5:
                    vendor = parts[3].replace("_", " ")
                    product = parts[4].replace("_", " ")
                    return vendor, product
    return "", ""
