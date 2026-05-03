"""
cve/nvd_client.py — Ingestão de CVEs via NVD API 2.0.
Respeita rate limits (50 req/30s com key, 5 req/30s sem key).
"""

import json
import re
import time
import threading
from datetime import datetime, timedelta, timezone
from typing import Any

import config
from core import storage
from core.clients import http_client
from core.logger import get_logger

logger = get_logger("cve.nvd_client")

_RESULTS_PER_PAGE: int = 100
_MAX_RETRIES: int = 5
_RATE_LIMIT_DELAY: float = 2.0

_nvd_lock = threading.Lock()
_last_req_time = 0.0

def _rate_limit_wait():
    """Garante o respeito estrito ao limite de requisições da NVD."""
    global _last_req_time
    # 50 req/30s com key (0.6s), 5 req/30s sem key (6.0s)
    min_interval = 0.65 if config.NVD_API_KEY else 6.5
    with _nvd_lock:
        now = time.time()
        elapsed = now - _last_req_time
        if elapsed < min_interval:
            time.sleep(min_interval - elapsed)
        _last_req_time = time.time()

from concurrent.futures import ThreadPoolExecutor, as_completed

def fetch_recent_cves(time_window_minutes: int | None = None) -> list[dict[str, Any]]:
    """
    Busca CVEs modificadas recentemente na NVD 2.0 usando download paralelo.
    """
    all_cves = []
    now = datetime.now(timezone.utc)
    
    # Define a janela de busca: Sempre pelo menos 24 horas
    window_min = max(config.TIME_WINDOW_MINUTES, 24 * 60)
    start = now - timedelta(minutes=window_min)

    logger.info("Coleta NVD iniciada (Janela 24h): %s", start.isoformat())

    base_params: dict[str, Any] = {
        "lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "lastModEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": _RESULTS_PER_PAGE,
    }
    headers = {"apiKey": config.NVD_API_KEY} if config.NVD_API_KEY else {}


    # 1. Sondagem inicial para obter o total de resultados
    try:
        probe_params = base_params.copy()
        probe_params["resultsPerPage"] = 1 # Mínimo possível para ser rápido
        response = http_client.get(config.NVD_BASE_URL, params=probe_params, headers=headers)
        if response.status_code != 200:
            logger.error("NVD Probe Error HTTP %d", response.status_code)
            return []
        
        total_results = response.json().get("totalResults", 0)
        if total_results == 0:
            logger.info("NVD: Nenhuma vulnerabilidade encontrada na janela.")
            return []
            
        total_pages = (total_results // _RESULTS_PER_PAGE) + 1
        logger.info("NVD: %d vulnerabilidades detectadas. Baixando %d páginas em paralelo com controle de banda...", total_results, total_pages)

    except Exception as exc:
        logger.error("Falha na sondagem inicial NVD: %s", exc)
        return []

    # 2. Download paralelo das páginas
    def fetch_page(page_num: int) -> list[dict[str, Any]]:
        start_index = page_num * _RESULTS_PER_PAGE
        params = base_params.copy()
        params["startIndex"] = start_index
        
        # Retry loop robusto para evitar perda de dados
        for attempt in range(1, _MAX_RETRIES + 1):
            try:
                # Retries subsequentes ganham um backoff extra
                if attempt > 1:
                    time.sleep(attempt * 2.0)

                _rate_limit_wait()
                resp = http_client.get(config.NVD_BASE_URL, params=params, headers=headers)
                if resp.status_code == 200:
                    if attempt > 1:
                        logger.info("NVD: Página %d recuperada com sucesso na tentativa %d.", page_num + 1, attempt)
                    data = resp.json()
                    vulnerabilities = data.get("vulnerabilities", [])
                    page_results = []
                    for v in vulnerabilities:
                        parsed = _parse_cve(v.get("cve", {}))
                        if parsed: page_results.append(parsed)
                    return page_results
                
                logger.warning("NVD: Falha na página %d (Tentativa %d/%d - HTTP %d)", 
                               page_num + 1, attempt, _MAX_RETRIES, resp.status_code)
            except Exception as e:
                logger.error("NVD: Erro na página %d (Tentativa %d/%d): %s", 
                             page_num + 1, attempt, _MAX_RETRIES, e)
        
        return []

    # Executa com 10 workers para maximizar o download. O _rate_limit_wait impede o banimento.
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(fetch_page, p) for p in range(total_pages)]
        completed = 0
        for future in as_completed(futures):
            all_cves.extend(future.result())
            completed += 1
            if completed % 10 == 0 or completed == total_pages:
                logger.info("NVD: Progresso do download: %d/%d páginas concluídas...", completed, total_pages)

    # Atualiza o estado de sucesso
    storage.set_state("nvd_last_success", now.isoformat())
    
    logger.info("NVD: Coleta paralela concluída. %d itens prontos para análise.", len(all_cves))
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

    # Filtrar por idade de publicação real (evitar alertas falsos de CVEs de 2010 que foram modificadas hoje)
    published_str = cve_data.get("published", "")
    if published_str:
        try:
            pub_date = datetime.fromisoformat(published_str.replace("Z", "+00:00"))
            if pub_date.tzinfo is None:
                pub_date = pub_date.replace(tzinfo=timezone.utc)
            
            age_days = (datetime.now(timezone.utc) - pub_date).days
            if age_days > config.MAX_CVE_AGE_DAYS:
                logger.debug("CVE %s ignorada — Publicação original muito antiga (%d dias atrás).", cve_id, age_days)
                return None
        except Exception as exc:
            logger.debug("Falha ao analisar data de publicação da CVE %s: %s", cve_id, exc)


    # Extrair TODOS os pares vendor/produto afetados
    affected_items = _extract_all_cpe_matches(cve_data)
    
    # Para compatibilidade, pegamos o primeiro para os campos 'vendor' e 'product'
    primary_vendor = affected_items[0][0] if affected_items else ""
    primary_product = affected_items[0][1] if affected_items else ""

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
        "vendor": primary_vendor,
        "product": primary_product,
        "affected_products": affected_items, # Nova lista completa
        "description": description_en,
        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        "date": cve_data.get("published", ""),
        "epss_score": None,
        "in_cisa_kev": False,
        "has_known_exploit": any(
            "exploit-db.com" in ref.get("url", "").lower() or 
            "Exploit" in ref.get("tags", []) 
            for ref in cve_data.get("references", [])
        ),
        "risk_tag": None,
        "impacted_clients": [],
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


def _extract_all_cpe_matches(cve_data: dict[str, Any]) -> list[tuple[str, str]]:
    """Extrai TODOS os pares vendor e produto de forma recursiva."""
    affected: set[tuple[str, str]] = set()
    configurations = cve_data.get("configurations", [])
    
    def _walk_nodes(nodes: list[dict[str, Any]]) -> None:
        for node in nodes:
            # 1. Extrair CPEs deste nó
            for match in node.get("cpeMatch", []):
                cpe_uri = match.get("criteria", "")
                parts = cpe_uri.split(":")
                if len(parts) >= 5:
                    # Normaliza: 'microsoft' e 'exchange_server' -> 'microsoft', 'exchange server'
                    vendor = parts[3].replace("_", " ").strip().lower()
                    product = parts[4].replace("_", " ").strip().lower()
                    affected.add((vendor, product))
            
            # 2. Recursão para nós filhos (NVD 2.0 nesting)
            children = node.get("children")
            if children:
                _walk_nodes(children)

    for cfg in configurations:
        _walk_nodes(cfg.get("nodes", []))
                    
    return list(affected)
