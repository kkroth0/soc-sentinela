"""
cve/pipeline.py — Orquestra o fluxo completo do pipeline CVE com Injeção de Dependência.
"""
from typing import Any

import config
from concurrent.futures import ThreadPoolExecutor, as_completed
from core import storage
from core.models import StandardCVEAlert
from core.notifications import global_dispatcher
from core.notifications.base import BaseNotifier
from core.data_manager import get_asset_map, get_blacklist
from core.logger import get_logger
from core.clients import groq_engine
from cve import asset_matcher, nvd_client, risk_scorer

logger = get_logger("cve.pipeline")


def should_alert(
    cve: dict[str, Any],
    normalized_assets: list[dict[str, Any]],
    blacklist: list[dict[str, Any]],
) -> tuple[bool, str]:
    """Decide se uma CVE se torna alerta."""
    cve_id = cve.get("cve_id", "")

    if storage.is_cve_sent(cve_id):
        return False, "já enviada"

    if not storage.acquire_cve_lock(cve_id):
        return False, "já em processamento"

    try:
        clients = asset_matcher.match_cve_to_clients(cve, normalized_assets)
        cve["impacted_clients"] = clients

        if not clients:
            logger.debug("CVE %s ignorada: %s/%s não encontrado nos ativos", cve_id, cve.get("vendor"), cve.get("product"))
            return False, "sem match de ativos"

        risk_scorer.enrich_cve(cve, blacklist)
        risk_tag = cve.get("risk_tag", "LOW")

        if risk_tag == "LOG_ONLY":
            return False, "produto na blacklist (LOG_ONLY)"

        return True, f"{len(clients)} cliente(s) impactado(s)"
    except Exception:
        raise


def _process_single_cve(
    cve: dict[str, Any],
    normalized_assets: list[dict[str, Any]],
    blacklist: list[dict[str, Any]],
    notifier: BaseNotifier
) -> tuple[bool, str]:
    """Processa uma única CVE e envia via notificador injetado."""
    cve_id = cve.get("cve_id", "")

    try:
        alert_rule, reason = should_alert(cve, normalized_assets, blacklist)
        if not alert_rule:
            return False, reason

        groq_engine.process_cve_intelligence(cve)

        alert = StandardCVEAlert(
            cve_id=cve_id,
            cvss_score=cve.get("cvss_score"),
            severity=cve.get("severity", "UNKNOWN"),
            risk_tag=cve.get("risk_tag", "LOW"),
            vendor=cve.get("vendor", ""),
            product=cve.get("product", ""),
            description=cve.get("description_pt") or cve.get("description", ""),
            url=cve.get("url", ""),
            date=cve.get("date", ""),
            impacted_clients=cve.get("impacted_clients", []),
            epss_score=cve.get("epss_score"),
            in_cisa_kev=cve.get("in_cisa_kev", False),
            has_exploit_db=cve.get("has_known_exploit", False),
            headline=cve.get("headline_pt", ""),
            raw_payload=cve
        )

        success = notifier.send_cve_alert(alert)

        if success:
            storage.save_cve(cve)
            return True, "enviado com sucesso"
        else:
            return False, "falha no envio"

    except Exception as exc:
        logger.error("Erro ao processar CVE %s: %s", cve_id, exc)
        return False, f"erro inesperado: {str(exc)}"
    finally:
        storage.release_cve_lock(cve_id)


def run(notifier: BaseNotifier = global_dispatcher) -> dict[str, int]:
    """Executa o pipeline CVE injetando o notificador."""
    logger.info("--- Pipeline CVE iniciado ---")
    stats = {"total": 0, "alerted": 0, "skipped": 0, "errors": 0}
    skipped_reasons = {}

    try:
        asset_map = get_asset_map()
        normalized_assets = asset_matcher.normalize_asset_map(asset_map)
        blacklist = get_blacklist()
        cves = nvd_client.fetch_recent_cves()
        stats["total"] = len(cves)
        logger.info("NVD retornou %d CVEs para análise", len(cves))

        with ThreadPoolExecutor(max_workers=3) as executor:
            future_to_cve = {
                executor.submit(_process_single_cve, cve, normalized_assets, blacklist, notifier): cve 
                for cve in cves
            }
            
            for future in as_completed(future_to_cve):
                cve = future_to_cve[future]
                cve_id = cve.get("cve_id", "UNKNOWN")
                try:
                    success, reason = future.result()
                    if success:
                        stats["alerted"] += 1
                    else:
                        stats["skipped"] += 1
                        skipped_reasons[cve_id] = reason
                except Exception as exc:
                    stats["errors"] += 1
                    logger.error("Erro inesperado na CVE %s: %s", cve_id, exc)
                    skipped_reasons[cve_id] = f"erro fatal: {str(exc)}"

    except Exception as exc:
        logger.error("Erro fatal no pipeline CVE: %s", exc)

    if skipped_reasons:
        logger.info("Resumo das CVEs ignoradas:")
        # Agrupar por motivo para não inundar o log se houver centenas
        from collections import Counter
        summary_reasons = Counter(skipped_reasons.values())
        for reason, count in summary_reasons.items():
            logger.info("  - %d CVE(s) ignorada(s) por: %s", count, reason)

    logger.info(
        "--- Pipeline CVE finalizado — total=%d alertas=%d skip=%d erros=%d ---",
        stats["total"], stats["alerted"], stats["skipped"], stats["errors"],
    )
    return stats
