"""
cve/pipeline.py — Orquestra o fluxo completo do pipeline CVE.
should_alert() é a ÚNICA função autorizada a decidir se uma CVE vira alerta.
"""

from typing import Any

from core import storage
from core.models import StandardCVEAlert
from core.notifications import global_dispatcher
from core.data_manager import get_asset_map, get_blacklist
from core.logger import get_logger
from cve import asset_matcher, nvd_client, risk_scorer, translator

logger = get_logger("cve.pipeline")


def should_alert(
    cve: dict[str, Any],
    asset_map: dict[str, dict[str, Any]],
    blacklist: list[dict[str, Any]],
) -> tuple[bool, str]:
    """
    Única função autorizada a decidir se uma CVE se torna alerta no Teams.
    
    Critérios (todos devem ser satisfeitos):
      1. CVE não foi enviada anteriormente (deduplicação via SQLite)
      2. CVE não está em processamento (lock em memória — bug fix #3)
      3. CVE corresponde a pelo menos um ativo de cliente
      4. risk_tag NÃO é LOG_ONLY (produtos blacklistados são descartados)

    Nota: CVEs sem match de ativos são descartadas antes do
    enriquecimento (EPSS/KEV) para economizar chamadas de API.
    """
    cve_id = cve.get("cve_id", "")

    # 1. Já enviada?
    if storage.is_cve_sent(cve_id):
        logger.debug("CVE %s — já enviada, ignorando", cve_id)
        return False, "já enviada"

    # 2. Em processamento? (race condition guard)
    if not storage.acquire_cve_lock(cve_id):
        logger.debug("CVE %s — já em processamento, ignorando", cve_id)
        return False, "já em processamento"

    try:
        # 3. Match com ativos de clientes (MOVE UP para economizar API do EPSS)
        clients = asset_matcher.match_cve_to_clients(cve, asset_map)
        cve["impacted_clients"] = clients

        # 4. Enriquecer com EPSS, CISA KEV, risk_tag
        # Só chamamos a API do EPSS se houver match de ativos ou se a CVE for potencialmente crítica
        # (Neste caso, só enriquecemos se houver match para poupar API conforme solicitado)
        if not clients:
            logger.debug("CVE %s — sem match de ativos", cve_id)
            return False, "sem match de ativos"

        risk_scorer.enrich_cve(cve, blacklist)
        risk_tag = cve.get("risk_tag", "LOW")

        # 5. Blacklisted?
        if risk_tag == "LOG_ONLY":
            logger.info("CVE %s — LOG_ONLY (blacklist) — não alerta", cve_id)
            return False, "produto na blacklist (LOG_ONLY)"

        # 6. Decisão final
        logger.info("CVE %s — %d cliente(s) impactado(s) [%s] → ALERTAR", cve_id, len(clients), risk_tag)
        return True, f"{len(clients)} cliente(s) impactado(s)"

    except Exception:
        # Em caso de erro, liberar o lock para retry
        storage.release_cve_lock(cve_id)
        raise


def _process_single_cve(
    cve: dict[str, Any],
    asset_map: dict[str, dict[str, Any]],
    blacklist: list[dict[str, Any]],
) -> tuple[bool, str]:
    """Processa uma única CVE: decide, traduz, formata, envia."""
    cve_id = cve.get("cve_id", "")

    try:
        alert_rule, reason = should_alert(cve, asset_map, blacklist)
        if not alert_rule:
            storage.release_cve_lock(cve_id)
            return False, reason

        # Traduzir
        translator.translate_cve(cve)

        # Construir Payload Neutro (DTO)
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
            raw_payload=cve
        )

        success = global_dispatcher.dispatch_cve(alert)

        if success:
            storage.save_cve(cve)
            logger.info("CVE %s — alerta enviado com sucesso", cve_id)
            return True, "enviado com sucesso"
        else:
            logger.error("CVE %s — falha no envio", cve_id)
            return False, "falha no envio"

    except Exception as exc:
        logger.error("Erro ao processar CVE %s: %s", cve_id, exc)
        return False, f"erro inesperado: {str(exc)}"

    finally:
        storage.release_cve_lock(cve_id)


def run() -> dict[str, int]:
    """
    Executa o pipeline CVE completo:
      1. Ingestão via NVD
      2. Para cada CVE: should_alert → translate → format → send
    
    Retorna contadores: {'total': N, 'alerted': N, 'skipped': N, 'errors': N}
    """
    logger.info("═══ Pipeline CVE iniciado ═══")
    stats = {"total": 0, "alerted": 0, "skipped": 0, "errors": 0}
    skipped_reasons = {}

    try:
        # Carregar dados
        asset_map = get_asset_map()
        blacklist = get_blacklist()

        # Ingerir CVEs recentes
        cves = nvd_client.fetch_recent_cves()
        stats["total"] = len(cves)
        logger.info("NVD retornou %d CVEs", len(cves))

        for cve in cves:
            cve_id = cve.get("cve_id", "UNKNOWN")
            try:
                success, reason = _process_single_cve(cve, asset_map, blacklist)
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
        logger.info("Resumo das CVEs não enviadas:")
        for cid, rsn in skipped_reasons.items():
            logger.info("  - %s: %s", cid, rsn)

    logger.info(
        "═══ Pipeline CVE finalizado — total=%d alertas=%d skip=%d erros=%d ═══",
        stats["total"], stats["alerted"], stats["skipped"], stats["errors"],
    )
    return stats
