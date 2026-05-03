"""
cti/pipeline.py — Orquestra o fluxo completo do pipeline CTI com Injeção de Dependência.
"""
from typing import Any
from concurrent.futures import ThreadPoolExecutor, as_completed

import config

from core.models import StandardCTINews
from core.notifications import global_dispatcher
from core.notifications.base import BaseNotifier
from core import storage
from core.logger import get_logger
from core.data_manager import get_asset_map
from core.clients import groq_engine
from cti import rss_client
from cti.scorer import score_article

logger = get_logger("cti.pipeline")


from cti.scrapling_client import scrapling_client
from core.clients.scrapers import BaseScraper

def _process_single_article(
    article: dict[str, Any], 
    asset_map: dict[str, dict[str, Any]],
    notifier: BaseNotifier,
    db_module: Any = storage,
    scraper: BaseScraper = scrapling_client
) -> tuple[bool, str]:
    """Processa um único artigo: deduplica, traduz, formata, envia."""
    url = article.get("url", "")
    title = article.get("title", "?")[:40]

    # Deduplicação via interface de storage injetada
    if db_module.is_news_sent(url):
        logger.debug("Artigo já enviado: %s", url)
        return False, "já enviado"

    # Lock em memória para evitar processamento paralelo da mesma URL
    if not db_module.acquire_news_lock(url):
        logger.debug("Artigo já em processamento: %s", url)
        return False, "em processamento"

    try:
        # Avaliação de Relevância (Scoring Inteligente)
        score, reasons = score_article(article, asset_map)
        if score < 50:
            logger.debug("Artigo ignorado (Score: %d) — %s", score, title)
            db_module.save_news(article, status="SKIPPED")
            return False, f"Score insuficiente ({score}): {', '.join(reasons)}"

        logger.info("Artigo APROVADO (Score: %d) — %s [Motivos: %s]", score, title, ", ".join(reasons))

        # Deep Fetch via Scraper injetado
        if not article.get("full_content"):
            article["full_content"] = scraper.fetch_content(url)

        # Processamento ÚNICO de IA (Tradução + Resumo) via motor unificado
        groq_engine.process_news_intelligence(article)

        # Construir Payload Neutro (DTO)
        news = StandardCTINews(
            title=article.get("title_pt") or article.get("title", ""),
            url=url,
            source=article.get("source", ""),
            layer=int(article.get("layer", 0)),
            summary=article.get("summary_pt") or article.get("summary", ""),
            date=article.get("date", ""),
            iocs=article.get("iocs", "")
        )
        
        # Envio via notificador injetado
        success = notifier.send_cti_news(news)

        if success:
            db_module.save_news(article)
            logger.info("Artigo enviado: %s", article.get("title", "?")[:60])
            return True, "enviado com sucesso"
        else:
            logger.error("Falha ao enviar artigo: %s", url)
            return False, "falha no envio"
    finally:
        db_module.release_news_lock(url)


def run(
    notifier: BaseNotifier = global_dispatcher, 
    db_module: Any = storage,
    scraper: BaseScraper = scrapling_client
) -> dict[str, int]:
    """
    Executa o pipeline CTI completo com injeção de dependências.
    """
    logger.info("--- Pipeline CTI iniciado ---")
    stats = {"total": 0, "sent": 0, "skipped": 0, "errors": 0}
    skipped_reasons = {}

    try:
        asset_map = get_asset_map()
        articles = rss_client.fetch_recent_articles()
        stats["total"] = len(articles)
        logger.info("RSS retornou %d artigos", len(articles))

        # Otimização para VPS: Baixa concorrência (2 workers) para poupar RAM e CPU
        with ThreadPoolExecutor(max_workers=2) as executor:
            future_to_article = {
                executor.submit(_process_single_article, article, asset_map, notifier, db_module, scraper): article 
                for article in articles
            }
            
            for future in as_completed(future_to_article):
                article = future_to_article[future]
                title = article.get("title", "?")[:40]
                url = article.get("url", "N/A")
                try:
                    success, reason = future.result()
                    if success:
                        stats["sent"] += 1
                    else:
                        stats["skipped"] += 1
                        skipped_reasons[url] = {"title": title, "reason": reason}
                except Exception as exc:
                    stats["errors"] += 1
                    logger.error("Erro ao processar notícia '%s': %s", title, exc)
                    skipped_reasons[url] = {"title": title, "reason": f"erro na execução: {exc}"}

    except Exception as exc:
        logger.error("Erro fatal no pipeline CTI: %s", exc)

    if skipped_reasons:
        logger.info("Resumo das notícias ignoradas ou com erro:")
        for url, data in skipped_reasons.items():
            logger.info("  - [%s] %s: %s", url[:30] + "...", data["title"], data["reason"])

    # --- Rotina de Housekeeping (Faxina do Banco) ---
    try:
        cleaned_count = db_module.cleanup_old_data(days=90)
        if cleaned_count > 0:
            logger.info("Faxina concluída: %d registros antigos removidos do banco.", cleaned_count)
    except Exception as exc:
        logger.warning("Falha na rotina de housekeeping: %s", exc)

    logger.info(
        "--- Pipeline CTI finalizado — total=%d enviados=%d skip=%d erros=%d ---",
        stats["total"], stats["sent"], stats["skipped"], stats["errors"],
    )
    return stats
