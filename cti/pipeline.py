"""
cti/pipeline.py — Orquestra o fluxo completo do pipeline CTI.
Ingestão → Deduplicação → Tradução → Formatação → Envio ao Teams.
"""

from typing import Any

from core.models import StandardCTINews
from core.notifications import global_dispatcher
from core import storage
from core.logger import get_logger
from core.data_manager import get_asset_map
from cti import rss_client, intelligence
from cti.scorer import score_article

logger = get_logger("cti.pipeline")


def _process_single_article(article: dict[str, Any], asset_map: dict[str, dict[str, Any]]) -> tuple[bool, str]:
    """Processa um único artigo: deduplica, traduz, formata, envia."""
    url = article.get("url", "")
    title = article.get("title", "?")[:40]

    # Deduplicação
    if storage.is_news_sent(url):
        logger.debug("Artigo já enviado: %s", url)
        return False, "já enviado"

    # Avaliação de Relevância (Scoring Inteligente)
    score, reasons = score_article(article, asset_map)
    if score < 50:
        logger.debug("Artigo ignorado (Score: %d) — %s", score, title)
        # Salvar como SKIPPED para evitar repetição nos logs
        storage.save_news(article, status="SKIPPED")
        return False, f"Score insuficiente ({score}): {', '.join(reasons)}"


    logger.info("Artigo APROVADO (Score: %d) — %s [Motivos: %s]", score, title, ", ".join(reasons))

    # Processamento ÚNICO de IA (Tradução + Resumo)
    intelligence.process_article_intelligence(article)

    # Construir Payload Neutro (DTO)
    news = StandardCTINews(
        title=article.get("title_pt") or article.get("title", ""),
        url=url,
        source=article.get("source", ""),
        layer=int(article.get("layer", 0)),
        summary=article.get("summary_pt") or article.get("summary", ""),
        date=article.get("date", "")
    )
    
    success = global_dispatcher.dispatch_cti(news)

    if success:
        storage.save_news(article)
        logger.info("Artigo enviado: %s", article.get("title", "?")[:60])
        return True, "enviado com sucesso"
    else:
        logger.error("Falha ao enviar artigo: %s", url)
        return False, "falha no envio"


def run() -> dict[str, int]:
    """
    Executa o pipeline CTI completo.
    Retorna contadores: {'total': N, 'sent': N, 'skipped': N, 'errors': N}
    """
    logger.info("═══ Pipeline CTI iniciado ═══")
    stats = {"total": 0, "sent": 0, "skipped": 0, "errors": 0}
    skipped_reasons = {}

    try:
        asset_map = get_asset_map()
        articles = rss_client.fetch_recent_articles()
        stats["total"] = len(articles)
        logger.info("RSS retornou %d artigos", len(articles))

        for article in articles:
            title = article.get("title", "?")[:40]
            try:
                success, reason = _process_single_article(article, asset_map)
                if success:
                    stats["sent"] += 1
                else:
                    stats["skipped"] += 1
                    skipped_reasons[title] = reason
            except Exception as exc:
                stats["errors"] += 1
                logger.error("Erro ao processar artigo '%s': %s", title, exc)
                skipped_reasons[title] = f"erro na execução: {exc}"

    except Exception as exc:
        logger.error("Erro fatal no pipeline CTI: %s", exc)

    if skipped_reasons:
        logger.info("Resumo dos artigos não enviados:")
        for title, rsn in skipped_reasons.items():
            logger.info("  - %s: %s", title, rsn)

    logger.info(
        "═══ Pipeline CTI finalizado — total=%d enviados=%d skip=%d erros=%d ═══",
        stats["total"], stats["sent"], stats["skipped"], stats["errors"],
    )
    return stats
