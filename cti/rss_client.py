"""
cti/rss_client.py — Ingestão de artigos de segurança via feeds RSS.
Feeds organizados em camadas temáticas.
"""

from datetime import datetime, timedelta, timezone
from typing import Any

import re
import requests
import feedparser  # type: ignore
from concurrent.futures import ThreadPoolExecutor, as_completed

import config
from core.logger import get_logger  # type: ignore
from core.clients import http_client  # type: ignore

logger = get_logger("cti.rss_client")

# ─── Feeds por camada ─────────────────────────────────────────────────
import json
import os

RSS_FEEDS: list[dict[str, Any]] = []

def load_feeds() -> list[dict[str, Any]]:
    """Carrega a lista de feeds do arquivo JSON de configuração."""
    global RSS_FEEDS
    path = config.CTI_FEEDS_PATH
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                RSS_FEEDS = json.load(f)
            logger.info("Carregados %d feeds CTI de %s", len(RSS_FEEDS), path)
        except Exception as exc:
            logger.error("Erro ao carregar feeds CTI: %s. Usando lista vazia.", exc)
            RSS_FEEDS = []
    else:
        logger.warning("Arquivo de feeds CTI não encontrado: %s. Usando lista vazia.", path)
        RSS_FEEDS = []
    return RSS_FEEDS

# Inicialização imediata
load_feeds()



def fetch_recent_articles(time_window_minutes: int | None = None) -> list[dict[str, Any]]:
    """
    Coleta artigos recentes de todos os feeds RSS configurados.
    """
    window = time_window_minutes or config.NEWS_TIME_WINDOW_MINUTES
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=window)
    all_articles: list[dict[str, Any]] = []

    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_feed = {
            executor.submit(_parse_feed, feed_info, cutoff): feed_info  # type: ignore
            for feed_info in RSS_FEEDS
        }
        
        for future in as_completed(future_to_feed):
            feed_info = future_to_feed[future]
            try:
                articles = future.result()
                all_articles.extend(articles)
            except Exception as exc:
                logger.warning(
                    "Falha ao processar feed '%s': %s", feed_info["source"], exc
                )

    logger.info("Total de artigos coletados: %d (janela: %d min)", len(all_articles), window)
    return all_articles


def _fetch_via_scrapling(url: str) -> Any:
    """Baixa um feed via Scrapling (curl_cffi) para furar WAFs (ex.: Akamai/CISA).

    O fingerprint TLS de browser + Referer do Google passa por proteções que
    bloqueiam o `requests` puro. Retorna o corpo (bytes/str) ou None.
    """
    try:
        from scrapling.fetchers import Fetcher
        page = Fetcher.get(url, timeout=20, headers={
            "Referer": "https://www.google.com/",
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        })
        if page.status == 200:
            return page.body
        logger.debug("Bypass Scrapling retornou HTTP %s para %s", page.status, url)
    except Exception as exc:
        logger.debug("Bypass Scrapling falhou para %s: %s", url, exc)
    return None


def _parse_feed(
    feed_info: dict[str, Any],
    cutoff: datetime,
) -> list[dict[str, Any]]:
    """Baixa e parseia um feed RSS individual."""
    url = feed_info["url"]
    source = feed_info["source"]
    layer = feed_info["layer"]
    is_static = feed_info.get("is_static", False)

    logger.debug("Processando %s: %s", "site estático" if is_static else "feed", source)
    
    if is_static:
        return _parse_static_page(feed_info, cutoff)
    
    try:
        # Fetch explícito com timeout RÍGIDO (sem retries automáticos) 
        # para que o ThreadPool flua super rápido caso um server caia
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        }
        resp = http_client.get(
            url,
            timeout=15,
            headers=headers,
            use_retry=False
        )
        if resp.status_code == 200:
            raw_xml = resp.content
        elif resp.status_code in (403, 406, 429, 503):
            # Provável WAF (Akamai/Cloudflare). Tenta o bypass via Scrapling.
            logger.info("Feed '%s' HTTP %d — tentando bypass via Scrapling...", source, resp.status_code)
            raw_xml = _fetch_via_scrapling(url)
        else:
            resp.raise_for_status()
            raw_xml = resp.content
    except Exception as exc:
        logger.debug("Falha HTTP no feed '%s' (%s) — tentando bypass via Scrapling...", source, exc)
        raw_xml = _fetch_via_scrapling(url)

    if not raw_xml:
        logger.warning("Falha ao baixar feed '%s' (inclusive bypass).", source)
        return []

    feed = feedparser.parse(raw_xml)

    if feed.bozo and not feed.entries:
        logger.warning("Feed '%s' retornou erro no parser: %s", source, feed.bozo_exception)
        return []

    articles: list[dict[str, Any]] = []
    for entry in feed.entries:
        article = _parse_entry(entry, source, layer, cutoff, weight_boost=feed_info.get("weight_boost", 0))
        if article:
            articles.append(article)

    if articles:
        logger.info("Feed '%s': %d artigos novos", source, len(articles))

    return articles


def _parse_static_page(feed_info: dict[str, Any], cutoff: datetime) -> list[dict[str, Any]]:
    """Descoberta de links em sites estáticos (sem RSS)."""
    from scrapling import Fetcher
    
    url = feed_info["url"]
    source = feed_info["source"]
    layer = feed_info["layer"]
    weight_boost = feed_info.get("weight_boost", 0)
    
    articles: list[dict[str, Any]] = []
    
    try:
        fetcher = Fetcher()
        page = fetcher.get(url)
        # Seletores específicos para Securonix (identificados pelo browser agent)
        # Buscamos os cards de artigos
        links = page.find_all("a.noHover") or page.find_all("a.avia-button")
        
        # Filtramos links válidos e removemos duplicados
        seen_urls = set()
        for link_element in links:
            link = link_element.attrib.get("href")
            if not link or "/blog/" not in link or link == url or link in seen_urls:
                continue
            
            seen_urls.add(link)
            # Como não temos a data no card de forma fácil, usamos 'now' 
            # (o pipeline vai filtrar por duplicidade no banco depois)
            articles.append({
                "title": link_element.text or "Securonix Intelligence",
                "url": link,
                "summary": "Descoberta via monitoramento estático.",
                "source": source,
                "layer": layer,
                "weight_boost": weight_boost,
                "date": datetime.now(timezone.utc).isoformat()
            })
            # Pegamos apenas os 3 primeiros para não sobrecarregar
            if len(articles) >= 3: break
            
    except Exception as exc:
        logger.error("Erro na descoberta estática de '%s': %s", source, exc)

    return articles


def _parse_entry(
    entry: Any,
    source: str,
    layer: int,
    cutoff: datetime,
    weight_boost: int = 0,
) -> dict[str, Any] | None:
    """
    Normaliza uma entrada RSS. Atua como 'Sensor de Descoberta'.
    O conteúdo denso será extraído posteriormente pelo ScraplingClient.
    """
    import calendar
    import html

    # 1. Validação de Janela Temporal
    published = entry.get("published_parsed") or entry.get("updated_parsed")
    if published:
        pub_date = datetime.fromtimestamp(calendar.timegm(published), tz=timezone.utc)
        if pub_date < cutoff:
            return None
    else:
        pub_date = datetime.now(timezone.utc)

    # 2. Extração Básica (Identidade da Notícia)
    title = html.unescape(entry.get("title", "").strip())
    link = entry.get("link", "").strip()
    
    if not title or not link:
        return None

    # Limpeza de trackers na URL para evitar duplicidade no DB
    link = re.sub(r'[\?&](utm_[^&]+|feature=[^&]+|fbclid=[^&]+)', '', link).rstrip('?')

    # 3. Resumo Preliminar (Apenas como metadado ou fallback)
    summary = entry.get("summary", entry.get("description", ""))
    if summary:
        summary = re.sub(r"<[^>]+>", "", summary) # Limpeza HTML ultra-básica
        summary = html.unescape(summary).strip()
    
    return {
        "title": title,
        "url": link,
        "summary": summary[:1000] if summary else "",
        "source": source,
        "layer": layer,
        "weight_boost": weight_boost,
        "date": pub_date.isoformat(),
    }
