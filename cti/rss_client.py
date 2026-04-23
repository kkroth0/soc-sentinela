"""
cti/rss_client.py — Ingestão de artigos de segurança via feeds RSS.
Feeds organizados em camadas temáticas.
"""

import time
from datetime import datetime, timedelta, timezone
from typing import Any

import config  # type: ignore
import requests
import re
import feedparser  # type: ignore
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.logger import get_logger  # type: ignore
from core.clients import http_client  # type: ignore

logger = get_logger("cti.rss_client")

# ─── Feeds por camada ─────────────────────────────────────────────────
RSS_FEEDS: list[dict[str, Any]] = [
    # Layer 1: Vendor Security Advisories
    {"url": "https://filestore.fortinet.com/fortiguard/rss/ir.xml", "source": "FortiGuard IR", "layer": 1},
    {"url": "https://filestore.fortinet.com/fortiguard/rss/outbreakalert.xml", "source": "FortiGuard Outbreak", "layer": 1},
    {"url": "https://feeds.feedburner.com/GoogleChromeReleases", "source": "Google Chrome Releases", "layer": 1},
    {"url": "https://about.gitlab.com/security-releases.xml", "source": "GitLab Security", "layer": 1},
    {"url": "https://blogs.cisco.com/security/feed", "source": "Cisco Security Blog", "layer": 1},
    {"url": "https://blog.cloudflare.com/tag/security/rss", "source": "Cloudflare Security", "layer": 1},
    {"url": "https://www.microsoft.com/security/blog/feed/", "source": "Microsoft Security Blog", "layer": 1},

    # Layer 2: Breaking News & Disclosure Velocity (Novos sugeridos)
    {"url": "https://arstechnica.com/security/feed", "source": "Ars Technica Security", "layer": 2},
    {"url": "https://www.bleepingcomputer.com/feed/", "source": "BleepingComputer", "layer": 2},
    {"url": "https://feeds.feedburner.com/TheHackersNews", "source": "TheHackerNews", "layer": 2},
    {"url": "https://feeds.feedburner.com/Securityweek", "source": "SecurityWeek", "layer": 2},
    {"url": "https://therecord.media/feed/", "source": "The Record", "layer": 2},
    {"url": "https://krebsonsecurity.com/feed/", "source": "Krebs on Security", "layer": 2},
    {"url": "https://www.cyberscoop.com/feed/", "source": "CyberScoop", "layer": 2},

    # Layer 3: Threat Intelligence / Research
    {"url": "https://isc.sans.edu/rssfeed_full.xml", "source": "SANS ISC", "layer": 3},
    {"url": "https://research.checkpoint.com/feed/", "source": "Check Point Research", "layer": 3},
    {"url": "https://www.sentinelone.com/labs/feed/", "source": "SentinelOne Labs", "layer": 3},
    {"url": "https://securelist.com/feed/", "source": "Securelist (Kaspersky)", "layer": 3},
    {"url": "https://blog.malwarebytes.com/feed/", "source": "Malwarebytes Labs", "layer": 3},
    {"url": "https://www.welivesecurity.com/en/rss/feed/", "source": "WeLiveSecurity", "layer": 3},
    {"url": "https://any.run/cybersecurity-blog/feed/", "source": "ANY.RUN Blog", "layer": 3},
    {"url": "https://www.elastic.co/security-labs/rss/feed.xml", "source": "Elastic Security", "layer": 3},
    {"url": "https://feeds.feedburner.com/threatintelligence/pvexyqv7v0v/", "source": "Mandiant Google", "layer": 3},

    # Layer 4: Regional Intelligence (LATAM/BR)
    {"url": "https://www.cisoadvisor.com.br/feed/", "source": "CISO Advisor", "layer": 4},
    {"url": "https://thehack.com.br/rss/", "source": "The Hack", "layer": 4},
    {"url": "https://www.convergenciadigital.com.br/feed/", "source": "Convergência Digital", "layer": 4}
]



def fetch_recent_articles(time_window_minutes: int | None = None) -> list[dict[str, Any]]:
    """
    Coleta artigos recentes de todos os feeds RSS configurados.
    Utiliza ThreadPoolExecutor para processar os feeds em paralelo,
    evitando a lentidão da execução sequencial original.
    """
    # Fixamos para as últimas 24 horas para garantir que nada passe
    # despercebido se o bot for desligado momentaneamente
    window = 24 * 60
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


def _parse_feed(
    feed_info: dict[str, Any],
    cutoff: datetime,
) -> list[dict[str, Any]]:
    """Baixa e parseia um feed RSS individual."""
    url = feed_info["url"]
    source = feed_info["source"]
    layer = feed_info["layer"]

    logger.debug("Processando feed: %s", source)
    
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
        resp = requests.get(
            url, 
            timeout=8, 
            headers=headers
        )
        resp.raise_for_status()
        raw_xml = resp.content
    except Exception as exc:
        logger.warning("Tempo limite ou falha ao baixar feed '%s': %s", source, exc)
        return []

    feed = feedparser.parse(raw_xml)

    if feed.bozo and not feed.entries:
        logger.warning("Feed '%s' retornou erro no parser: %s", source, feed.bozo_exception)
        return []

    articles: list[dict[str, Any]] = []
    for entry in feed.entries:
        article = _parse_entry(entry, source, layer, cutoff)
        if article:
            articles.append(article)

    if articles:
        logger.info("Feed '%s': %d artigos novos", source, len(articles))

    return articles


def _parse_entry(
    entry: Any,
    source: str,
    layer: int,
    cutoff: datetime,
) -> dict[str, Any] | None:
    """Normaliza uma entrada RSS em estrutura interna."""
    # Data de publicação
    published = entry.get("published_parsed") or entry.get("updated_parsed")
    if published:
        pub_date = datetime(published[0], published[1], published[2], published[3], published[4], published[5], tzinfo=timezone.utc)
        if pub_date < cutoff:
            return None
    else:
        pub_date = datetime.now(timezone.utc)

    title = entry.get("title", "").strip()
    link = entry.get("link", "").strip()
    summary = entry.get("summary", entry.get("description", "")).strip()

    if not title or not link:
        return None

    # Limpar HTML do summary
    if "<" in summary:
        summary = re.sub(r"<[^>]+>", "", summary).strip()

    # Fallback Ativo: Se o Feed vier oco (Sem summary), raspa o site original!
    if not summary:
        try:
            logger.debug("RSS Oco detectado em %s. Raspando site...", source)
            resp = http_client.get(link, timeout=4)
            if resp.status_code == 200:
                html_doc = resp.text
                
                # Tenta pegar a tag og:description do Facebook ou a meta description nativa
                match = re.search(r'<meta[^>]*?(?:name|property)=["\'](?:og:description|description)["\'][^>]*?content=["\']([^"\']+)["\']', html_doc, re.IGNORECASE)
                if match:
                    summary = match.group(1).strip()
                    logger.debug("Resumo raspado com sucesso via Fallback Crawler!")
                else:
                    # Alternativa bizarra: Pega o primeiro parágrafo longo do HTML
                    p_match = re.search(r'<p[^>]*>([^<]{100,500})</p>', html_doc, re.IGNORECASE)
                    if p_match:
                        summary = p_match.group(1).strip()
        except Exception as fallback_exc:
            logger.debug("Scraper de fallback falhou p/ %s: %s", source, fallback_exc)

    return {
        "title": title,
        "url": link,
        "summary": str(summary)[:500],  # type: ignore
        "source": source,
        "layer": layer,
        "date": pub_date.isoformat(),
        "translated": False,
    }
