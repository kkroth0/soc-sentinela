"""
cti/scrapling_client.py — Cliente robusto de Web Scraping usando Scrapling.
Focado em extrair o conteúdo principal de notícias e burlar anti-bots.
"""

import re
from typing import Any
from scrapling.fetchers import StealthyFetcher, Fetcher
from core.logger import get_logger

logger = get_logger("cti.scrapling")

def fetch_full_content(url: str) -> str:
    """
    Visita o site e extrai o conteúdo. 
    Tenta primeiro com Fetcher (rápido) e se falhar/bloquear tenta StealthyFetcher.
    """
    logger.info("Iniciando raspagem profunda para: %s", url)
    
    try:
        # Tenta primeiro com Fetcher (baseado em curl_cffi, muito rápido e bypassa TLS fingerprints)
        page = Fetcher.get(url, timeout=15)
        
        # Se for bloqueado (403, 401) ou der erro, tenta o StealthyFetcher (Playwright)
        if page.status != 200:
            logger.info("Fetcher falhou (Status %d). Tentando StealthyFetcher...", page.status)
            page = StealthyFetcher.fetch(url, headless=True, network_idle=True, timeout=30000)
        
        if page.status != 200:
            logger.warning("Falha total na raspagem (Status %d): %s", page.status, url)
            return ""

        # Seletores comuns de corpo de notícia
        content_selectors = [
            'article', 
            'main',
            '.post-content', 
            '.article-body', 
            '.entry-content', 
            '#main-content',
            'body'
        ]
        
        best_text = ""
        for selector in content_selectors:
            # Pega todo o texto recursivamente de dentro do seletor
            # Usando o seletor ::text do Scrapling/Scrapy que pega todos os nós de texto
            elements = page.css(f"{selector} *::text")
            if elements:
                texts = elements.getall()
                clean_text = " ".join(t.strip() for t in texts if t.strip())
                
                if len(clean_text) > len(best_text):
                    best_text = clean_text
                
                if len(best_text) > 1500: # Achamos o conteúdo principal
                    break
        
        # Se falhou, tenta o body inteiro sem o '*'
        if not best_text:
            elements = page.css("body::text")
            if elements:
                best_text = " ".join(t.strip() for t in elements.getall() if t.strip())
        
        # Limpeza final (remove excesso de espaços)
        best_text = re.sub(r'\s+', ' ', best_text).strip()
        
        logger.info("Raspagem concluída. Extraídos %d caracteres.", len(best_text))
        return best_text
        
    except Exception as exc:
        logger.error("Erro crítico ao raspar %s: %s", url, exc)
        return ""
