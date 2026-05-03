"""
cti/scrapling_client.py — Cliente robusto de Web Scraping usando Scrapling.
Focado em extrair o conteúdo principal de notícias e burlar anti-bots.
"""

import re
from typing import Any
from scrapling.fetchers import StealthyFetcher, Fetcher
from core.logger import get_logger

from core.clients.scrapers import BaseScraper
from core.logger import get_logger

logger = get_logger("cti.scrapling")

class ScraplingClient(BaseScraper):
    def __init__(self):
        # Aqui poderíamos inicializar um pool se necessário
        pass

    def fetch_content(self, url: str) -> str:
        """
        Visita o site e extrai o conteúdo principal. 
        Tenta primeiro com Fetcher (rápido) e se falhar/bloquear tenta StealthyFetcher.
        """
        logger.info("Iniciando raspagem profunda para: %s", url)
        
        # Cabeçalhos para aumentar a credibilidade
        headers = {
            "Referer": "https://www.google.com/",
            "Accept-Language": "en-US,en;q=0.9",
        }
        
        try:
            # Tenta primeiro com Fetcher (baseado em curl_cffi, muito rápido)
            page = Fetcher.get(url, timeout=15, headers=headers)
            
            # Se for bloqueado ou der erro, tenta o StealthyFetcher (Playwright)
            if page.status != 200:
                logger.info("Fetcher falhou (Status %d). Tentando StealthyFetcher...", page.status)
                page = StealthyFetcher.fetch(url, headless=True, network_idle=True, timeout=30000)
            
            if page.status != 200:
                logger.warning("Falha total na raspagem (Status %d): %s", page.status, url)
                return ""

            # PODER MÁXIMO: find_all busca tudo de uma vez com lógica interna otimizada
            # Procuramos por tags de artigo ou blocos de conteúdo conhecidos
            content_blocks = page.find_all(
                tags=["article", "main", "section"],
                classes=["post-content", "article-body", "entry-content", "td-post-content", "article-content"]
            )
            
            best_text = ""
            if content_blocks:
                # Se achamos blocos específicos, processamos o maior deles
                for block in content_blocks:
                    texts = block.css("*::text").getall()
                    clean_lines = [t.strip() for t in texts if t.strip() and "{" not in t and "function(" not in t]
                    clean_text = " ".join(clean_lines)
                    if len(clean_text) > len(best_text):
                        best_text = clean_text
            
            # Fallback: se não achou blocos específicos, pega o body inteiro (limpo)
            if not best_text or len(best_text) < 500:
                texts = page.css("body *::text").getall()
                clean_lines = [t.strip() for t in texts if t.strip() and "{" not in t and "function(" not in t]
                best_text = " ".join(clean_lines)
                    
            
            if len(best_text) > 20000:
                best_text = best_text[:5000] + "\n[... TRUNCADO ...] \n" + best_text[-15000:]
            
            best_text = re.sub(r'\s+', ' ', best_text).strip()
            
            logger.info("Raspagem concluída. Extraídos %d caracteres.", len(best_text))
            return best_text
            
        except Exception as exc:
            logger.error("Erro crítico ao raspar %s: %s", url, exc)
            return ""

# Instância única compartilhada (Singleton prático)
scrapling_client = ScraplingClient()
