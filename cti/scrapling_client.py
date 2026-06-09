"""
cti/scrapling_client.py — Cliente robusto de Web Scraping usando Scrapling.
Focado em extrair o conteúdo principal de notícias e burlar anti-bots.
"""

import re
from typing import Any
from urllib.parse import urlparse
from scrapling.fetchers import StealthyFetcher, Fetcher
from core.logger import get_logger

from core.clients.scrapers import BaseScraper
from core.logger import get_logger

logger = get_logger("cti.scrapling")

# Padrões de links que NÃO são referências (botões de compartilhar, tracking, etc.)
_SHARE_NOISE = (
    "/intent/", "/sharer", "/share?", "sharer.php", "/submit", "mailto:",
    "wa.me", "api.whatsapp", "//t.co/", "/cdn-cgi/", "javascript:",
    "/tag/", "/category/", "/author/", "/feed", "utm_",
)


def _extract_references(blocks: list[Any], base_url: str, limit: int = 6) -> list[str]:
    """Extrai links EXTERNOS citados no corpo do artigo (fontes/referências).

    Descarta links internos (mesmo domínio), botões de compartilhar e tracking.
    """
    base_dom = urlparse(base_url).netloc.lower().replace("www.", "")
    seen: set[str] = set()
    refs: list[str] = []
    for block in blocks:
        try:
            hrefs = block.css("a::attr(href)").getall()
        except Exception:
            continue
        for h in hrefs:
            h = (h or "").strip()
            if not h.startswith("http"):
                continue
            dom = urlparse(h).netloc.lower().replace("www.", "")
            if not dom or dom == base_dom:          # link interno ao próprio site
                continue
            low = h.lower()
            if any(n in low for n in _SHARE_NOISE):  # share/tracking/navegação
                continue
            if h in seen:
                continue
            seen.add(h)
            refs.append(h)
            if len(refs) >= limit:
                return refs
    return refs

class ScraplingClient(BaseScraper):
    def __init__(self):
        # Aqui poderíamos inicializar um pool se necessário
        pass

    def fetch_content(self, url: str, sink: dict[str, Any] | None = None) -> str:
        """
        Visita o site e extrai o conteúdo principal.
        Tenta primeiro com Fetcher (rápido) e se falhar/bloquear tenta StealthyFetcher.

        Se ``sink`` for fornecido, popula ``sink['references']`` com os links
        externos citados no corpo do artigo (thread-safe: usa o dict do artigo).
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

            # Procuramos por tags de artigo ou blocos de conteúdo conhecidos.
            # A API do Scrapling trata os kwargs de find_all como filtros de
            # atributo (que só aceitam string), então as tags estruturais vão
            # como argumento posicional e as classes via seletor CSS.
            content_blocks = list(page.find_all(["article", "main", "section"]))
            content_blocks += list(page.css(
                ".post-content, .article-body, .entry-content, .td-post-content, .article-content"
            ))
            
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

            # Coleta de referências (links externos citados no corpo)
            if sink is not None:
                try:
                    refs = _extract_references(content_blocks, url)
                    if refs:
                        sink["references"] = refs
                        logger.info("Referências coletadas: %d link(s) externo(s).", len(refs))
                except Exception as exc:
                    logger.debug("Falha ao coletar referências de %s: %s", url, exc)

            logger.info("Raspagem concluída. Extraídos %d caracteres.", len(best_text))
            return best_text
            
        except Exception as exc:
            logger.error("Erro crítico ao raspar %s: %s", url, exc)
            return ""

# Instância única compartilhada (Singleton prático)
scrapling_client = ScraplingClient()
