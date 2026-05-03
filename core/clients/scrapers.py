"""
core/clients/scrapers.py — Abstração de raspagem de dados.
Permite trocar a engine de scraping sem afetar as regras de negócio.
"""
from abc import ABC, abstractmethod

class BaseScraper(ABC):
    @abstractmethod
    def fetch_content(self, url: str) -> str:
        """Extrai o conteúdo principal de uma URL."""
        pass
