"""
core/clients/scrapers.py — Abstração de raspagem de dados.
Permite trocar a engine de scraping sem afetar as regras de negócio.
"""
from abc import ABC, abstractmethod

class BaseScraper(ABC):
    @abstractmethod
    def fetch_content(self, url: str, sink: dict | None = None) -> str:
        """Extrai o conteúdo principal de uma URL.

        Se ``sink`` for fornecido, pode popular ``sink['references']`` com os
        links externos citados no corpo (opcional, depende da engine).
        """
        pass
