import sys
import os
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from cti.rss_client import _parse_entry
from datetime import datetime, timezone

class TestRssClientRegex:
    """Testes focados nas Expressões Regulares do módulo cti/rss_client.py."""

    def test_html_cleaning_summary(self):
        """Testa se a regex de limpeza HTML funciona corretamente."""
        # A regex atual é: re.sub(r"<[^>]+>", "", summary).strip()
        
        # Teste 1: Limpeza simples
        entry = {
            "title": "Title",
            "link": "http://link",
            "summary": "<p>This is a <b>test</b>.</p>"
        }
        res = _parse_entry(entry, "Test Source", 2, datetime(2000, 1, 1, tzinfo=timezone.utc))
        assert res is not None
        assert res["summary"] == "This is a test."
        
        # Teste 2: Script e estilos (pode vazar se não houver um parse completo, mas vamos ver o que a regex faz)
        entry2 = {
            "title": "Title",
            "link": "http://link",
            "summary": "<div><script>alert(1)</script>Text</div>"
        }
        res2 = _parse_entry(entry2, "Test Source", 2, datetime(2000, 1, 1, tzinfo=timezone.utc))
        # A regex remove <script> mas deixa "alert(1)Text". Isso é esperado do comportamento atual,
        # serve para mostrar que a regex não é perfeita, mas limpa as tags HTML em si.
        assert "alert(1)Text" in res2["summary"]
        
        # Teste 3: Sem HTML
        entry3 = {
            "title": "Title",
            "link": "http://link",
            "summary": "Plain text."
        }
        res3 = _parse_entry(entry3, "Test Source", 2, datetime(2000, 1, 1, tzinfo=timezone.utc))
        assert res3["summary"] == "Plain text."
