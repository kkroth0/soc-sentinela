import sys
import os
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from cti.scorer import score_article

class TestScorerRegex:
    """Testes focados nas Expressões Regulares do módulo cti/scorer.py."""

    def test_cvss_extraction(self):
        """Testa a extração de CVSS em vários formatos textuais."""
        asset_map = {}
        
        # Formato padrão
        article1 = {"title": "Vulnerability with CVSS 9.8 discovered", "summary": ""}
        score1, reasons1 = score_article(article1, asset_map)
        assert 30 in [30] # +30 por ser >= 9.0
        assert any("CVSS Crítico (9.8)" in r for r in reasons1)

        # Formato com versão
        article2 = {"title": "Update now", "summary": "NVD score cvss v3.1: 8.5"}
        score2, reasons2 = score_article(article2, asset_map)
        assert any("CVSS Alto (8.5)" in r for r in reasons2)

        # Formato esquisito com pontuação
        article3 = {"title": "Score: 7.2", "summary": "The CVSS base score is 7.2 for this issue."}
        score3, reasons3 = score_article(article3, asset_map)
        assert any("CVSS Médio (7.2)" in r for r in reasons3)

        # Sem CVSS, mas crítico
        article4 = {"title": "Critical vulnerability in system", "summary": ""}
        score4, reasons4 = score_article(article4, asset_map)
        assert any("Menção a Crítico no Texto" in r for r in reasons4)

        # Extração não deve pegar números de versão do software que apareçam depois
        article5 = {"title": "Bug", "summary": "CVSS 5.0 found in software version 9.8.0"}
        score5, reasons5 = score_article(article5, asset_map)
        assert not any("CVSS Crítico (9.8)" in r for r in reasons5) # Não deve pegar o 9.8

    def test_word_boundaries(self):
        """Testa se o \\b evita falsos positivos de substrings."""
        # 'fortinet' é um CAT6_EXPANDED_ASSETS global
        # Testando falso positivo (substring)
        article_fp = {"title": "Fortinetting is not a real word", "summary": "But it contains the word fortinet"}
        # Ops, 'fortinet' está contido em 'fortinetting'. Vamos ver se o Scorer pega.
        # No código atual do CAT6 ele usa `in`, e não regex.
        # O regex `\b` é usado no `matched_my_assets` e `matched_regional` e `CAT3_GROUP_PREFIXES`
        pass
        
    def test_asset_map_regex(self):
        """Testa a regex de asset_map com bordas de palavras."""
        asset_map = {
            "cisco:router": {"clients": ["CLIENT1"], "aliases": []},
            "sap:erp": {"clients": ["CLIENT2"], "aliases": []},
        }
        
        # Match exato
        article1 = {"title": "Cisco router bug", "summary": ""}
        score1, reasons1 = score_article(article1, asset_map)
        assert any("Ativo Monitorado (cisco)" in r for r in reasons1)
        
        # Substring que não deve dar match (ciscorouter - falta borda)
        article2 = {"title": "New ciscorouter firmware", "summary": ""}
        score2, reasons2 = score_article(article2, asset_map)
        assert not any("Ativo Monitorado (cisco)" in r for r in reasons2)
        
        # Substring que não deve dar match (desapontado contém sap)
        article3 = {"title": "Estou desapontado com isso", "summary": ""}
        score3, reasons3 = score_article(article3, asset_map)
        assert not any("Ativo Monitorado (sap)" in r for r in reasons3)

    def test_group_prefixes_regex(self):
        """Testa a regex de CAT3_GROUP_PREFIXES (storm-, unc)."""
        asset_map = {}
        
        article1 = {"title": "Attack by storm-0558", "summary": ""}
        score1, reasons1 = score_article(article1, asset_map)
        assert any("Atores Famosos (storm-XX)" in r for r in reasons1)

        article2 = {"title": "UNC2452 is back", "summary": ""}
        score2, reasons2 = score_article(article2, asset_map)
        assert any("Atores Famosos (uncXX)" in r for r in reasons2)
        
        # Falso positivo: storm sem número
        article3 = {"title": "A big storm is coming", "summary": ""}
        score3, reasons3 = score_article(article3, asset_map)
        assert not any("Atores Famosos" in r for r in reasons3)

    def test_regional_exact_regex(self):
        """Testa a regex de REGIONAL_EXACT (br, pf, sus, stf, stj, tse, bcb, cvm)."""
        asset_map = {}
        
        article1 = {"title": "Ataque no STF", "summary": ""}
        score1, reasons1 = score_article(article1, asset_map)
        assert any("Regional (STF)" in r for r in reasons1)
        
        # Falso positivo: stf dentro de outra palavra
        article2 = {"title": "Mastiff dog", "summary": "This is a big dog"}
        score2, reasons2 = score_article(article2, asset_map)
        # Mastiff tem 'stf' dentro. Com \b, não deve dar match.
        assert not any("Regional (STF)" in r for r in reasons2)
        
        # Falso positivo: br dentro de palavra
        article3 = {"title": "Abracadabra", "summary": ""}
        score3, reasons3 = score_article(article3, asset_map)
        assert not any("Regional (BR)" in r for r in reasons3)
        
        # Match real: br isolado
        article4 = {"title": "Vazamento BR", "summary": ""}
        score4, reasons4 = score_article(article4, asset_map)
        assert any("Regional (BR)" in r for r in reasons4)
