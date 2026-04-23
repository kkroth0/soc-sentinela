"""
tests/test_regex_full.py — Bateria extensa de testes de regex do SOC Sentinel.
Cobre: CTI scorer, RSS client HTML cleaning, meta scraper, CVSS extraction,
word boundaries, asset matching, group prefixes, regional patterns.
"""

import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cti.scorer import score_article
from cti.rss_client import _parse_entry
from datetime import datetime, timezone


# ═══════════════════════════════════════════════════════════════════════
# 1. CVSS EXTRACTION
# ═══════════════════════════════════════════════════════════════════════

class TestCvssExtraction:
    """Testes extensivos para a extração de CVSS do CTI scorer."""

    ASSET_MAP = {}

    def _score(self, title, summary=""):
        return score_article({"title": title, "summary": summary}, self.ASSET_MAP)

    def test_cvss_standard_format(self):
        _, reasons = self._score("Vulnerability with CVSS 9.8 discovered")
        assert any("CVSS Crítico (9.8)" in r for r in reasons)

    def test_cvss_with_version_prefix(self):
        _, reasons = self._score("", "NVD score cvss v3.1: 8.5")
        assert any("CVSS Alto (8.5)" in r for r in reasons)

    def test_cvss_score_keyword(self):
        _, reasons = self._score("", "The CVSS base score is 7.2 for this issue.")
        assert any("CVSS Médio (7.2)" in r for r in reasons)

    def test_cvss_below_7_not_scored(self):
        score, reasons = self._score("CVSS score 6.9")
        assert not any("CVSS" in r for r in reasons)

    def test_cvss_exactly_9(self):
        _, reasons = self._score("CVSS score 9.0")
        assert any("CVSS Crítico (9.0)" in r for r in reasons)

    def test_cvss_exactly_8(self):
        _, reasons = self._score("CVSS score 8.0")
        assert any("CVSS Alto (8.0)" in r for r in reasons)

    def test_cvss_exactly_7(self):
        _, reasons = self._score("CVSS score 7.0")
        assert any("CVSS Médio (7.0)" in r for r in reasons)

    def test_version_number_not_confused_with_cvss(self):
        """v3.1, v9.8.0 etc devem ser removidos antes de extrair CVSS."""
        score, reasons = self._score("", "CVSS 5.0 found in software version 9.8.0")
        assert not any("CVSS Crítico (9.8)" in r for r in reasons)

    def test_no_cvss_but_critical_text(self):
        _, reasons = self._score("Critical vulnerability in system")
        assert any("Menção a Crítico" in r for r in reasons)

    def test_no_cvss_vulnerabilidade_critica(self):
        _, reasons = self._score("vulnerabilidade crítica encontrada")
        assert any("Menção a Crítico" in r for r in reasons)

    def test_cvss_with_10(self):
        _, reasons = self._score("CVSS score 10.0 maximum severity")
        assert any("CVSS Crítico (10.0)" in r for r in reasons)

    def test_cvss_only_first_match_used(self):
        """Se há múltiplos CVSS, o primeiro deve ser usado."""
        _, reasons = self._score("", "score 9.1 and score 7.0")
        cvss_reasons = [r for r in reasons if "CVSS" in r]
        assert len(cvss_reasons) == 1
        assert "9.1" in cvss_reasons[0]


# ═══════════════════════════════════════════════════════════════════════
# 2. WORD BOUNDARIES (REGIONAL EXACT)
# ═══════════════════════════════════════════════════════════════════════

class TestRegionalExact:
    """Testes para REGIONAL_EXACT com \\b."""

    ASSET_MAP = {}

    def _score(self, title, summary=""):
        return score_article({"title": title, "summary": summary}, self.ASSET_MAP)

    def test_br_isolated(self):
        _, reasons = self._score("Vazamento BR")
        assert any("Regional (BR)" in r for r in reasons)

    def test_br_inside_word_no_match(self):
        _, reasons = self._score("Abracadabra")
        assert not any("Regional (BR)" in r for r in reasons)

    def test_stf_isolated(self):
        _, reasons = self._score("Ataque ao STF")
        assert any("Regional (STF)" in r for r in reasons)

    def test_stf_inside_mastiff_no_match(self):
        _, reasons = self._score("Mastiff dog breed")
        assert not any("Regional (STF)" in r for r in reasons)

    def test_sus_isolated(self):
        _, reasons = self._score("Falha no SUS")
        assert any("Regional (SUS)" in r for r in reasons)

    def test_sus_in_suspicious_no_match(self):
        """'suspicious' contém 'sus' mas não deve dar match."""
        _, reasons = self._score("Suspicious activity detected")
        assert not any("Regional (SUS)" in r for r in reasons)

    def test_pf_isolated(self):
        _, reasons = self._score("Operação da PF")
        assert any("Regional (PF)" in r for r in reasons)

    def test_pf_in_pfizer_no_match(self):
        _, reasons = self._score("Pfizer vaccine update")
        assert not any("Regional (PF)" in r for r in reasons)

    def test_bcb_isolated(self):
        _, reasons = self._score("Comunicado do BCB")
        assert any("Regional (BCB)" in r for r in reasons)

    def test_cvm_isolated(self):
        _, reasons = self._score("Alerta CVM")
        assert any("Regional (CVM)" in r for r in reasons)


# ═══════════════════════════════════════════════════════════════════════
# 3. REGIONAL SUBSTRING
# ═══════════════════════════════════════════════════════════════════════

class TestRegionalSubstring:
    """Testes para REGIONAL_SUBSTRING (match por 'in')."""

    ASSET_MAP = {}

    def _score(self, title, summary=""):
        return score_article({"title": title, "summary": summary}, self.ASSET_MAP)

    def test_brasil(self):
        _, reasons = self._score("Ataque cibernético no Brasil")
        assert any("Regional" in r for r in reasons)

    def test_brazil_english(self):
        _, reasons = self._score("Ransomware targets Brazil")
        assert any("Regional" in r for r in reasons)

    def test_latam(self):
        _, reasons = self._score("New LATAM threat campaign")
        assert any("Regional" in r for r in reasons)

    def test_dot_com_br(self):
        _, reasons = self._score("Site atacado example.com.br")
        assert any("Regional" in r for r in reasons)

    def test_gov_br(self):
        _, reasons = self._score("Data from portal.gov.br leaked")
        assert any("Regional" in r for r in reasons)

    def test_sao_paulo(self):
        _, reasons = self._score("Empresa de são paulo atacada")
        assert any("Regional" in r for r in reasons)


# ═══════════════════════════════════════════════════════════════════════
# 4. ASSET MAP WORD BOUNDARIES
# ═══════════════════════════════════════════════════════════════════════

class TestAssetMapRegex:
    """Testes para regex de asset_map com \\b."""

    def _asset_map(self, key):
        return {key: {"clients": ["CLIENT1"], "aliases": []}}

    def test_exact_match(self):
        _, reasons = score_article(
            {"title": "Cisco router bug", "summary": ""},
            self._asset_map("cisco:router"),
        )
        assert any("Ativo Monitorado" in r for r in reasons)

    def test_substring_no_match(self):
        """ciscorouter deve NÃO dar match em 'cisco'."""
        _, reasons = score_article(
            {"title": "New ciscorouter firmware", "summary": ""},
            self._asset_map("cisco:router"),
        )
        # 'cisco' tem len > 2, mas 'ciscorouter' não contém word boundary para 'cisco'
        # Actually 'cisco' IS a substring of 'ciscorouter', but the regex uses \b
        # 'ciscorouter' — \bcisco\b would not match because 'r' follows directly
        # Correto: não dá match
        assert not any("Ativo Monitorado (cisco)" in r for r in reasons)

    def test_short_term_skipped(self):
        """Termos com len <= 2 devem ser ignorados para evitar falsos positivos."""
        _, reasons = score_article(
            {"title": "HP laptop release date is today", "summary": ""},
            self._asset_map("hp:laptop"),
        )
        # 'hp' tem len == 2, deve ser ignorado. 'laptop' tem len > 2.
        # 'laptop' está no título, deve dar match
        assert any("Ativo Monitorado" in r for r in reasons)

    def test_underscore_normalization(self):
        """windows_server deve dar match em 'windows server'."""
        _, reasons = score_article(
            {"title": "Windows Server vulnerability", "summary": ""},
            {"microsoft:windows_server": {"clients": ["C1"], "aliases": []}},
        )
        assert any("Ativo Monitorado" in r for r in reasons)

    def test_sap_in_desapontado_no_match(self):
        """'sap' (3 chars) dentro de 'desapontado' não deve dar match."""
        _, reasons = score_article(
            {"title": "Estou desapontado com isso", "summary": ""},
            {"sap:erp": {"clients": ["C1"], "aliases": []}},
        )
        assert not any("Ativo Monitorado (sap)" in r for r in reasons)


# ═══════════════════════════════════════════════════════════════════════
# 5. GROUP PREFIXES
# ═══════════════════════════════════════════════════════════════════════

class TestGroupPrefixes:
    """Testes para regex de CAT5_GROUP_PREFIXES."""

    ASSET_MAP = {}

    def _score(self, title):
        return score_article({"title": title, "summary": ""}, self.ASSET_MAP)

    def test_storm_with_number(self):
        _, reasons = self._score("Attack by storm-0558")
        assert any("Atores Famosos (storm-XX)" in r for r in reasons)

    def test_unc_with_number(self):
        _, reasons = self._score("UNC2452 is back")
        assert any("Atores Famosos (uncXX)" in r for r in reasons)

    def test_storm_without_number_no_match(self):
        _, reasons = self._score("A big storm is coming")
        assert not any("Atores Famosos" in r for r in reasons)

    def test_unc_without_number_no_match(self):
        _, reasons = self._score("Uncle Bob says")
        assert not any("Atores Famosos" in r for r in reasons)

    def test_storm_with_large_number(self):
        _, reasons = self._score("storm-12345 campaign")
        assert any("Atores Famosos" in r for r in reasons)


# ═══════════════════════════════════════════════════════════════════════
# 6. CATEGORY MATCHING (SUBSTRING)
# ═══════════════════════════════════════════════════════════════════════

class TestCategoryMatching:
    """Testes para as categorias que usam 'in' (substring)."""

    ASSET_MAP = {}

    def _score(self, title, summary=""):
        return score_article({"title": title, "summary": summary}, self.ASSET_MAP)

    def test_zero_day(self):
        _, reasons = self._score("Zero-day exploit in the wild")
        assert any("Impacto Crítico" in r for r in reasons)

    def test_0day(self):
        _, reasons = self._score("0-day vulnerability discovered")
        assert any("Impacto Crítico" in r for r in reasons)

    def test_ransomware(self):
        _, reasons = self._score("New ransomware variant")
        assert any("Malware/Ransomware" in r for r in reasons)

    def test_data_breach(self):
        _, reasons = self._score("Major data breach at company")
        assert any("Data Breach" in r for r in reasons)

    def test_phishing(self):
        _, reasons = self._score("Phishing campaign targeting banks")
        assert any("TTP/Campanha" in r for r in reasons)

    def test_lockbit(self):
        _, reasons = self._score("LockBit 3.0 attacks increase")
        assert any("Atores Famosos (lockbit)" in r for r in reasons)

    def test_microsoft_vendor(self):
        _, reasons = self._score("Microsoft patches 50 CVEs")
        assert any("Vendor Crítico (microsoft)" in r for r in reasons)

    def test_banco_setor(self):
        _, reasons = self._score("Ataque ao banco nacional")
        assert any("Setor Nacional (banco)" in r for r in reasons)

    def test_cve_mention(self):
        _, reasons = self._score("CVE-2026-1234 exploited")
        assert any("CVE Identificada" in r for r in reasons)

    def test_layer_4_bonus(self):
        score, reasons = score_article(
            {"title": "Anything", "summary": "", "layer": 4},
            self.ASSET_MAP,
        )
        assert any("Radar Local" in r for r in reasons)

    def test_mass_exploitation(self):
        _, reasons = self._score("mass exploitation of critical bug")
        assert any("Grande Escala" in r for r in reasons)


# ═══════════════════════════════════════════════════════════════════════
# 7. RSS HTML CLEANING
# ═══════════════════════════════════════════════════════════════════════

class TestRssHtmlCleaning:
    """Testes para a regex de limpeza HTML no rss_client."""

    CUTOFF = datetime(2000, 1, 1, tzinfo=timezone.utc)

    def _parse(self, summary):
        entry = {"title": "Title", "link": "http://link", "summary": summary}
        result = _parse_entry(entry, "Test", 2, self.CUTOFF)
        return result["summary"] if result else ""

    def test_simple_tags(self):
        assert self._parse("<p>Hello <b>world</b></p>") == "Hello world"

    def test_nested_tags(self):
        assert self._parse("<div><span>Text</span></div>") == "Text"

    def test_self_closing_tags(self):
        result = self._parse("Before<br/>After")
        assert "Before" in result and "After" in result

    def test_tags_with_attributes(self):
        assert self._parse('<a href="http://evil">Click</a>') == "Click"

    def test_no_html_passthrough(self):
        assert self._parse("Plain text.") == "Plain text."

    def test_script_tag_content_leaks(self):
        """Documenta comportamento: conteúdo de <script> NÃO é removido, apenas a tag."""
        result = self._parse("<script>alert(1)</script>Text")
        assert "alert(1)" in result  # Limitação conhecida

    def test_truncation_at_500(self):
        long_text = "A" * 600
        result = self._parse(long_text)
        assert len(result) <= 500


# ═══════════════════════════════════════════════════════════════════════
# 8. META DESCRIPTION SCRAPER REGEX
# ═══════════════════════════════════════════════════════════════════════

class TestMetaDescriptionRegex:
    """Testes unitários isolados para a regex de meta description."""

    REGEX = re.compile(
        r'<meta[^>]*?(?:name|property)=["\'](?:og:description|description)["\'][^>]*?content=["\']([^"\']+)["\']',
        re.IGNORECASE,
    )

    def test_standard_meta_description(self):
        html = '<meta name="description" content="A security advisory.">'
        match = self.REGEX.search(html)
        assert match and match.group(1) == "A security advisory."

    def test_og_description(self):
        html = '<meta property="og:description" content="Open Graph desc">'
        match = self.REGEX.search(html)
        assert match and match.group(1) == "Open Graph desc"

    def test_single_quotes(self):
        html = "<meta name='description' content='Single quote desc'>"
        match = self.REGEX.search(html)
        assert match and match.group(1) == "Single quote desc"

    def test_content_before_name_no_match(self):
        """Limitação: não pega se content vem antes de name."""
        html = '<meta content="Reversed" name="description">'
        match = self.REGEX.search(html)
        assert match is None  # Limitação documentada

    def test_no_meta_tag(self):
        html = "<html><body>No meta here</body></html>"
        match = self.REGEX.search(html)
        assert match is None


# ═══════════════════════════════════════════════════════════════════════
# 9. SCORE ACCUMULATION
# ═══════════════════════════════════════════════════════════════════════

class TestScoreAccumulation:
    """Testa que múltiplas categorias acumulam pontos corretamente."""

    def test_max_score_scenario(self):
        """Artigo regional + zero-day + ransomware + asset match + CVE mention."""
        asset_map = {"microsoft:windows": {"clients": ["C1"], "aliases": []}}
        article = {
            "title": "Zero-day ransomware hits Microsoft Windows in Brazil",
            "summary": "CVE-2026-9999 actively exploited",
            "layer": 4,
        }
        score, reasons = score_article(article, asset_map)
        # Regional(50) + Asset(50) + Critical(50) + Malware(40) + Vendor(15) + CVE(10) + L4(30) = 245
        assert score >= 200
        assert len(reasons) >= 5

    def test_zero_score_irrelevant_article(self):
        """Artigo completamente irrelevante deve ter score 0."""
        score, reasons = score_article(
            {"title": "New cooking recipe published", "summary": "How to make pasta"},
            {},
        )
        assert score == 0
        assert len(reasons) == 0
