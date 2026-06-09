"""
tests/cti/test_scorer_regex.py — Testes do motor de scoring CTI funcional.
"""
import sys
import os
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from cti.scorer import score_article


class TestScorerCVSS:
    """Testes da extração e pontuação de CVSS no texto."""

    def test_cvss_critical(self):
        article = {"title": "Vulnerability with CVSS 9.8 discovered", "summary": ""}
        score, reasons = score_article(article, {})
        assert any("CVSS Crítico (9.8)" in r for r in reasons)

    def test_cvss_high(self):
        article = {"title": "Update now", "summary": "NVD score cvss v3.1: 8.5"}
        score, reasons = score_article(article, {})
        assert any("CVSS Alto (8.5)" in r for r in reasons)

    def test_cvss_medium_with_score_keyword(self):
        article = {"title": "Score: 7.2", "summary": "The CVSS base score is 7.2 for this issue."}
        score, reasons = score_article(article, {})
        assert any("7.2" in r for r in reasons)

    def test_cvss_below_threshold_ignored(self):
        article = {"title": "Bug", "summary": "CVSS 5.0 found"}
        score, reasons = score_article(article, {})
        assert not any("CVSS" in r for r in reasons)

    def test_cvss_takes_highest_not_first(self):
        # Mesmo citado depois, o 9.8 deve prevalecer sobre o 7.5 que vem antes.
        article = {"title": "CVSS 7.5 in module A, CVSS 9.8 in module B", "summary": ""}
        score, reasons = score_article(article, {})
        assert any("CVSS Crítico (9.8)" in r for r in reasons)
        assert not any("CVSS Alto" in r for r in reasons)

    def test_cvss_perfect_ten_integer(self):
        # "CVSS 10" (inteiro, sem decimal) deve ser detectado como crítico.
        article = {"title": "Maximum severity CVSS 10 flaw", "summary": ""}
        score, reasons = score_article(article, {})
        assert any("CVSS Crítico" in r for r in reasons)

    def test_cvss_version_not_confused_with_score(self):
        # "CVSS:3.1 base score 9.0" deve capturar 9.0, não a versão 3.1.
        article = {"title": "CVSS:3.1 base score 9.0 issue", "summary": ""}
        score, reasons = score_article(article, {})
        assert any("CVSS Crítico (9.0)" in r for r in reasons)


class TestScorerVulnClass:
    """Testes da categoria de classe de vulnerabilidade (exploitabilidade)."""

    def test_rce_scores(self):
        article = {"title": "Unauthenticated remote code execution in product", "summary": ""}
        score, reasons = score_article(article, {})
        assert any("Classe de Vuln" in r for r in reasons)

    def test_rce_token_word_boundary(self):
        # 'rce' isolado pontua, mas não dentro de 'force'/'commerce'.
        assert any("Classe de Vuln" in r for r in score_article({"title": "RCE found", "summary": ""}, {})[1])
        assert not any("Classe de Vuln" in r for r in score_article({"title": "ecommerce force", "summary": ""}, {})[1])


class TestScorerAssetMatch:
    """Testes da regra de match de ativos monitorados."""

    def test_exact_match(self):
        asset_map = {"cisco:router": {"clients": ["CLIENT1"], "aliases": []}}
        article = {"title": "Cisco router bug", "summary": ""}
        score, reasons = score_article(article, asset_map)
        assert any("Ativo Monitorado (cisco)" in r for r in reasons)

    def test_no_false_positive_substring(self):
        asset_map = {"cisco:router": {"clients": ["CLIENT1"], "aliases": []}}
        article = {"title": "New ciscorouter firmware", "summary": ""}
        score, reasons = score_article(article, asset_map)
        assert not any("Ativo Monitorado" in r for r in reasons)

    def test_sap_no_false_positive(self):
        asset_map = {"sap:erp": {"clients": ["CLIENT2"], "aliases": []}}
        article = {"title": "Estou desapontado com isso", "summary": ""}
        score, reasons = score_article(article, asset_map)
        assert not any("Ativo Monitorado" in r for r in reasons)


class TestScorerGroups:
    """Testes da regex de grupos de ameaça (storm-, unc)."""

    def test_storm_group(self):
        article = {"title": "Attack by storm-0558", "summary": ""}
        score, reasons = score_article(article, {})
        assert any("Grupo Cibercriminoso" in r for r in reasons)

    def test_unc_group(self):
        article = {"title": "UNC2452 is back", "summary": ""}
        score, reasons = score_article(article, {})
        assert any("Grupo Cibercriminoso" in r for r in reasons)

    def test_storm_without_number_no_match(self):
        """'storm' sem número não deve dar match como grupo."""
        article = {"title": "A big storm is coming", "summary": ""}
        score, reasons = score_article(article, {})
        assert not any("Grupo Cibercriminoso" in r for r in reasons)


class TestScorerRegional:
    """Testes da regex regional (BR/LATAM)."""

    def test_stf_exact(self):
        article = {"title": "Ataque no STF", "summary": ""}
        score, reasons = score_article(article, {})
        assert any("Regional (STF)" in r for r in reasons)

    def test_stf_false_positive_in_word(self):
        """'stf' dentro de 'Mastiff' não deve dar match."""
        article = {"title": "Mastiff dog", "summary": "This is a big dog"}
        score, reasons = score_article(article, {})
        assert not any("Regional" in r for r in reasons)

    def test_br_false_positive_in_word(self):
        """'br' dentro de 'Abracadabra' não deve dar match."""
        article = {"title": "Abracadabra", "summary": ""}
        score, reasons = score_article(article, {})
        assert not any("Regional" in r for r in reasons)

    def test_br_isolated(self):
        article = {"title": "Vazamento BR", "summary": ""}
        score, reasons = score_article(article, {})
        assert any("Regional (BR)" in r for r in reasons)


class TestScorerNormalization:
    """Testes de normalização e limites do score."""

    def test_score_capped_at_100(self):
        """Score nunca deve ultrapassar 100."""
        # Artigo com muitos sinais: critical + ransomware + breach + regional + CVE
        article = {
            "title": "CRITICAL zero-day ransomware data breach in Brazil CVE-2026-1234",
            "summary": "CVSS 9.8 critical exploit lockbit attack on governo"
        }
        score, reasons = score_article(article, {})
        assert score <= 100
        assert len(reasons) > 3  # Deve ter múltiplos motivos

    def test_score_min_is_zero(self):
        """Score nunca deve ser negativo."""
        article = {"title": "Vaga de emprego para analista de segurança tutorial webinar", "summary": ""}
        score, reasons = score_article(article, {})
        assert score >= 0

    def test_noise_does_not_substring_match_real_words(self):
        """Ruído ('dica') não pode matar artigo legítimo via substring ('indicating')."""
        article = {
            "title": "Interlock Ransomware Attack",
            "summary": "Active ransomware campaign with unauthenticated RCE, indicating a mature operation.",
        }
        score, reasons = score_article(article, {})
        assert score > 0
        assert not any("Ruído" in r for r in reasons)

    def test_cve_mention_scores(self):
        """Menção a CVE deve pontuar."""
        article = {"title": "New flaw CVE-2026-1234 discovered", "summary": ""}
        score, reasons = score_article(article, {})
        assert any("CVE Identificada" in r for r in reasons)

    def test_empty_article_zero_score(self):
        """Artigo vazio deve ter score 0."""
        article = {"title": "", "summary": ""}
        score, reasons = score_article(article, {})
        assert score == 0
        assert reasons == []


class TestScorerWeightBoost:
    """Testes do bônus de confiança da fonte (weight_boost do feed)."""

    def test_weight_boost_applied_when_content_signal(self):
        base = {"title": "New ransomware campaign", "summary": ""}
        boosted = {"title": "New ransomware campaign", "summary": "", "weight_boost": 20}
        s_base, _ = score_article(base, {})
        s_boost, reasons = score_article(boosted, {})
        assert s_boost == s_base + 20
        assert any("Fonte Prioritária" in r for r in reasons)

    def test_weight_boost_is_capped(self):
        base = {"title": "New ransomware campaign", "summary": ""}
        boosted = {"title": "New ransomware campaign", "summary": "", "weight_boost": 999}
        s_base, _ = score_article(base, {})
        s_boost, _ = score_article(boosted, {})
        assert s_boost == s_base + 20  # boost de 999 é limitado ao cap de 20

    def test_weight_boost_alone_does_not_pass(self):
        """Boost sem nenhum sinal de conteúdo não pontua (evita ruído aprovado)."""
        article = {"title": "Random unrelated article", "summary": "", "weight_boost": 20}
        score, reasons = score_article(article, {})
        assert score == 0
        assert not any("Fonte Prioritária" in r for r in reasons)
