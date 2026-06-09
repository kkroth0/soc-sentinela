"""
tests/cti/test_pipeline.py — Testes do fluxo completo CTI atualizados para Arquitetura Hexagonal.
"""

import sys
import os
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from cti.pipeline import _process_single_article, run


class TestProcessSingleArticle:
    """Testes do processamento individual de artigos."""

    @patch("cti.pipeline.storage")
    @patch("cti.pipeline.telegram_dispatcher")
    @patch("cti.pipeline.groq_engine")
    @patch("cti.pipeline.score_article")
    def test_new_article_is_sent(self, mock_score, mock_groq, mock_dispatcher, mock_storage):
        """Artigo novo → deve ser enviado via dispatcher."""
        mock_storage.is_news_sent.return_value = False
        mock_dispatcher.send_cti_news.return_value = True
        mock_score.return_value = (50, ["Test Reason"])

        article = {
            "title": "New Threat Report",
            "url": "https://example.com/article1",
            "summary": "A new threat has been identified.",
            "source": "Test Source",
            "layer": 3,
            "date": "2026-04-01T10:00:00",
        }
        asset_map = {}

        success, reason = _process_single_article(article, asset_map, mock_dispatcher, db_module=mock_storage)
        assert success is True
        assert reason == "enviado com sucesso"
        mock_storage.save_news.assert_called_once()
        mock_dispatcher.send_cti_news.assert_called_once()

    @patch("cti.pipeline.storage")
    def test_duplicate_article_is_skipped(self, mock_storage):
        """Artigo já enviado → deve ser pulado."""
        mock_storage.is_news_sent.return_value = True

        article = {"url": "https://example.com/old"}
        asset_map = {}

        success, reason = _process_single_article(article, asset_map, MagicMock(), db_module=mock_storage)
        assert success is False
        assert reason == "já enviado"

    @patch("cti.pipeline.storage")
    @patch("cti.pipeline.telegram_dispatcher")
    @patch("cti.pipeline.groq_engine")
    @patch("cti.pipeline.score_article")
    def test_dispatcher_failure_does_not_save(self, mock_score, mock_groq, mock_dispatcher, mock_storage):
        """Falha no dispatcher → artigo NÃO deve ser salvo no banco."""
        mock_storage.is_news_sent.return_value = False
        mock_dispatcher.send_cti_news.return_value = False
        mock_score.return_value = (100, ["Critical"])

        article = {
            "title": "Failed Article",
            "url": "https://example.com/fail",
            "source": "Test",
            "layer": 2,
        }
        asset_map = {}

        success, reason = _process_single_article(article, asset_map, mock_dispatcher, db_module=mock_storage)
        assert success is False
        assert reason == "falha no envio"
        mock_storage.save_news.assert_not_called()

    @patch("cti.pipeline.storage")
    @patch("cti.pipeline.telegram_dispatcher")
    @patch("cti.pipeline.groq_engine")
    @patch("cti.pipeline.score_article")
    def test_article_extracts_cwe_and_threats(self, mock_score, mock_groq, mock_dispatcher, mock_storage):
        """Artigo com CWE-79 e menções a ransomware/unc2452 deve extrair CWE e ameaças."""
        mock_storage.is_news_sent.return_value = False
        mock_dispatcher.send_cti_news.return_value = True
        mock_score.return_value = (80, ["Test Reason"])

        article = {
            "title": "Severe vulnerability CWE-79 in system",
            "url": "https://example.com/article_cwe",
            "summary": "This ransomware attack was launched by UNC2452 targeting critical targets.",
            "source": "BleepingComputer",
            "layer": 3,
            "date": "2026-04-01T10:00:00",
        }
        asset_map = {}

        success, reason = _process_single_article(article, asset_map, mock_dispatcher, db_module=mock_storage)
        assert success is True
        
        mock_dispatcher.send_cti_news.assert_called_once()
        sent_news = mock_dispatcher.send_cti_news.call_args[0][0]
        assert sent_news.cwes == ["CWE-79"]
        assert "Ransomware" in sent_news.threats
        assert "Grupo APT (UNC2452)" in sent_news.threats

    @patch("cti.pipeline.storage")
    @patch("cti.pipeline.telegram_dispatcher")
    @patch("cti.pipeline.groq_engine")
    @patch("cti.pipeline.score_article")
    @patch("cti.pipeline.get_or_fetch_cve")
    def test_article_extracts_and_enriches_cve(self, mock_get_cve, mock_score, mock_groq, mock_dispatcher, mock_storage):
        """Artigo com menção a CVE-2026-9999 deve extrair a CVE e mesclar seus CWEs e ameaças."""
        mock_storage.is_news_sent.return_value = False
        mock_dispatcher.send_cti_news.return_value = True
        mock_score.return_value = (80, ["Test"])
        mock_get_cve.return_value = {
            "cve_id": "CVE-2026-9999",
            "cvss_score": 9.8,
            "severity": "CRITICAL",
            "risk_tag": "CRITICAL",
            "cwes": ["CWE-20"],
            "threats": ["Exploração Ativa (CISA KEV)", "Ransomware"]
        }

        article = {
            "title": "New report on CVE-2026-9999",
            "url": "https://example.com/cve_news",
            "summary": "This article discusses a critical flaw.",
            "source": "BleepingComputer",
            "layer": 3,
            "date": "2026-04-01T10:00:00",
        }
        asset_map = {}

        success, reason = _process_single_article(article, asset_map, mock_dispatcher, db_module=mock_storage)
        assert success is True

        mock_dispatcher.send_cti_news.assert_called_once()
        sent_news = mock_dispatcher.send_cti_news.call_args[0][0]
        
        assert len(sent_news.cves) == 1
        assert sent_news.cves[0]["cve_id"] == "CVE-2026-9999"
        assert sent_news.cves[0]["cvss_score"] == 9.8

        assert "CWE-20" in sent_news.cwes
        assert "Exploração Ativa (CISA KEV)" in sent_news.threats
        assert "Ransomware" in sent_news.threats


class TestRunPipeline:
    """Testes do pipeline CTI completo."""

    @patch("cti.pipeline.rss_client")
    @patch("cti.pipeline.storage")
    @patch("cti.pipeline.telegram_dispatcher")
    @patch("cti.pipeline.groq_engine")
    @patch("cti.pipeline.score_article")
    def test_run_processes_articles(self, mock_score, mock_groq, mock_dispatcher, mock_storage, mock_rss):
        """Pipeline completo processa artigos."""
        mock_rss.fetch_recent_articles.return_value = [
            {"title": "Art 1", "url": "https://ex.com/1", "source": "S1", "layer": 4},
            {"title": "Art 2", "url": "https://ex.com/2", "source": "S2", "layer": 4},
        ]
        mock_storage.is_news_sent.return_value = False
        mock_dispatcher.send_cti_news.return_value = True
        mock_score.return_value = (50, ["Mocked"])

        stats = run(notifier=mock_dispatcher, db_module=mock_storage)
        assert stats["total"] == 2
        assert stats["sent"] == 2
        assert stats["errors"] == 0

    @patch("cti.pipeline.rss_client")
    def test_run_with_no_articles(self, mock_rss):
        """Pipeline com zero artigos → retorna zeros."""
        mock_rss.fetch_recent_articles.return_value = []

        stats = run(db_module=MagicMock())
        assert stats["total"] == 0
        assert stats["sent"] == 0
