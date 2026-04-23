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
    @patch("cti.pipeline.global_dispatcher")
    @patch("cti.pipeline.translator")
    @patch("cti.pipeline.score_article")
    def test_new_article_is_sent(self, mock_score, mock_trans, mock_dispatcher, mock_storage):
        """Artigo novo → deve ser enviado via dispatcher."""
        mock_storage.is_news_sent.return_value = False
        mock_trans.translate_article.side_effect = lambda a: a
        mock_dispatcher.dispatch_cti.return_value = True
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

        success, reason = _process_single_article(article, asset_map)
        assert success is True
        assert reason == "enviado com sucesso"
        mock_storage.save_news.assert_called_once()
        mock_dispatcher.dispatch_cti.assert_called_once()

    @patch("cti.pipeline.storage")
    def test_duplicate_article_is_skipped(self, mock_storage):
        """Artigo já enviado → deve ser pulado."""
        mock_storage.is_news_sent.return_value = True

        article = {"url": "https://example.com/old"}
        asset_map = {}

        success, reason = _process_single_article(article, asset_map)
        assert success is False
        assert reason == "já enviado"

    @patch("cti.pipeline.storage")
    @patch("cti.pipeline.global_dispatcher")
    @patch("cti.pipeline.translator")
    @patch("cti.pipeline.score_article")
    def test_dispatcher_failure_does_not_save(self, mock_score, mock_trans, mock_dispatcher, mock_storage):
        """Falha no dispatcher → artigo NÃO deve ser salvo no banco."""
        mock_storage.is_news_sent.return_value = False
        mock_trans.translate_article.side_effect = lambda a: a
        mock_dispatcher.dispatch_cti.return_value = False
        mock_score.return_value = (100, ["Critical"])

        article = {
            "title": "Failed Article",
            "url": "https://example.com/fail",
            "source": "Test",
            "layer": 2,
        }
        asset_map = {}

        success, reason = _process_single_article(article, asset_map)
        assert success is False
        assert reason == "falha no envio"
        mock_storage.save_news.assert_not_called()


class TestRunPipeline:
    """Testes do pipeline CTI completo."""

    @patch("cti.pipeline.rss_client")
    @patch("cti.pipeline.storage")
    @patch("cti.pipeline.global_dispatcher")
    @patch("cti.pipeline.translator")
    @patch("cti.pipeline.score_article")
    def test_run_processes_articles(self, mock_score, mock_trans, mock_dispatcher, mock_storage, mock_rss):
        """Pipeline completo processa artigos."""
        mock_rss.fetch_recent_articles.return_value = [
            {"title": "Art 1", "url": "https://ex.com/1", "source": "S1", "layer": 4},
            {"title": "Art 2", "url": "https://ex.com/2", "source": "S2", "layer": 4},
        ]
        mock_storage.is_news_sent.return_value = False
        mock_trans.translate_article.side_effect = lambda a: a
        mock_dispatcher.dispatch_cti.return_value = True
        mock_score.return_value = (50, ["Mocked"])

        stats = run()
        assert stats["total"] == 2
        assert stats["sent"] == 2
        assert stats["errors"] == 0

    @patch("cti.pipeline.rss_client")
    def test_run_with_no_articles(self, mock_rss):
        """Pipeline com zero artigos → retorna zeros."""
        mock_rss.fetch_recent_articles.return_value = []

        stats = run()
        assert stats["total"] == 0
        assert stats["sent"] == 0
