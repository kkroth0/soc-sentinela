"""
tests/cve/test_pipeline.py — Testes do should_alert() atualizados para a nova lógica e retorno.
"""

import sys
import os
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from cve.pipeline import should_alert


class TestShouldAlert:
    """Testes da função should_alert() — a decision authority."""

    @patch("cve.pipeline.storage")
    @patch("cve.pipeline.risk_scorer")
    @patch("cve.pipeline.asset_matcher")
    def test_cve_with_matching_clients_should_alert(
        self, mock_matcher, mock_scorer, mock_storage, sample_cve, sample_asset_map, sample_blacklist
    ):
        """CVE com clientes impactados → deve alertar."""
        mock_storage.is_cve_sent.return_value = False
        mock_storage.acquire_cve_lock.return_value = True
        mock_scorer.enrich_cve.side_effect = lambda cve, bl: cve.update({"risk_tag": "HIGH"}) or cve
        mock_matcher.match_cve_to_clients.return_value = ["CLIENTE1", "CLIENTE2"]

        success, reason = should_alert(sample_cve, sample_asset_map, sample_blacklist)
        assert success is True
        assert "cliente(s) impactado(s)" in reason

    @patch("cve.pipeline.storage")
    @patch("cve.pipeline.risk_scorer")
    @patch("cve.pipeline.asset_matcher")
    def test_cve_without_matching_clients_non_critical_should_not_alert(
        self, mock_matcher, mock_scorer, mock_storage, sample_cve_low, sample_asset_map, sample_blacklist
    ):
        """CVE LOW sem match de ativos → não deve alertar."""
        mock_storage.is_cve_sent.return_value = False
        mock_storage.acquire_cve_lock.return_value = True
        mock_scorer.enrich_cve.side_effect = lambda cve, bl: cve.update({"risk_tag": "LOW"}) or cve
        mock_matcher.match_cve_to_clients.return_value = []

        success, reason = should_alert(sample_cve_low, sample_asset_map, sample_blacklist)
        assert success is False
        assert "sem match de ativos" in reason

    @patch("cve.pipeline.storage")
    @patch("cve.pipeline.risk_scorer")
    @patch("cve.pipeline.asset_matcher")
    def test_critical_without_clients_does_not_alert(
        self, mock_matcher, mock_scorer, mock_storage, sample_cve, sample_asset_map, sample_blacklist
    ):
        """CVE CRITICAL sem match de ativos → correlação é mandatória → não alerta."""
        mock_storage.is_cve_sent.return_value = False
        mock_storage.acquire_cve_lock.return_value = True
        mock_scorer.enrich_cve.side_effect = lambda cve, bl: cve.update({"risk_tag": "CRITICAL"}) or cve
        mock_matcher.match_cve_to_clients.return_value = []

        success, reason = should_alert(sample_cve, sample_asset_map, sample_blacklist)
        assert success is False
        assert "sem match de ativos" in reason

    @patch("cve.pipeline.storage")
    @patch("cve.pipeline.risk_scorer")
    @patch("cve.pipeline.asset_matcher")
    def test_blacklisted_cve_should_not_alert(
        self, mock_matcher, mock_scorer, mock_storage, sample_cve_blacklisted, sample_asset_map, sample_blacklist
    ):
        """CVE com produto blacklistado → LOG_ONLY → não deve alertar."""
        mock_storage.is_cve_sent.return_value = False
        mock_storage.acquire_cve_lock.return_value = True
        mock_scorer.enrich_cve.side_effect = lambda cve, bl: cve.update({"risk_tag": "LOG_ONLY"}) or cve
        # Pipeline exige match de ativos antes de checar blacklist
        mock_matcher.match_cve_to_clients.return_value = ["CLIENTE1"]

        success, reason = should_alert(sample_cve_blacklisted, sample_asset_map, sample_blacklist)
        assert success is False
        assert "blacklist" in reason

    @patch("cve.pipeline.storage")
    def test_already_sent_cve_should_not_alert(
        self, mock_storage, sample_cve, sample_asset_map, sample_blacklist
    ):
        """CVE já enviada → não deve alertar (deduplicação)."""
        mock_storage.is_cve_sent.return_value = True

        success, reason = should_alert(sample_cve, sample_asset_map, sample_blacklist)
        assert success is False
        assert reason == "já enviada"

    @patch("cve.pipeline.storage")
    def test_cve_in_processing_should_not_alert(
        self, mock_storage, sample_cve, sample_asset_map, sample_blacklist
    ):
        """CVE em processamento (race condition) → não deve alertar."""
        mock_storage.is_cve_sent.return_value = False
        mock_storage.acquire_cve_lock.return_value = False

        success, reason = should_alert(sample_cve, sample_asset_map, sample_blacklist)
        assert success is False
        assert reason == "já em processamento"
