"""
tests/cve/test_risk_scorer.py — Testes do scoring de risco.
Validação da ordem sagrada: blacklist → CISA KEV → EPSS → CVSS.
"""

import sys
import os
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from cve.risk_scorer import calculate_risk, _cvss_to_risk, _bump_severity


class TestCvssToRisk:
    """Testes da classificação CVSS → risk_tag."""

    def test_critical_threshold(self):
        assert _cvss_to_risk(9.0) == "CRITICAL"
        assert _cvss_to_risk(10.0) == "CRITICAL"

    def test_high_threshold(self):
        assert _cvss_to_risk(7.0) == "HIGH"
        assert _cvss_to_risk(8.9) == "HIGH"

    def test_medium_threshold(self):
        assert _cvss_to_risk(4.0) == "MEDIUM"
        assert _cvss_to_risk(6.9) == "MEDIUM"

    def test_low_threshold(self):
        assert _cvss_to_risk(3.9) == "LOW"
        assert _cvss_to_risk(0.0) == "LOW"

    def test_none_score(self):
        assert _cvss_to_risk(None) == "LOW"


class TestBumpSeverity:
    """Testes do bump de severidade (EPSS > 50%)."""

    def test_low_to_medium(self):
        assert _bump_severity("LOW") == "MEDIUM"

    def test_medium_to_high(self):
        assert _bump_severity("MEDIUM") == "HIGH"

    def test_high_to_critical(self):
        assert _bump_severity("HIGH") == "CRITICAL"

    def test_critical_stays_critical(self):
        assert _bump_severity("CRITICAL") == "CRITICAL"


class TestCalculateRisk:
    """Testes da função principal de scoring."""

    @patch("cve.risk_scorer._is_in_kev", return_value=False)
    @patch("cve.risk_scorer._fetch_epss", return_value=None)
    def test_blacklist_returns_log_only(self, mock_epss, mock_kev, sample_cve_blacklisted, sample_blacklist):
        """Bug fix #1: Blacklist SEMPRE retorna LOG_ONLY, mesmo com CVSS 10.0."""
        result = calculate_risk(sample_cve_blacklisted, sample_blacklist)
        assert result == "LOG_ONLY"
        # KEV e EPSS NÃO devem ser consultados para produtos blacklistados
        mock_kev.assert_not_called()
        mock_epss.assert_not_called()

    @patch("cve.risk_scorer._is_in_kev", return_value=True)
    @patch("cve.risk_scorer._fetch_epss", return_value=None)
    def test_cisa_kev_returns_critical(self, mock_epss, mock_kev, sample_cve):
        """CISA KEV → CRITICAL (exploração ativa confirmada)."""
        result = calculate_risk(sample_cve, [])
        assert result == "CRITICAL"

    @patch("cve.risk_scorer._is_in_kev", return_value=False)
    @patch("cve.risk_scorer._fetch_epss", return_value=0.78)
    def test_epss_high_bumps_severity(self, mock_epss, mock_kev, sample_cve_low):
        """EPSS > 50% faz bump: LOW → MEDIUM."""
        result = calculate_risk(sample_cve_low, [])
        assert result == "MEDIUM"  # LOW bumped to MEDIUM

    @patch("cve.risk_scorer._is_in_kev", return_value=False)
    @patch("cve.risk_scorer._fetch_epss", return_value=0.30)
    def test_normal_cvss_scoring(self, mock_epss, mock_kev, sample_cve):
        """CVSS 9.8 sem KEV nem EPSS alto → CRITICAL pelo score."""
        result = calculate_risk(sample_cve, [])
        assert result == "CRITICAL"

    @patch("cve.risk_scorer._is_in_kev", return_value=False)
    @patch("cve.risk_scorer._fetch_epss", return_value=0.10)
    def test_low_cvss_stays_low(self, mock_epss, mock_kev, sample_cve_low):
        """CVSS 3.5 sem KEV nem EPSS alto → LOW."""
        result = calculate_risk(sample_cve_low, [])
        assert result == "LOW"

    @patch("cve.risk_scorer._is_in_kev", return_value=True)
    @patch("cve.risk_scorer._fetch_epss", return_value=None)
    def test_blacklist_overrides_kev(self, mock_epss, mock_kev, sample_cve_blacklisted, sample_blacklist):
        """Bug fix #2: Blacklist tem prioridade sobre CISA KEV."""
        result = calculate_risk(sample_cve_blacklisted, sample_blacklist)
        assert result == "LOG_ONLY"
        # KEV NÃO deve ser consultado — blacklist para antes
        mock_kev.assert_not_called()

    @patch("cve.risk_scorer._is_in_kev", return_value=False)
    @patch("cve.risk_scorer._fetch_epss", return_value=0.60)
    def test_epss_bumps_high_to_critical(self, mock_epss, mock_kev):
        """EPSS > 50% bumpa HIGH → CRITICAL."""
        cve = {"cve_id": "CVE-2026-5555", "cvss_score": 7.5, "product": "test"}
        result = calculate_risk(cve, [])
        assert result == "CRITICAL"  # HIGH bumped to CRITICAL
