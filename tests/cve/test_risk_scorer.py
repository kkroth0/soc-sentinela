"""
tests/cve/test_risk_scorer.py — Testes do scoring de risco.
Validação da ordem sagrada: blacklist → CISA KEV → EPSS → CVSS.
"""

import sys
import os
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from cve.risk_scorer import calculate_risk, _kev_cache


class TestCalculateRisk:
    """Testes da função principal de scoring."""

    @patch("cve.risk_scorer._refresh_kev_cache", return_value=None)
    @patch("cve.risk_scorer._fetch_epss", return_value=None)
    def test_blacklist_returns_log_only(self, mock_epss, mock_refresh, sample_cve_blacklisted, sample_blacklist):
        """Bug fix #1: Blacklist SEMPRE retorna LOG_ONLY, mesmo com CVSS 10.0."""
        result, reasons = calculate_risk(sample_cve_blacklisted, sample_blacklist)
        assert result == "LOG_ONLY"
        mock_refresh.assert_not_called()
        mock_epss.assert_not_called()

    @patch("cve.risk_scorer._refresh_kev_cache", return_value=None)
    @patch("cve.risk_scorer._fetch_epss", return_value=None)
    def test_cisa_kev_returns_critical(self, mock_epss, mock_refresh, sample_cve):
        """CISA KEV → CRITICAL (exploração ativa confirmada)."""
        cve_id = sample_cve["cve_id"]
        _kev_cache["cves"][cve_id] = {"ransomware": False}
        result, reasons = calculate_risk(sample_cve, [])
        assert result == "CRITICAL"
        _kev_cache["cves"].pop(cve_id, None)

    @patch("cve.risk_scorer._refresh_kev_cache", return_value=None)
    @patch("cve.risk_scorer._fetch_epss", return_value=0.78)
    def test_epss_high_bumps_severity(self, mock_epss, mock_refresh, sample_cve_low):
        """EPSS > 50% faz bump: LOW → MEDIUM."""
        result, reasons = calculate_risk(sample_cve_low, [])
        assert result == "MEDIUM"  # LOW bumped to MEDIUM

    @patch("cve.risk_scorer._refresh_kev_cache", return_value=None)
    @patch("cve.risk_scorer._fetch_epss", return_value=0.30)
    def test_normal_cvss_scoring(self, mock_epss, mock_refresh, sample_cve):
        """CVSS 9.8 sem KEV nem EPSS alto → CRITICAL pelo score."""
        result, reasons = calculate_risk(sample_cve, [])
        assert result == "CRITICAL"

    @patch("cve.risk_scorer._refresh_kev_cache", return_value=None)
    @patch("cve.risk_scorer._fetch_epss", return_value=0.10)
    def test_low_cvss_stays_low(self, mock_epss, mock_refresh, sample_cve_low):
        """CVSS 3.5 sem KEV nem EPSS alto → LOW."""
        result, reasons = calculate_risk(sample_cve_low, [])
        assert result == "LOW"

    @patch("cve.risk_scorer._refresh_kev_cache", return_value=None)
    @patch("cve.risk_scorer._fetch_epss", return_value=None)
    def test_blacklist_overrides_kev(self, mock_epss, mock_refresh, sample_cve_blacklisted, sample_blacklist):
        """Bug fix #2: Blacklist tem prioridade sobre CISA KEV."""
        result, reasons = calculate_risk(sample_cve_blacklisted, sample_blacklist)
        assert result == "LOG_ONLY"
        mock_refresh.assert_not_called()

    @patch("cve.risk_scorer._refresh_kev_cache", return_value=None)
    @patch("cve.risk_scorer._fetch_epss", return_value=0.60)
    def test_epss_bumps_high_to_critical(self, mock_epss, mock_refresh):
        """EPSS > 50% bumpa HIGH → CRITICAL."""
        cve = {"cve_id": "CVE-2026-5555", "cvss_score": 7.5, "product": "test"}
        result, reasons = calculate_risk(cve, [])
        assert result == "CRITICAL"  # HIGH bumped to CRITICAL

    def test_enrich_cve_extracts_threats(self):
        """Testa se a função enrich_cve mapeia ameaças corretamente."""
        from cve.risk_scorer import enrich_cve
        cve = {
            "cve_id": "CVE-2026-9999",
            "cvss_score": 9.8,
            "description": "A critical zero-day ransomware attack vectors targets Cisco systems.",
            "has_known_exploit": True,
            "cwes": ["CWE-79"]
        }
        
        # Simula presença em CISA KEV com ransomware e congela o cache
        import time
        _kev_cache["last_fetch"] = time.time()
        _kev_cache["cves"]["CVE-2026-9999"] = {"ransomware": True}
        
        try:
            enriched = enrich_cve(cve, [])
            threats = enriched.get("threats", [])
            assert "Exploração Ativa (CISA KEV)" in threats
            assert "Uso em Ransomware" in threats
            assert "Exploit Público Disponível" in threats
            assert "Ransomware" in threats
            assert "Zero-Day" in threats
            assert "Grupo APT" not in threats
        finally:
            _kev_cache["cves"].pop("CVE-2026-9999", None)
