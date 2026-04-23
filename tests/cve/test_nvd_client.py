import sys
import os
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from cve.nvd_client import fetch_recent_cves, _parse_cve

class TestNvdClient:
    """Testes do cliente NVD API."""

    @patch("cve.nvd_client.http_client.get")
    def test_fetch_cves_pagination(self, mock_get):
        """Testa se o cliente faz paginação corretamente até buscar todos os resultados."""
        # Mock de 3 páginas: 50 + 50 + 20 = 120 resultados totais
        
        # Página 1
        page1 = {
            "totalResults": 120,
            "vulnerabilities": [{"cve": {"id": f"CVE-2026-{i}", "metrics": {}}} for i in range(50)]
        }
        # Página 2
        page2 = {
            "totalResults": 120,
            "vulnerabilities": [{"cve": {"id": f"CVE-2026-{i}", "metrics": {}}} for i in range(50, 100)]
        }
        # Página 3
        page3 = {
            "totalResults": 120,
            "vulnerabilities": [{"cve": {"id": f"CVE-2026-{i}", "metrics": {}}} for i in range(100, 120)]
        }

        indices_chamados = []
        def capture_params(*args, **kwargs):
            indices_chamados.append(kwargs.get('params', {}).get('startIndex'))
            return MagicMock(status_code=200, json=lambda: [page1, page2, page3][len(indices_chamados)-1])

        mock_get.side_effect = capture_params

        with patch("cve.nvd_client.time.sleep"): # Evitar delays no teste
            results = fetch_recent_cves(time_window_minutes=60)

        assert len(results) == 120
        assert mock_get.call_count == 3
        # Verifica se o startIndex incrementou corretamente
        assert indices_chamados == [0, 50, 100]

    def test_parse_cve_minimal_data(self):
        """Testa o parse de uma CVE com dados mínimos."""
        cve_data = {
            "id": "CVE-2026-9999",
            "descriptions": [{"lang": "en", "value": "A test vulnerability"}],
            "metrics": {
                "cvssMetricV31": [{
                    "cvssData": {
                        "baseScore": 9.8,
                        "baseSeverity": "CRITICAL"
                    }
                }]
            }
        }
        parsed = _parse_cve(cve_data)
        assert parsed["cve_id"] == "CVE-2026-9999"
        assert parsed["cvss_score"] == 9.8
        assert parsed["severity"] == "CRITICAL"
        assert parsed["description"] == "A test vulnerability"

    @patch("cve.nvd_client.config")
    def test_filter_by_min_cvss(self, mock_config):
        """Testa se CVEs abaixo do score mínimo são ignoradas."""
        mock_config.MIN_CVSS_SCORE = 7.0
        cve_data = {
            "id": "CVE-2026-low",
            "metrics": {
                "cvssMetricV31": [{
                    "cvssData": {"baseScore": 4.5}
                }]
            }
        }
        parsed = _parse_cve(cve_data)
        assert parsed is None

    def test_extract_cpe_info(self):
        """Testa a extração de vendor e produto do CPE."""
        cve_data = {
            "id": "CVE-2026-cpe",
            "configurations": [{
                "nodes": [{
                    "cpeMatch": [{
                        "criteria": "cpe:2.3:a:microsoft:exchange_server:2019:*:*:*:*:*:*:*"
                    }]
                }]
            }]
        }
        parsed = _parse_cve(cve_data)
        assert parsed["vendor"] == "microsoft"
        assert parsed["product"] == "exchange server"

    @patch("cve.nvd_client.http_client.get")
    def test_nvd_api_error_handling(self, mock_get):
        """Testa como o cliente lida com erros HTTP da API NVD."""
        mock_get.return_value = MagicMock(status_code=403, text="Forbidden")
        
        results = fetch_recent_cves()
        assert results == []
