import sys
import os
import json
import pytest
import threading
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from cve.nvd_client import fetch_recent_cves, _parse_cve

class TestNvdClient:
    """Testes do cliente NVD API."""

    @patch("cve.nvd_client.http_client.get")
    def test_fetch_cves_pagination(self, mock_get):
        """Testa se o cliente faz paginação corretamente até buscar todos os resultados."""
        # Mock de 2 páginas: 100 + 20 = 120 resultados totais
        
        probe_response = {
            "totalResults": 120,
            "vulnerabilities": [{"cve": {"id": "CVE-2026-probe", "metrics": {}}}]
        }
        page1 = {
            "totalResults": 120,
            "vulnerabilities": [{"cve": {"id": f"CVE-2026-{i}", "metrics": {}}} for i in range(100)]
        }
        page2 = {
            "totalResults": 120,
            "vulnerabilities": [{"cve": {"id": f"CVE-2026-{i}", "metrics": {}}} for i in range(100, 120)]
        }

        calls_dict = {}
        calls_lock = threading.Lock()

        def capture_params(*args, **kwargs):
            params = kwargs.get('params', {})
            r_per_page = params.get('resultsPerPage')
            start_idx = params.get('startIndex', 0)
            
            with calls_lock:
                calls_dict[start_idx] = calls_dict.get(start_idx, 0) + 1
            
            if r_per_page == 1:
                return MagicMock(status_code=200, json=lambda: probe_response)
            elif start_idx == 0:
                return MagicMock(status_code=200, json=lambda: page1)
            elif start_idx == 100:
                return MagicMock(status_code=200, json=lambda: page2)
            else:
                return MagicMock(status_code=200, json=lambda: {"totalResults": 120, "vulnerabilities": []})

        mock_get.side_effect = capture_params

        with patch("cve.nvd_client.time.sleep"), patch("cve.nvd_client.storage") as mock_storage:
            results = fetch_recent_cves(time_window_minutes=60)

        assert len(results) == 120
        assert mock_get.call_count == 3
        assert 100 in calls_dict
        assert 0 in calls_dict

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

    @patch("cve.nvd_client.http_client.get")
    def test_nvd_api_json_decode_error_skip(self, mock_get):
        """Testa se o cliente pula páginas com JSON quebrado e extrai o totalResults via regex."""
        probe_response = MagicMock(status_code=200)
        probe_response.json.return_value = {"totalResults": 60}

        page2 = {
            "totalResults": 60,
            "vulnerabilities": [{"cve": {"id": f"CVE-2026-{i}", "metrics": {}}} for i in range(30, 60)]
        }

        def mock_json_decode_error():
            raise json.JSONDecodeError("Expecting value", "", 0)

        mock_response_1 = MagicMock(status_code=200, text='{"totalResults": 60, "vul')
        mock_response_1.json.side_effect = mock_json_decode_error
        
        mock_response_2 = MagicMock(status_code=200, text=json.dumps(page2))
        mock_response_2.json.return_value = page2

        # Temporariamente ajustar o tamanho da página para bater com o mock
        import cve.nvd_client
        original_page_size = cve.nvd_client._RESULTS_PER_PAGE
        cve.nvd_client._RESULTS_PER_PAGE = 30

        def capture_params(*args, **kwargs):
            params = kwargs.get('params', {})
            r_per_page = params.get('resultsPerPage')
            start_idx = params.get('startIndex', 0)
            
            if r_per_page == 1:
                return probe_response
            elif start_idx == 0:
                return mock_response_1
            elif start_idx == 30:
                return mock_response_2
            else:
                empty_response = MagicMock(status_code=200)
                empty_response.json.return_value = {"totalResults": 60, "vulnerabilities": []}
                return empty_response

        mock_get.side_effect = capture_params

        try:
            with patch("cve.nvd_client.time.sleep"), patch("cve.nvd_client.storage"):
                results = fetch_recent_cves(time_window_minutes=60)
        finally:
            cve.nvd_client._RESULTS_PER_PAGE = original_page_size

        # Deve ter pulado a primeira página (perdendo 30), mas pegado a segunda página com 30 itens.
        assert len(results) == 30
        assert mock_get.call_count == 8
