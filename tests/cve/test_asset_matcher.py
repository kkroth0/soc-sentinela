"""
tests/cve/test_asset_matcher.py — Testes do cruzamento CVE × ativos de clientes.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from cve.asset_matcher import match_cve_to_clients


class TestMatchCveToClients:
    """Testes de correspondência CVE × ativos."""

    def test_exact_match(self, sample_asset_map):
        """Match exato: vendor:product encontrado no asset_map."""
        cve = {"cve_id": "CVE-2026-0001", "vendor": "cisco", "product": "ios xe"}
        result = match_cve_to_clients(cve, sample_asset_map)
        assert sorted(result) == ["CLIENTE1", "CLIENTE2"]

    def test_case_insensitive_match(self, sample_asset_map):
        """Match case-insensitive: Cisco/IOS XE → cisco:ios xe."""
        cve = {"cve_id": "CVE-2026-0002", "vendor": "Cisco", "product": "IOS XE"}
        result = match_cve_to_clients(cve, sample_asset_map)
        assert sorted(result) == ["CLIENTE1", "CLIENTE2"]

    def test_no_match(self, sample_asset_map):
        """Sem match: vendor/product não encontrado."""
        cve = {"cve_id": "CVE-2026-0003", "vendor": "unknown", "product": "unknown product"}
        result = match_cve_to_clients(cve, sample_asset_map)
        assert result == []

    def test_empty_asset_map(self):
        """Asset map vazio → sem match."""
        cve = {"cve_id": "CVE-2026-0004", "vendor": "cisco", "product": "ios xe"}
        result = match_cve_to_clients(cve, {})
        assert result == []

    def test_empty_vendor_product(self, sample_asset_map):
        """CVE sem vendor/product → sem match."""
        cve = {"cve_id": "CVE-2026-0005", "vendor": "", "product": ""}
        result = match_cve_to_clients(cve, sample_asset_map)
        assert result == []

    def test_single_client_match(self, sample_asset_map):
        """Match com apenas um cliente."""
        cve = {"cve_id": "CVE-2026-0006", "vendor": "fortinet", "product": "fortigate"}
        result = match_cve_to_clients(cve, sample_asset_map)
        assert result == ["CLIENTE1"]

    def test_partial_product_match(self, sample_asset_map):
        """Match parcial: 'http server' no product."""
        cve = {"cve_id": "CVE-2026-0007", "vendor": "apache", "product": "http server"}
        result = match_cve_to_clients(cve, sample_asset_map)
        assert result == ["CLIENTE3"]

    def test_result_is_sorted(self, sample_asset_map):
        """Resultado deve ser ordenado alfabeticamente."""
        cve = {"cve_id": "CVE-2026-0008", "vendor": "cisco", "product": "ios xe"}
        result = match_cve_to_clients(cve, sample_asset_map)
        assert result == sorted(result)

    def test_no_duplicate_clients(self, sample_asset_map):
        """Não deve ter clientes duplicados no resultado."""
        cve = {"cve_id": "CVE-2026-0009", "vendor": "cisco", "product": "ios xe"}
        result = match_cve_to_clients(cve, sample_asset_map)
        assert len(result) == len(set(result))
