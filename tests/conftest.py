"""
tests/conftest.py — Fixtures compartilhadas entre os testes.
Estruturas atualizadas para refletir os tipos reais do sistema:
  - asset_map: dict[str, dict[str, Any]] com 'clients' e 'aliases'
  - blacklist: list[dict[str, Any]] com 'vendor', 'product', 'aliases'
"""

import os
import sys

import pytest

# Garantir que o root do projeto está no path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture
def sample_cve() -> dict:
    """CVE de exemplo com todos os campos."""
    return {
        "cve_id": "CVE-2026-9999",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "vendor": "cisco",
        "product": "ios xe",
        "description": "A critical vulnerability in Cisco IOS XE allows remote code execution.",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-9999",
        "date": "2026-04-01T10:00:00",
        "epss_score": None,
        "in_cisa_kev": False,
        "risk_tag": None,
        "impacted_clients": [],
        "translated": False,
    }


@pytest.fixture
def sample_cve_low() -> dict:
    """CVE de baixa severidade."""
    return {
        "cve_id": "CVE-2026-1111",
        "cvss_score": 3.5,
        "severity": "LOW",
        "vendor": "apache",
        "product": "http server",
        "description": "A low severity information disclosure vulnerability.",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-1111",
        "date": "2026-04-01T10:00:00",
        "epss_score": None,
        "in_cisa_kev": False,
        "risk_tag": None,
        "impacted_clients": [],
        "translated": False,
    }


@pytest.fixture
def sample_cve_blacklisted() -> dict:
    """CVE com produto na blacklist mas CVSS alto."""
    return {
        "cve_id": "CVE-2026-8888",
        "cvss_score": 10.0,
        "severity": "CRITICAL",
        "vendor": "wordpress",
        "product": "wordpress",
        "description": "Critical RCE in WordPress.",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-8888",
        "date": "2026-04-01T10:00:00",
        "epss_score": None,
        "in_cisa_kev": False,
        "risk_tag": None,
        "impacted_clients": [],
        "translated": False,
    }


@pytest.fixture
def sample_asset_map() -> dict[str, dict]:
    """Mapa de ativos com estrutura real (clients + aliases)."""
    return {
        "cisco:ios xe": {"clients": ["CLIENTE1", "CLIENTE2"], "aliases": ["ios-xe"]},
        "fortinet:fortigate": {"clients": ["CLIENTE1"], "aliases": ["fortigate-vm"]},
        "microsoft:windows server 2022": {"clients": ["CLIENTE1"], "aliases": ["win-server-2022", "windows server"]},
        "palo alto:pan-os": {"clients": ["CLIENTE2"], "aliases": ["panos"]},
        "vmware:esxi": {"clients": ["CLIENTE2"], "aliases": ["vsphere esxi"]},
        "apache:http server": {"clients": ["CLIENTE3"], "aliases": ["httpd", "apache2"]},
    }


@pytest.fixture
def sample_blacklist() -> list[dict]:
    """Blacklist com estrutura real (vendor + product + aliases)."""
    return [
        {"vendor": "", "product": "wordpress", "aliases": ["wp", "wordpress.org"]},
        {"vendor": "", "product": "drupal", "aliases": []},
        {"vendor": "", "product": "joomla", "aliases": []},
        {"vendor": "", "product": "phpmyadmin", "aliases": ["pma"]},
        {"vendor": "", "product": "magento", "aliases": []},
    ]


@pytest.fixture
def tmp_db_path(tmp_path):
    """Caminho temporário para banco SQLite de teste."""
    return str(tmp_path / "test_bot.db")


@pytest.fixture
def sample_report_stats() -> dict:
    """Stats completos de relatório para testes de formatação."""
    return {
        "period": "2026-W16",
        "period_label": "14/04 — 20/04/2026",
        "report_type": "weekly",
        "cve_count": 47,
        "news_count": 23,
        "avg_cvss": 7.4,
        "risk_breakdown": {
            "CRITICAL": 5,
            "HIGH": 18,
            "MEDIUM": 20,
            "LOW": 4,
        },
        "trend_cve": "↑ 12%",
        "trend_news": "↓ 8%",
        "trend_critical": "↑ novo",
        "top_vendors": [
            {"vendor": "microsoft", "total": 12, "critical": 3, "high": 5, "avg_cvss": 8.2},
            {"vendor": "cisco", "total": 8, "critical": 1, "high": 4, "avg_cvss": 7.5},
            {"vendor": "fortinet", "total": 6, "critical": 0, "high": 3, "avg_cvss": 7.1},
        ],
        "top_products": [
            {"product": "windows server 2022", "vendor": "microsoft", "total": 5, "avg_cvss": 8.2},
            {"product": "ios xe", "vendor": "cisco", "total": 4, "avg_cvss": 7.8},
        ],
        "top_clients": [
            {"client": "CLIENTE1", "count": 35},
            {"client": "CLIENTE2", "count": 12},
        ],
        "top_news_sources": [
            {"source": "BleepingComputer", "layer": 2, "total": 5},
            {"source": "TheHackerNews", "layer": 2, "total": 4},
        ],
    }
