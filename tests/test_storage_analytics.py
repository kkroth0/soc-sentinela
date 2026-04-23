"""
tests/test_storage_analytics.py — Testes para as queries analíticas do storage.
Usa banco SQLite em memória para velocidade máxima.
"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Precisa configurar o config ANTES de importar storage
import config
config.BOT_DB_PATH = ":memory:"

from core import storage


@pytest.fixture(autouse=True)
def reset_db():
    """Reseta a conexão e reinicializa o banco para cada teste."""
    storage.close_db()
    storage._connection = None
    storage.init_db()
    yield
    storage.close_db()


def _insert_cve(cve_id, vendor, product, risk_tag, cvss, clients, sent_at):
    """Helper para inserir CVE no banco."""
    storage.save_cve({
        "cve_id": cve_id,
        "vendor": vendor,
        "product": product,
        "risk_tag": risk_tag,
        "cvss_score": cvss,
        "severity": risk_tag,
        "impacted_clients": clients,
    })
    # Corrigir o sent_at manualmente para controlar o período
    conn = storage._get_connection()
    conn.execute("UPDATE sent_cves SET sent_at = ? WHERE cve_id = ?", (sent_at, cve_id))
    conn.commit()


def _insert_news(url, title, source, layer, sent_at):
    """Helper para inserir notícia no banco."""
    storage.save_news({
        "url": url,
        "title": title,
        "source": source,
        "layer": layer,
    })
    conn = storage._get_connection()
    conn.execute("UPDATE sent_news SET sent_at = ? WHERE article_url = ?", (sent_at, url))
    conn.commit()


class TestGetCvesByVendor:
    """Testes para get_cves_by_vendor()."""

    def test_returns_top5_vendors_ordered(self):
        for i in range(7):
            _insert_cve(f"CVE-MS-{i}", "microsoft", "windows", "HIGH", 8.0, ["C1"], "2026-04-15T10:00:00")
        for i in range(3):
            _insert_cve(f"CVE-CISCO-{i}", "cisco", "ios", "CRITICAL", 9.5, ["C1"], "2026-04-15T10:00:00")
        _insert_cve("CVE-FORT-0", "fortinet", "fortigate", "HIGH", 7.5, ["C2"], "2026-04-15T10:00:00")

        result = storage.get_cves_by_vendor("2026-04-01", "2026-04-30")
        assert len(result) == 3
        assert result[0]["vendor"] == "microsoft"
        assert result[0]["total"] == 7
        assert result[1]["vendor"] == "cisco"
        assert result[1]["total"] == 3

    def test_critical_and_high_breakdown(self):
        _insert_cve("CVE-1", "cisco", "ios", "CRITICAL", 9.8, [], "2026-04-15T10:00:00")
        _insert_cve("CVE-2", "cisco", "ios xe", "HIGH", 8.0, [], "2026-04-15T10:00:00")
        _insert_cve("CVE-3", "cisco", "router", "MEDIUM", 5.0, [], "2026-04-15T10:00:00")

        result = storage.get_cves_by_vendor("2026-04-01", "2026-04-30")
        assert result[0]["critical"] == 1
        assert result[0]["high"] == 1

    def test_excludes_empty_vendor(self):
        _insert_cve("CVE-NO-V", "", "mystery", "HIGH", 8.0, [], "2026-04-15T10:00:00")
        result = storage.get_cves_by_vendor("2026-04-01", "2026-04-30")
        assert len(result) == 0

    def test_respects_date_range(self):
        _insert_cve("CVE-IN", "cisco", "ios", "HIGH", 8.0, [], "2026-04-15T10:00:00")
        _insert_cve("CVE-OUT", "cisco", "ios", "HIGH", 8.0, [], "2026-03-01T10:00:00")

        result = storage.get_cves_by_vendor("2026-04-01", "2026-04-30")
        assert result[0]["total"] == 1

    def test_empty_period(self):
        result = storage.get_cves_by_vendor("2026-04-01", "2026-04-30")
        assert result == []


class TestGetCvesByProduct:
    """Testes para get_cves_by_product()."""

    def test_returns_products_with_avg_cvss(self):
        _insert_cve("CVE-1", "ms", "windows server", "CRITICAL", 9.0, [], "2026-04-15T10:00:00")
        _insert_cve("CVE-2", "ms", "windows server", "HIGH", 7.0, [], "2026-04-15T10:00:00")

        result = storage.get_cves_by_product("2026-04-01", "2026-04-30")
        assert result[0]["product"] == "windows server"
        assert result[0]["total"] == 2
        assert result[0]["avg_cvss"] == 8.0

    def test_excludes_empty_product(self):
        _insert_cve("CVE-1", "cisco", "", "HIGH", 8.0, [], "2026-04-15T10:00:00")
        result = storage.get_cves_by_product("2026-04-01", "2026-04-30")
        assert result == []


class TestGetMostImpactedClients:
    """Testes para get_most_impacted_clients()."""

    def test_counts_client_mentions(self):
        _insert_cve("CVE-1", "ms", "win", "HIGH", 8.0, ["ClienteA", "ClienteB"], "2026-04-15T10:00:00")
        _insert_cve("CVE-2", "cisco", "ios", "HIGH", 8.0, ["ClienteA"], "2026-04-15T10:00:00")

        result = storage.get_most_impacted_clients("2026-04-01", "2026-04-30")
        assert result[0]["client"] == "ClienteA"
        assert result[0]["count"] == 2
        assert result[1]["client"] == "ClienteB"
        assert result[1]["count"] == 1

    def test_empty_clients(self):
        _insert_cve("CVE-1", "ms", "win", "HIGH", 8.0, [], "2026-04-15T10:00:00")
        result = storage.get_most_impacted_clients("2026-04-01", "2026-04-30")
        assert result == []

    def test_limits_to_5(self):
        for i in range(8):
            _insert_cve(f"CVE-{i}", "ms", "win", "HIGH", 8.0, [f"Client{i}"], "2026-04-15T10:00:00")

        result = storage.get_most_impacted_clients("2026-04-01", "2026-04-30")
        assert len(result) == 5


class TestGetNewsBySource:
    """Testes para get_news_by_source()."""

    def test_returns_sources_ordered(self):
        for i in range(5):
            _insert_news(f"http://bc/{i}", f"News {i}", "BleepingComputer", 2, "2026-04-15T10:00:00")
        for i in range(2):
            _insert_news(f"http://thn/{i}", f"News {i}", "TheHackerNews", 2, "2026-04-15T10:00:00")

        result = storage.get_news_by_source("2026-04-01", "2026-04-30")
        assert result[0]["source"] == "BleepingComputer"
        assert result[0]["total"] == 5
        assert result[1]["source"] == "TheHackerNews"
        assert result[1]["total"] == 2


class TestGetAvgCvss:
    """Testes para get_avg_cvss()."""

    def test_calculates_average(self):
        _insert_cve("CVE-1", "ms", "win", "CRITICAL", 10.0, [], "2026-04-15T10:00:00")
        _insert_cve("CVE-2", "ms", "win", "HIGH", 8.0, [], "2026-04-15T10:00:00")

        result = storage.get_avg_cvss("2026-04-01", "2026-04-30")
        assert result == 9.0

    def test_empty_returns_zero(self):
        result = storage.get_avg_cvss("2026-04-01", "2026-04-30")
        assert result == 0.0


class TestSaveMonthSummary:
    """Testes para save_monthly_summary()."""

    def test_saves_and_replaces(self):
        stats = {
            "period": "2026-04",
            "cve_count": 10,
            "news_count": 5,
            "avg_cvss": 7.5,
            "risk_breakdown": {"CRITICAL": 2, "HIGH": 3, "MEDIUM": 4, "LOW": 1},
            "top_vendors": [{"vendor": "ms", "total": 5}],
            "top_products": [],
            "top_clients": [],
        }
        storage.save_monthly_summary(stats)

        # Salvar novamente com dados diferentes — deve fazer REPLACE
        stats["cve_count"] = 20
        storage.save_monthly_summary(stats)

        conn = storage._get_connection()
        row = conn.execute("SELECT cve_count FROM monthly_summary WHERE period_key = '2026-04'").fetchone()
        assert row["cve_count"] == 20


class TestCveStatsWithUntil:
    """Testes para get_cve_stats com parâmetro until."""

    def test_filters_by_range(self):
        _insert_cve("CVE-IN", "ms", "win", "CRITICAL", 9.8, [], "2026-04-15T10:00:00")
        _insert_cve("CVE-OUT", "ms", "win", "CRITICAL", 9.8, [], "2026-05-15T10:00:00")

        result = storage.get_cve_stats("2026-04-01", "2026-04-30")
        assert result.get("CRITICAL", 0) == 1

    def test_without_until_returns_all_after_since(self):
        _insert_cve("CVE-1", "ms", "win", "HIGH", 8.0, [], "2026-04-15T10:00:00")
        _insert_cve("CVE-2", "ms", "win", "HIGH", 8.0, [], "2026-05-15T10:00:00")

        result = storage.get_cve_stats("2026-04-01")
        assert result.get("HIGH", 0) == 2
