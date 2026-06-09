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


def _insert_news(url, title, source, layer, sent_at, status="SENT"):
    """Helper para inserir notícia no banco."""
    storage.save_news({
        "url": url,
        "title": title,
        "source": source,
        "layer": layer,
    }, status=status)
    conn = storage._get_connection()
    norm_url = url.replace("https://", "").replace("http://", "").replace("www.", "").rstrip("/").lower()
    conn.execute("UPDATE sent_news SET sent_at = ? WHERE article_url = ?", (sent_at, norm_url))
    conn.commit()


class TestGetReportStats:
    """Testes para get_report_stats()."""

    def test_calculates_stats_correctly(self):
        _insert_cve("CVE-1", "microsoft", "windows", "HIGH", 8.0, ["C1"], "2026-04-15T10:00:00")
        _insert_cve("CVE-2", "cisco", "ios", "CRITICAL", 9.5, ["C1", "C2"], "2026-04-16T10:00:00")
        _insert_news("http://bc/1", "News 1", "BleepingComputer", 2, "2026-04-17T10:00:00")

        stats = storage.get_report_stats("2026-04-01", "2026-05-01")
        assert stats["total_cves"] == 2
        assert stats["avg_cvss"] == 8.8
        assert stats["total_news"] == 1
        assert stats["risk_distribution"]["CRITICAL"] == 1
        assert stats["risk_distribution"]["HIGH"] == 1
        assert len(stats["top_vendors"]) == 2
        assert stats["top_vendors"][0]["vendor"] in ("microsoft", "cisco")
        assert len(stats["top_clients"]) == 2


class TestGetRecentCves:
    """Testes para get_recent_cves()."""

    def test_returns_recent_cves_ordered(self):
        _insert_cve("CVE-1", "ms", "win", "HIGH", 8.0, [], "2026-04-15T10:00:00")
        _insert_cve("CVE-2", "ms", "win", "CRITICAL", 9.8, [], "2026-04-16T10:00:00")

        recent = storage.get_recent_cves(limit=5)
        assert len(recent) == 2
        assert recent[0]["cve_id"] == "CVE-2"
        assert recent[1]["cve_id"] == "CVE-1"


class TestGetRecentNews:
    """Testes para get_recent_news()."""

    def test_returns_recent_news_ordered(self):
        _insert_news("http://bc/1", "News 1", "BC", 2, "2026-04-15T10:00:00", status="SENT")
        _insert_news("http://bc/2", "News 2", "BC", 2, "2026-04-16T10:00:00", status="SENT")
        _insert_news("http://bc/3", "News 3", "BC", 2, "2026-04-17T10:00:00", status="SKIPPED")

        recent = storage.get_recent_news(limit=5)
        # Deve retornar apenas status = 'SENT'
        assert len(recent) == 2
        assert recent[0]["title"] == "News 2"
        assert recent[1]["title"] == "News 1"


class TestGetCvesForMonth:
    """Testes para get_cves_for_month()."""

    def test_filters_by_month(self):
        _insert_cve("CVE-1", "ms", "win", "HIGH", 8.0, [], "2026-04-15T10:00:00")
        _insert_cve("CVE-2", "ms", "win", "HIGH", 8.0, [], "2026-05-15T10:00:00")

        result = storage.get_cves_for_month("2026-04")
        assert len(result) == 1
        assert result[0]["cve_id"] == "CVE-1"


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
