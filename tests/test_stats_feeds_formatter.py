"""Testes dos formatters de /stats e /feeds + sanidade do FAQ."""

from core.notifications.formatters.report_formatter import (
    build_stats_telegram,
    build_feeds_telegram,
)
from commands.faq_content import FAQ


def test_stats_renders_volume_and_risk():
    stats = {
        "total_cves": 12, "total_news": 30, "avg_cvss": 7.4,
        "risk_distribution": {"CRITICAL": 3, "HIGH": 5, "MEDIUM": 4, "LOW": 0},
        "top_vendors": [{"vendor": "microsoft", "total": 6}],
        "top_clients": [{"client": "SOC", "count": 9}],
        "top_sources": [{"source": "BleepingComputer", "total": 8}],
    }
    msg = build_stats_telegram(stats, "Last 7 days")
    assert "Last 7 days" in msg
    assert "CVEs alerted: <b>12</b>" in msg
    assert "MICROSOFT" in msg and "BleepingComputer" in msg
    assert "kkroth0" in msg  # assinatura


def test_stats_handles_empty():
    msg = build_stats_telegram({}, "Last 30 days")
    assert "CVEs alerted: <b>0</b>" in msg


def test_feeds_counts_and_flags_problems():
    rows = [
        {"source": "CISA", "layer": 1, "status": "WAF-BYPASS", "entries": 30},
        {"source": "OK Feed", "layer": 2, "status": "OK", "entries": 10},
        {"source": "Dead Feed", "layer": 3, "status": "FAIL", "entries": 0},
    ]
    msg = build_feeds_telegram(rows)
    assert "Operational: <b>2/3</b>" in msg
    assert "WAF bypass active" in msg and "CISA" in msg
    assert "Dead Feed — FAIL" in msg


def test_feeds_all_operational():
    rows = [{"source": "A", "layer": 1, "status": "OK", "entries": 5}]
    msg = build_feeds_telegram(rows)
    assert "Operational: <b>1/1</b>" in msg
    assert "All feeds operational." in msg


def test_faq_content_is_well_formed():
    assert len(FAQ) >= 5
    for tid, (label, body) in FAQ.items():
        assert isinstance(label, str) and label
        assert isinstance(body, str) and len(body) > 20
