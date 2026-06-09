"""
tests/test_report_formatter.py — Testes para os formatadores de relatório do Telegram.
"""

import os
import sys
import html as html_mod

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.notifications.formatters.report_formatter import (
    build_weekly_report_telegram,
    build_monthly_report_telegram,
)

class TestTelegramMessage:
    """Testes para as mensagens Telegram de relatório."""

    def test_weekly_telegram_contains_title(self, sample_report_stats):
        msg = build_weekly_report_telegram(sample_report_stats)
        assert "Relatório Semanal" in msg
        assert "<b>" in msg

    def test_monthly_telegram_contains_title(self, sample_report_stats):
        sample_report_stats["report_type"] = "monthly"
        msg = build_monthly_report_telegram(sample_report_stats)
        assert "Relatório Mensal" in msg

    def test_telegram_contains_kpis(self, sample_report_stats):
        msg = build_weekly_report_telegram(sample_report_stats)
        assert "47" in msg
        assert "23" in msg
        assert "7.4" in msg

    def test_telegram_contains_vendors(self, sample_report_stats):
        msg = build_weekly_report_telegram(sample_report_stats)
        assert "Microsoft" in msg
        assert "12 CVEs" in msg

    def test_telegram_contains_trend(self, sample_report_stats):
        msg = build_weekly_report_telegram(sample_report_stats)
        assert "↑ 12%" in msg

    def test_telegram_escapes_html(self):
        """Nomes com <script> devem ser escapados."""
        stats = {
            "period": "2026-W16", "period_label": "<script>alert(1)</script>",
            "report_type": "weekly", "cve_count": 0, "news_count": 0,
            "avg_cvss": 0.0, "risk_breakdown": {},
            "trend_cve": "—", "trend_news": "—", "trend_critical": "—",
            "top_vendors": [{"vendor": "<b>evil</b>", "total": 1, "critical": 0, "high": 0}],
            "top_products": [], "top_clients": [], "top_news_sources": [],
        }
        msg = build_weekly_report_telegram(stats)
        assert "<script>" not in msg
        assert "&lt;script&gt;" in msg

    def test_monthly_telegram_shows_sources(self, sample_report_stats):
        sample_report_stats["report_type"] = "monthly"
        msg = build_monthly_report_telegram(sample_report_stats)
        assert "BleepingComputer" in msg

    def test_weekly_telegram_hides_sources(self, sample_report_stats):
        msg = build_weekly_report_telegram(sample_report_stats)
        assert "BleepingComputer" not in msg

    def test_telegram_footer(self, sample_report_stats):
        msg = build_weekly_report_telegram(sample_report_stats)
        assert "SOC Sentinel" in msg
        assert "Monitoramento Automatizado" in msg
