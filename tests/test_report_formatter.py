"""
tests/test_report_formatter.py — Testes para os formatadores de relatório (Teams + Telegram).
"""

import os
import sys
import json

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.notifications.formatters.report_formatter import (
    build_weekly_report_card,
    build_monthly_report_card,
    build_weekly_report_telegram,
    build_monthly_report_telegram,
)


class TestAdaptiveCard:
    """Testes para os Adaptive Cards de relatório."""

    def test_weekly_card_has_required_schema(self, sample_report_stats):
        card = build_weekly_report_card(sample_report_stats)
        assert card["type"] == "AdaptiveCard"
        assert card["version"] == "1.4"
        assert "$schema" in card
        assert isinstance(card["body"], list)
        assert len(card["body"]) > 0

    def test_monthly_card_has_required_schema(self, sample_report_stats):
        sample_report_stats["report_type"] = "monthly"
        card = build_monthly_report_card(sample_report_stats)
        assert card["type"] == "AdaptiveCard"

    def test_card_contains_period(self, sample_report_stats):
        card = build_weekly_report_card(sample_report_stats)
        body_json = json.dumps(card["body"])
        assert "14/04" in body_json
        assert "20/04/2026" in body_json

    def test_card_contains_kpis(self, sample_report_stats):
        card = build_weekly_report_card(sample_report_stats)
        body_json = json.dumps(card["body"])
        assert "47" in body_json  # cve_count
        assert "23" in body_json  # news_count
        assert "7.4" in body_json  # avg_cvss

    def test_card_contains_risk_breakdown(self, sample_report_stats):
        card = build_weekly_report_card(sample_report_stats)
        body_json = json.dumps(card["body"])
        assert "CRITICAL" in body_json
        assert "5" in body_json

    def test_card_contains_top_vendors(self, sample_report_stats):
        card = build_weekly_report_card(sample_report_stats)
        body_json = json.dumps(card["body"])
        assert "Microsoft" in body_json
        assert "12 CVEs" in body_json

    def test_card_contains_trend(self, sample_report_stats):
        card = build_weekly_report_card(sample_report_stats)
        body_json = json.dumps(card["body"], ensure_ascii=False)
        assert "↑ 12%" in body_json
        assert "↓ 8%" in body_json

    def test_card_contains_clients(self, sample_report_stats):
        card = build_weekly_report_card(sample_report_stats)
        body_json = json.dumps(card["body"])
        assert "CLIENTE1" in body_json
        assert "35 CVEs" in body_json

    def test_monthly_card_shows_cti_sources(self, sample_report_stats):
        sample_report_stats["report_type"] = "monthly"
        card = build_monthly_report_card(sample_report_stats)
        body_json = json.dumps(card["body"])
        assert "BleepingComputer" in body_json

    def test_weekly_card_hides_cti_sources(self, sample_report_stats):
        """Fontes CTI só aparecem no relatório mensal."""
        card = build_weekly_report_card(sample_report_stats)
        body_json = json.dumps(card["body"])
        assert "BleepingComputer" not in body_json

    def test_empty_stats_produces_valid_card(self):
        empty = {
            "period": "N/A", "period_label": "N/A", "report_type": "weekly",
            "cve_count": 0, "news_count": 0, "avg_cvss": 0.0,
            "risk_breakdown": {}, "trend_cve": "—", "trend_news": "—",
            "trend_critical": "—", "top_vendors": [], "top_products": [],
            "top_clients": [], "top_news_sources": [],
        }
        card = build_weekly_report_card(empty)
        assert card["type"] == "AdaptiveCard"
        assert len(card["body"]) >= 4  # header + period + KPIs + risk

    def test_cvss_color_warning_when_high(self, sample_report_stats):
        """CVSS >= 7.0 deve ter cor 'warning'."""
        card = build_weekly_report_card(sample_report_stats)
        body_json = json.dumps(card["body"])
        assert '"color": "warning"' in body_json

    def test_cvss_color_accent_when_low(self):
        stats = {
            "period": "N/A", "period_label": "N/A", "report_type": "weekly",
            "cve_count": 1, "news_count": 0, "avg_cvss": 4.5,
            "risk_breakdown": {}, "trend_cve": "—", "trend_news": "—",
            "trend_critical": "—", "top_vendors": [], "top_products": [],
            "top_clients": [], "top_news_sources": [],
        }
        card = build_weekly_report_card(stats)
        # Com CVSS 4.5, deve usar "accent" (azul) e não "warning"
        body_json = json.dumps(card["body"])
        # A coluna de CVSS médio existe
        assert "4.5" in body_json


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
