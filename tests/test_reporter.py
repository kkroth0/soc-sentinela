"""
tests/test_reporter.py — Testes para o motor de relatórios (reporter.py).
Testa cálculo de períodos, tendência temporal, e agregação.
"""

import os
import sys
from datetime import datetime, timezone
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reports.reporter import (
    _build_period_label,
    _calc_trend,
    _get_week_range,
    _get_previous_week_range,
    _get_month_range,
    _get_previous_month_range,
)


class TestCalcTrend:
    """Testes para _calc_trend()."""

    def test_increase(self):
        assert _calc_trend(12, 10) == "↑ 20%"

    def test_decrease(self):
        assert _calc_trend(8, 10) == "↓ 20%"

    def test_no_change(self):
        assert _calc_trend(10, 10) == "→ 0%"

    def test_from_zero_to_nonzero(self):
        assert _calc_trend(5, 0) == "↑ novo"

    def test_zero_to_zero(self):
        assert _calc_trend(0, 0) == "—"

    def test_large_increase(self):
        result = _calc_trend(100, 10)
        assert "↑" in result
        assert "900%" in result

    def test_100_percent_drop(self):
        result = _calc_trend(0, 10)
        assert "↓ 100%" in result

    def test_50_percent_drop(self):
        result = _calc_trend(5, 10)
        assert "↓ 50%" in result


class TestBuildPeriodLabel:
    """Testes para _build_period_label()."""

    def test_formats_correctly(self):
        result = _build_period_label("2026-04-14T00:00:00+00:00", "2026-04-20T23:59:59+00:00")
        assert "14/04" in result
        assert "20/04/2026" in result

    def test_invalid_iso_returns_empty(self):
        result = _build_period_label("not-a-date", "also-not")
        assert result == ""

    def test_same_day(self):
        result = _build_period_label("2026-01-01T00:00:00+00:00", "2026-01-01T23:59:59+00:00")
        assert "01/01" in result


class TestWeekRange:
    """Testes para _get_week_range e _get_previous_week_range."""

    @patch("reports.reporter.datetime")
    def test_week_range_returns_last_week(self, mock_dt):
        # Simula quarta-feira 2026-04-22
        mock_now = datetime(2026, 4, 22, 12, 0, 0, tzinfo=timezone.utc)
        mock_dt.now.return_value = mock_now
        mock_dt.side_effect = lambda *a, **kw: datetime(*a, **kw)

        period, start, end = _get_week_range()
        assert "W" in period
        assert start < end

    @patch("reports.reporter.datetime")
    def test_previous_week_is_before_current_week(self, mock_dt):
        mock_now = datetime(2026, 4, 22, 12, 0, 0, tzinfo=timezone.utc)
        mock_dt.now.return_value = mock_now
        mock_dt.side_effect = lambda *a, **kw: datetime(*a, **kw)

        _, cur_start, _ = _get_week_range()
        _, prev_start, _ = _get_previous_week_range()
        assert prev_start < cur_start


class TestMonthRange:
    """Testes para _get_month_range e _get_previous_month_range."""

    @patch("reports.reporter.datetime")
    def test_month_range_returns_previous_month(self, mock_dt):
        # Simula 2026-05-01 (deve retornar abril)
        mock_now = datetime(2026, 5, 1, 8, 0, 0, tzinfo=timezone.utc)
        mock_dt.now.return_value = mock_now
        mock_dt.side_effect = lambda *a, **kw: datetime(*a, **kw)

        period, start, end = _get_month_range()
        assert period == "2026-04"

    @patch("reports.reporter.datetime")
    def test_previous_month_is_two_ago(self, mock_dt):
        mock_now = datetime(2026, 5, 1, 8, 0, 0, tzinfo=timezone.utc)
        mock_dt.now.return_value = mock_now
        mock_dt.side_effect = lambda *a, **kw: datetime(*a, **kw)

        period, _, _ = _get_previous_month_range()
        assert period == "2026-03"

    @patch("reports.reporter.datetime")
    def test_january_wraps_to_previous_year(self, mock_dt):
        mock_now = datetime(2026, 1, 1, 8, 0, 0, tzinfo=timezone.utc)
        mock_dt.now.return_value = mock_now
        mock_dt.side_effect = lambda *a, **kw: datetime(*a, **kw)

        period, _, _ = _get_month_range()
        assert period == "2025-12"
