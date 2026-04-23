"""
tests/core/test_formatters.py — Testes de Contrato para Teams (JSON) e Telegram (HTML).
"""

import pytest
from core.notifications.formatters.cve_formatter import build_cve_card, build_cve_telegram_message
from core.notifications.formatters.cti_formatter import build_news_card, build_news_telegram_message


def test_build_cve_card_contract():
    """Testa se o AdaptiveCard gerado para o Teams segue o contrato estrutural."""
    cve_dict = {
        "cve_id": "CVE-2026-1234",
        "cvss_score": 9.8,
        "risk_tag": "CRITICAL",
        "vendor": "Microsoft",
        "product": "Windows",
        "description": "A bad vulnerability.",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-1234",
        "impacted_clients": ["Client A", "Client B"],
        "epss_score": 0.85,
        "in_cisa_kev": True
    }

    card = build_cve_card(cve_dict)

    # Validar Schema Básico
    assert card["$schema"] == "http://adaptivecards.io/schemas/adaptive-card.json"
    assert card["type"] == "AdaptiveCard"
    assert card["version"] == "1.4"
    assert "body" in card

    # Validar se o título está presente no body
    body_text = str(card["body"])
    assert "CVE-2026-1234" in body_text
    assert "CRITICAL" in body_text
    assert "Client A" in body_text
    assert "Client B" in body_text
    assert "KEV" in body_text


def test_build_cve_telegram_contract():
    """Testa se o HTML do Telegram para CVE escapa as tags e possui a formatação correta."""
    cve_dict = {
        "cve_id": "CVE-2026-5678",
        "cvss_score": 5.5,
        "risk_tag": "MEDIUM",
        "vendor": "Linux",
        "product": "Kernel < 6.0", # Testando escape HTML
        "description": "Test description",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-5678",
        "impacted_clients": ["Client X"],
        "epss_score": 0.1,
        "in_cisa_kev": False
    }

    html = build_cve_telegram_message(cve_dict)

    assert "<b>🔵 CVE-2026-5678</b> (MEDIUM)" in html
    assert "CVE-2026-5678" in html
    assert "Kernel &Lt; 6.0" in html
    assert "Client X" in html
    assert "<a href='https://nvd.nist.gov/vuln/detail/CVE-2026-5678'>Ver no NVD</a>" in html


def test_build_news_card_contract():
    """Testa contrato do AdaptiveCard para notícias CTI."""
    news_dict = {
        "title": "Hackers attack <script>alert(1)</script>",
        "summary": "This is a summary of the attack.",
        "url": "https://example.com/news",
        "source": "DarkReading",
        "layer": 3,
        "date": "2026-04-23"
    }

    card = build_news_card(news_dict)

    body_text = str(card["body"])
    assert "Hackers attack" in body_text
    assert "DarkReading" in body_text
    assert "This is a summary of the attack." in body_text


def test_build_news_telegram_contract():
    """Testa contrato HTML do Telegram para notícias CTI."""
    news_dict = {
        "title": "Hackers attack <script>alert(1)</script>",
        "summary": "This is a summary of the attack.",
        "url": "https://example.com/news",
        "source": "DarkReading",
        "layer": 3,
        "date": "2026-04-23"
    }

    html = build_news_telegram_message(news_dict)

    assert "<b>🔵 Threat Intelligence</b>" in html
    assert "Hackers attack &lt;script&gt;alert(1)&lt;/script&gt;" in html # Escape OK
    assert "This is a summary of the attack." in html
    assert "<a href='https://example.com/news'>Ler artigo completo</a>" in html
