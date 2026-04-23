"""
tests/cti/test_rss_client.py — Testes de Integração para a Ingestão de RSS.
Simula feeds válidos e inválidos retornados pela biblioteca feedparser.
"""

import pytest
from unittest.mock import patch, MagicMock

from cti.rss_client import fetch_recent_articles


@patch("cti.rss_client.requests.get")
@patch("cti.rss_client.feedparser.parse")
def test_fetch_recent_articles_success(mock_parse, mock_requests_get):
    """Testa se o cliente processa corretamente um feed simulado."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.content = b"<xml></xml>"
    mock_requests_get.return_value = mock_resp
    
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).timetuple()
    
    entry1 = {
        "title": "Critical Zero-Day in Microsoft Windows",
        "link": "https://thehackernews.com/article1",
        "summary": "<p>A critical zero-day vulnerability was found...</p>",
        "published_parsed": now
    }
    
    entry2 = {
        "title": "Old News",
        "link": "https://thehackernews.com/old",
        "summary": "This is old.",
        "published_parsed": (2000, 1, 1, 0, 0, 0, 0, 0, 0)
    }
    
    from feedparser import FeedParserDict
    
    mock_feed = FeedParserDict(
        bozo=0,
        feed=FeedParserDict(title="The Hacker News", link="https://thehackernews.com"),
        entries=[FeedParserDict(entry1), FeedParserDict(entry2)]
    )
    mock_parse.return_value = mock_feed
    
    with patch("cti.rss_client.RSS_FEEDS", [{"source": "THN", "url": "https://test", "layer": 1}]):
        with patch("cti.rss_client.config.NEWS_TIME_WINDOW_MINUTES", 60 * 24 * 30): # janela grande para garantir
            articles = fetch_recent_articles()
            
            # Apenas a entry1 deve passar no filtro de data
            assert len(articles) == 1
            assert articles[0]["title"] == "Critical Zero-Day in Microsoft Windows"
            assert articles[0]["url"] == "https://thehackernews.com/article1"
            assert articles[0]["layer"] == 1


@patch("cti.rss_client.requests.get")
@patch("cti.rss_client.feedparser.parse")
def test_fetch_recent_articles_bozo_exception(mock_parse, mock_requests_get):
    """Testa se o cliente ignora feeds quebrados (bozo_exception)."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.content = b"not xml"
    mock_requests_get.return_value = mock_resp

    mock_feed = MagicMock()
    mock_feed.bozo = 1
    mock_feed.bozo_exception = Exception("Malformed XML")
    mock_parse.return_value = mock_feed

    with patch("cti.rss_client.RSS_FEEDS", [{"source": "Broken", "url": "https://test", "layer": 1}]):
        articles = fetch_recent_articles()
        assert len(articles) == 0
