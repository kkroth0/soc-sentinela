"""Testes da extração de referências externas (cti.scrapling_client._extract_references)."""

from cti.scrapling_client import _extract_references


class _FakeResult:
    def __init__(self, hrefs):
        self._hrefs = hrefs

    def getall(self):
        return self._hrefs


class _FakeBlock:
    """Simula um bloco do Scrapling com .css('a::attr(href)')."""
    def __init__(self, hrefs):
        self._hrefs = hrefs

    def css(self, _selector):
        return _FakeResult(self._hrefs)


BASE = "https://www.bleepingcomputer.com/news/security/incident/"


def test_keeps_external_references():
    block = _FakeBlock([
        "https://www.reddit.com/r/sysadmin/comments/abc/",
        "https://www.servicenow.com/trust/security-advisories.html",
    ])
    refs = _extract_references([block], BASE)
    assert refs == [
        "https://www.reddit.com/r/sysadmin/comments/abc/",
        "https://www.servicenow.com/trust/security-advisories.html",
    ]


def test_drops_internal_links():
    block = _FakeBlock(["https://www.bleepingcomputer.com/news/other-article/"])
    assert _extract_references([block], BASE) == []


def test_drops_share_and_tracking():
    block = _FakeBlock([
        "https://twitter.com/intent/tweet?url=x",
        "https://www.facebook.com/sharer/sharer.php?u=x",
        "https://example.com/page?utm_source=feed",
    ])
    assert _extract_references([block], BASE) == []


def test_dedups_and_respects_limit():
    block = _FakeBlock([f"https://site{i}.com/a" for i in range(10)] + ["https://site0.com/a"])
    refs = _extract_references([block], BASE, limit=6)
    assert len(refs) == 6
    assert len(set(refs)) == 6


def test_ignores_non_http():
    block = _FakeBlock(["mailto:a@b.com", "javascript:void(0)", "/relative/path"])
    assert _extract_references([block], BASE) == []
