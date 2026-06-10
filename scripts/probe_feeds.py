"""Sonda URLs candidatas de feeds bloqueados, do mesmo ambiente da produção.
Testa fetch direto (UA de browser) e, se falhar/!=RSS, o bypass Scrapling.
Reporta: HTTP status, nº de entries do feedparser, e se precisou de bypass.
"""
import sys
import feedparser
from cti.rss_client import _fetch_via_scrapling
from core.clients import http_client

CANDIDATES = {
    "Cisco Talos": [
        "https://feeds.feedburner.com/feedburner/Talos",
        "https://blog.talosintelligence.com/feeds/posts/default?alt=rss",
        "https://blog.talosintelligence.com/rss/",
    ],
    "Proofpoint": [
        "https://www.proofpoint.com/us/rss.xml",
        "https://www.proofpoint.com/us/threat-insight/rss.xml",
    ],
    "SentinelOne": [
        "https://www.sentinelone.com/feed/",
        "https://www.sentinelone.com/labs/feed/",
        "https://s1.ai/blog-rss",
    ],
    "Malwarebytes": [
        "https://www.malwarebytes.com/blog/feed/",
        "https://blog.malwarebytes.com/feed/",
    ],
    "Volexity": [
        "https://www.volexity.com/feed/",
        "https://www.volexity.com/blog/feed/",
    ],
    "IBM Security Intelligence": [
        "https://securityintelligence.com/feed/",
        "https://securityintelligence.com/category/x-force/feed/",
    ],
    "Packet Storm": [
        "https://packetstormsecurity.com/rss/news/",
        "https://packetstormsecurity.com/feeds/news/",
        "https://rss.packetstormsecurity.com/news/",
        "https://packetstormsecurity.com/headlines.xml",
    ],
}

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")


def probe(url):
    status = "?"
    raw = None
    via = "direct"
    try:
        resp = http_client.get(url, timeout=15, headers={"User-Agent": UA}, use_retry=False)
        status = resp.status_code
        if resp.status_code == 200:
            raw = resp.content
        else:
            raw = _fetch_via_scrapling(url)
            via = "scrapling"
    except Exception as exc:
        status = f"EXC:{type(exc).__name__}"
        raw = _fetch_via_scrapling(url)
        via = "scrapling"

    if not raw:
        return f"  [{status:>10}] {url}\n      -> SEM CORPO (bypass tbm falhou)"

    feed = feedparser.parse(raw)
    n = len(feed.entries)
    # Se 0 entries no fetch direto, tenta o bypass tbm
    if n == 0 and via == "direct":
        raw2 = _fetch_via_scrapling(url)
        if raw2:
            f2 = feedparser.parse(raw2)
            if len(f2.entries) > 0:
                return f"  [{status:>10}] {url}\n      -> {len(f2.entries)} entries (VIA SCRAPLING) ✅"
    bozo = getattr(feed, "bozo_exception", "")
    flag = "✅" if n > 0 else "❌"
    extra = f" via={via}" if via != "direct" else ""
    note = "" if n > 0 else f" bozo={bozo}"
    return f"  [{status:>10}] {url}\n      -> {n} entries {flag}{extra}{note}"


for source, urls in CANDIDATES.items():
    print(f"\n=== {source} ===")
    for u in urls:
        print(probe(u))
