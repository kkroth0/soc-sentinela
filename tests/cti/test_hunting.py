"""Testes da geração de hunts KQL para Microsoft Sentinel (cti.hunting)."""

from core.models import StandardCTINews
from cti import hunting


def _news(**kw) -> StandardCTINews:
    base = dict(title="t", url="u", source="s", layer=2, summary="", date="2026-06-09")
    base.update(kw)
    return StandardCTINews(**base)


def test_parse_iocs_handles_dict_and_defang():
    ips, domains, hashes = hunting._parse_iocs(
        {"IPs": ["51.159.98.241", "1.1.1[.]1"], "Domínios": ["evil-c2.net"], "Hashes": ["a" * 64]}
    )
    assert "51.159.98.241" in ips and "1.1.1.1" in ips
    assert "evil-c2.net" in domains
    assert "a" * 64 in hashes


def test_ip_hunt_seeded_with_ioc():
    news = _news(iocs={"IPs": ["51.159.98.241"]})
    hunts = hunting.build_sentinel_hunts(news)
    ip_hunt = next(h for h in hunts if "IPs maliciosos" in h["title"])
    assert "51.159.98.241" in ip_hunt["kql"]
    assert "DeviceNetworkEvents" in ip_hunt["kql"]


def test_asset_hunt_maps_vendor_domain():
    news = _news(matched_assets=["servicenow"])
    hunts = hunting.build_sentinel_hunts(news)
    assert any("service-now.com" in h["kql"] for h in hunts)


def test_ttp_hunt_mapped_by_technique_id():
    news = _news(ttps=["T1110 — Brute Force"])
    hunts = hunting.build_sentinel_hunts(news)
    assert any(h["title"].startswith("T1110") and "SigninLogs" in h["kql"] for h in hunts)


def test_ttp_subtechnique_falls_back_to_parent():
    # T1059.001 tem template próprio; T1059.999 cairia no pai T1059 (sem template) -> ignora
    news = _news(ttps=["T1059.001 — PowerShell"])
    hunts = hunting.build_sentinel_hunts(news)
    assert any("powershell" in h["kql"].lower() for h in hunts)


def test_no_signals_no_hunts():
    assert hunting.build_sentinel_hunts(_news()) == []


def test_respects_limit():
    news = _news(
        iocs={"IPs": ["1.2.3.4"], "Domínios": ["a.com"], "Hashes": ["b" * 64]},
        ttps=["T1190 — x", "T1078 — x", "T1110 — x", "T1486 — x", "T1071 — x"],
    )
    assert len(hunting.build_sentinel_hunts(news, limit=4)) == 4
