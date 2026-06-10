"""Testes da classificação de buckets e KPIs do Patch Tuesday."""

from reports import patch_tuesday


def _meta():
    """Documento mínimo já parseado, cobrindo os 4 buckets."""
    return {
        "doc_id": "2026-Jun",
        "release_date": "2026-06-09T07:00:00",
        "vulns": [
            # core: acionável, on-prem, na data oficial
            {"cve_id": "CVE-1", "severity": "Critical", "impact": "RCE",
             "published": "2026-06-09", "action_category": "",
             "product_families": ["Windows 11"], "exploited": False, "publicly_disclosed": False},
            # core: outro
            {"cve_id": "CVE-2", "severity": "Important", "impact": "EoP",
             "published": "2026-06-09", "action_category": "",
             "product_families": ["Windows Server 2025"], "exploited": False, "publicly_disclosed": True},
            # edge: sem ação
            {"cve_id": "CVE-3", "severity": "", "impact": "",
             "published": "2026-06-05", "action_category": "edge",
             "product_families": ["Microsoft Edge"], "exploited": False, "publicly_disclosed": False},
            # cloud: sem ação
            {"cve_id": "CVE-4", "severity": "Critical", "impact": "Spoofing",
             "published": "2026-06-04", "action_category": "cloud",
             "product_families": ["Microsoft 365 Copilot"], "exploited": False, "publicly_disclosed": False},
            # out_of_band: acionável mas publicada antes da data oficial
            {"cve_id": "CVE-5", "severity": "Important", "impact": "EoP",
             "published": "2026-06-05", "action_category": "",
             "product_families": ["Azure HorizonDB"], "exploited": True, "publicly_disclosed": False},
        ],
    }


def test_classify_buckets():
    meta = _meta()
    official = patch_tuesday.classify_vulns(meta)
    assert official == "2026-06-09"
    by_id = {v["cve_id"]: v["bucket"] for v in meta["vulns"]}
    assert by_id == {
        "CVE-1": "core", "CVE-2": "core", "CVE-3": "edge",
        "CVE-4": "cloud", "CVE-5": "out_of_band",
    }
    assert meta["vulns"][0]["requires_action"] is True
    assert meta["vulns"][4]["requires_action"] is False  # out_of_band não exige ação no destaque


def test_aggregate_stats_uses_core_only():
    stats = patch_tuesday.aggregate_stats(_meta())
    assert stats["total"] == 2          # só os 2 core
    assert stats["total_all"] == 5
    assert stats["official_date"] == "2026-06-09"
    assert stats["bucket_counts"] == {"core": 2, "edge": 1, "cloud": 1, "out_of_band": 1}
    # severidade só do core
    assert stats["severity_breakdown"] == {"Critical": 1, "Important": 1}
    # top_products só do core (Edge/cloud fora)
    prods = dict(stats["top_products"])
    assert "Microsoft Edge" not in prods and "Microsoft 365 Copilot" not in prods
    # exploradas/divulgadas consideram TODAS (CVE-5 exploited mesmo sendo out_of_band)
    assert stats["exploited"] == ["CVE-5"]
    assert stats["publicly_disclosed"] == ["CVE-2"]
