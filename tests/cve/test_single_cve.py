"""Testes do helper de consulta de CVE sob demanda (cve.pipeline.build_single_cve_alert)."""

from unittest.mock import patch

from cve import pipeline


def test_returns_none_when_cve_not_found():
    with patch.object(pipeline.nvd_client, "fetch_single_cve", return_value=None):
        assert pipeline.build_single_cve_alert("CVE-2099-0001") is None


def test_builds_alert_from_nvd_data():
    fake = {
        "cve_id": "CVE-2021-44228", "cvss_score": 10.0, "severity": "CRITICAL",
        "vendor": "apache", "product": "log4j",
        "description": "RCE via JNDI", "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
        "date": "2021-12-10",
    }
    with patch.object(pipeline.nvd_client, "fetch_single_cve", return_value=fake), \
         patch.object(pipeline.asset_matcher, "match_cve_to_clients", return_value=[]), \
         patch.object(pipeline.risk_scorer, "enrich_cve"), \
         patch.object(pipeline.groq_engine, "process_cve_intelligence"), \
         patch.object(pipeline.advisories, "get_advisory_url", return_value=None), \
         patch.object(pipeline, "get_asset_map", return_value={}):
        alert = pipeline.build_single_cve_alert("CVE-2021-44228")

    assert alert is not None
    assert alert.cve_id == "CVE-2021-44228"
    assert alert.vendor == "apache"
    assert alert.cvss_score == 10.0
