"""Testes do parser MSRC (cve.msrc_client) — sem rede."""

from datetime import datetime, timezone

import pytest

from cve import msrc_client


def _sample_doc() -> dict:
    """Documento CVRF mínimo com 2 vulnerabilidades cobrindo os casos-chave."""
    return {
        "DocumentTitle": {"Value": "June 2026 Security Updates"},
        "DocumentTracking": {
            "InitialReleaseDate": "2026-06-09T07:00:00",
            "CurrentReleaseDate": "2026-06-09T07:00:00",
        },
        "ProductTree": {
            "FullProductName": [
                {"ProductID": "1", "Value": "Windows 11 Version 24H2 for x64-based Systems"},
                {"ProductID": "2", "Value": "Windows Server 2025"},
            ]
        },
        "Vulnerability": [
            {
                "CVE": "CVE-2026-0001",
                "Title": {"Value": "Windows Kernel RCE"},
                "CWE": [{"ID": "CWE-122", "Value": "Heap Overflow"}],
                "ProductStatuses": [{"ProductID": ["1", "2"], "Type": 3}],
                "Threats": [
                    {"Type": 0, "Description": {"Value": "Remote Code Execution"}, "ProductID": ["1"]},
                    {"Type": 3, "Description": {"Value": "Important"}, "ProductID": ["1"]},
                    {"Type": 3, "Description": {"Value": "Critical"}, "ProductID": ["2"]},
                    {"Type": 1, "Description": {
                        "Value": "Publicly Disclosed:Yes;Exploited:Yes;Latest Software Release:Exploitation More Likely"
                    }},
                ],
                "CVSSScoreSets": [
                    {"BaseScore": 7.5, "Vector": "CVSS:3.1/AV:N", "ProductID": ["1"]},
                    {"BaseScore": 8.8, "Vector": "CVSS:3.1/AV:N", "ProductID": ["2"]},
                ],
                "Remediations": [
                    {"Type": 2, "Description": {"Value": "5094123"},
                     "URL": "https://catalog.update.microsoft.com/?q=KB5094123", "ProductID": ["1"]},
                    {"Type": 2, "Description": {"Value": "5094123"}, "URL": "", "ProductID": ["2"]},
                    {"Type": 3, "Description": {"Value": "5094123"}, "URL": "https://support/x", "ProductID": ["1"]},
                ],
                # Republicada: revisão inicial mais antiga que a do mês -> menor data vence.
                "RevisionHistory": [
                    {"Number": "1.1", "Date": "2026-06-09T07:00:00"},
                    {"Number": "1.0", "Date": "2026-06-04T07:00:00"},
                ],
                "ReleaseDate": "0001-01-01T00:00:00",
            },
            {
                # Sem CVSS, sem KB, não explorada.
                "CVE": "CVE-2026-0002",
                "Title": {"Value": "Edge Spoofing"},
                "ProductStatuses": [{"ProductID": ["1"], "Type": 3}],
                "Threats": [
                    {"Type": 0, "Description": {"Value": "Spoofing"}, "ProductID": ["1"]},
                    {"Type": 1, "Description": {
                        "Value": "Publicly Disclosed:No;Exploited:No;Latest Software Release:N/A"
                    }},
                ],
                "CVSSScoreSets": [],
                "Remediations": [],
            },
            {"CVE": "", "Title": {"Value": "ignorada"}},  # sem CVE -> descartada
        ],
    }


def test_get_patch_tuesday_doc_id():
    assert msrc_client.get_patch_tuesday_doc_id(datetime(2026, 6, 9, tzinfo=timezone.utc)) == "2026-Jun"
    assert msrc_client.get_patch_tuesday_doc_id(datetime(2025, 1, 14, tzinfo=timezone.utc)) == "2025-Jan"
    assert msrc_client.get_patch_tuesday_doc_id(datetime(2024, 12, 10, tzinfo=timezone.utc)) == "2024-Dec"


def test_parse_document_basic():
    meta = msrc_client.parse_document(_sample_doc(), "2026-Jun")
    assert meta["doc_id"] == "2026-Jun"
    assert meta["release_date"].startswith("2026-06-09")
    # A entrada sem CVE é descartada -> 2 válidas.
    assert len(meta["vulns"]) == 2


def test_parse_vulnerability_fields():
    meta = msrc_client.parse_document(_sample_doc(), "2026-Jun")
    v1 = next(v for v in meta["vulns"] if v["cve_id"] == "CVE-2026-0001")

    assert v1["cvss_score"] == 8.8  # maior BaseScore
    assert v1["severity"] == "Critical"  # pior severidade entre produtos
    assert v1["impact"] == "Remote Code Execution"
    assert v1["published"] == "2026-06-04"  # menor data do RevisionHistory
    assert v1["action_category"] == ""  # tem KB numérica + não-Edge -> acionável
    assert v1["exploited"] is True
    assert v1["publicly_disclosed"] is True
    assert v1["exploitability"] == "Exploitation More Likely"
    assert v1["cwes"] == ["CWE-122"]
    # KB deduplicada (mesma 5094123 em 2 produtos, Type 3 ignorado).
    assert [k["kb"] for k in v1["kbs"]] == ["5094123"]
    assert "Windows Server 2025" in v1["products"]
    assert v1["url"].endswith("/CVE-2026-0001")


def test_parse_vulnerability_missing_optionals():
    meta = msrc_client.parse_document(_sample_doc(), "2026-Jun")
    v2 = next(v for v in meta["vulns"] if v["cve_id"] == "CVE-2026-0002")
    assert v2["cvss_score"] is None
    assert v2["severity"] == ""
    assert v2["impact"] == "Spoofing"
    assert v2["exploited"] is False
    assert v2["kbs"] == []
    assert v2["published"] == ""  # sem RevisionHistory nem ReleaseDate válido
    assert v2["action_category"] == "cloud"  # sem KB numérica -> corrigido server-side


def test_action_category():
    edge = msrc_client._action_category("", ["Microsoft Edge (Chromium-based)"], [{"kb": "5094123"}])
    assert edge == "edge"
    azl = msrc_client._action_category("Important", ["azl3 kernel 6.6 on Azure Linux 3.0"], [])
    assert azl == "azure_linux"
    cloud = msrc_client._action_category("Critical", ["Microsoft 365 Copilot"], [{"kb": "Release Notes"}])
    assert cloud == "cloud"
    core = msrc_client._action_category("Important", ["Windows 11"], [{"kb": "5094123"}])
    assert core == ""
    # "Azure Stack Edge" NÃO é o navegador Edge (regressão).
    assert msrc_client._action_category("Important", ["Azure Stack Edge"], [{"kb": "Release Notes"}]) != "edge"


def test_product_family_collapses_skus():
    assert msrc_client._product_family("Windows 11 Version 24H2 for x64-based Systems") == "Windows 11"
    assert msrc_client._product_family("Windows Server 2025") == "Windows Server 2025"


def test_fetch_patch_tuesday_polls_until_available(monkeypatch):
    calls = {"n": 0}

    def fake_fetch(doc_id):
        calls["n"] += 1
        return _sample_doc() if calls["n"] >= 3 else None

    sleeps: list[int] = []
    monkeypatch.setattr(msrc_client, "_fetch_document", fake_fetch)

    result = msrc_client.fetch_patch_tuesday(
        doc_id="2026-Jun", poll=True, retries=5, retry_sleep=1,
        sleep_fn=lambda s: sleeps.append(s),
    )
    assert result is not None
    assert calls["n"] == 3
    assert len(sleeps) == 2  # dormiu antes das 2 tentativas falhas


def test_fetch_patch_tuesday_gives_up(monkeypatch):
    monkeypatch.setattr(msrc_client, "_fetch_document", lambda doc_id: None)
    result = msrc_client.fetch_patch_tuesday(
        doc_id="2026-Jun", poll=True, retries=2, retry_sleep=0, sleep_fn=lambda s: None,
    )
    assert result is None
