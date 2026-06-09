"""Testes do vínculo de advisories de vendor (cve.advisories)."""

from cve import advisories


def test_advisory_fills_cve_placeholder():
    url = advisories.get_advisory_url("microsoft", "CVE-2026-1234")
    assert url == "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-1234"


def test_advisory_normalizes_cve_to_upper():
    url = advisories.get_advisory_url("redhat", "cve-2026-1234")
    assert url is not None and url.endswith("CVE-2026-1234")


def test_advisory_general_page_without_placeholder():
    # Vendor com página geral (sem {cve}) retorna a URL inalterada.
    url = advisories.get_advisory_url("oracle", "CVE-2026-1234")
    assert url == "https://www.oracle.com/security-alerts/"


def test_advisory_resolves_via_alias():
    # "windows" deve resolver para o advisory da Microsoft via aliases.
    url = advisories.get_advisory_url("windows", "CVE-2026-1234")
    assert url is not None and "msrc.microsoft.com" in url


def test_advisory_unknown_vendor_returns_none():
    assert advisories.get_advisory_url("vendor-inexistente-xyz", "CVE-2026-1234") is None


def test_advisory_empty_vendor_returns_none():
    assert advisories.get_advisory_url("", "CVE-2026-1234") is None
