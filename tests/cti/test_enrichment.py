"""Testes do módulo de extração de contexto de ameaça (cti.enrichment)."""

from cti import enrichment


def test_extract_cwes_normalizes_and_dedups():
    assert enrichment.extract_cwes("Falha CWE-79 e também cwe-89 e CWE-79") == {"CWE-79", "CWE-89"}


def test_extract_cwes_empty():
    assert enrichment.extract_cwes("") == set()
    assert enrichment.extract_cwes(None) == set()


def test_extract_cve_ids_sorted_unique_upper():
    text = "Veja CVE-2026-1234 e cve-2025-0001 e CVE-2026-1234"
    assert enrichment.extract_cve_ids(text) == ["CVE-2025-0001", "CVE-2026-1234"]


def test_extract_threats_keyword():
    assert "Ransomware" in enrichment.extract_threats("A new ransomware campaign")


def test_extract_threats_apt_group_formatting():
    assert "Grupo APT (UNC2452)" in enrichment.extract_threats("UNC2452 is back")


def test_extract_threats_named_group_formatting():
    assert "Ameaça (Lockbit)" in enrichment.extract_threats("lockbit hit a hospital")


def test_extract_threats_no_duplicates():
    threats = enrichment.extract_threats("ransomware ransomware ransomware")
    assert threats.count("Ransomware") == 1


def test_extract_threats_empty():
    assert enrichment.extract_threats("") == []


def test_extract_threats_apt_no_generic_when_specific():
    # "apt28" não deve produzir o genérico "Grupo APT" junto do específico.
    threats = enrichment.extract_threats("apt28 campaign detected")
    assert "Grupo APT (APT28)" in threats
    assert "Grupo APT" not in threats


# ── Setores ────────────────────────────────────────────────────────────
def test_extract_sectors_english_keyword():
    assert enrichment.extract_sectors("Ransomware hit a hospital network") == ["Saúde"]


def test_extract_sectors_portuguese_keyword():
    assert "Financeiro" in enrichment.extract_sectors("Ataque ao setor bancário brasileiro")


def test_extract_sectors_multiple_preserves_map_order():
    # "Saúde" vem antes de "Financeiro" no mapa → ordem determinística.
    assert enrichment.extract_sectors("banking and healthcare both targeted") == ["Saúde", "Financeiro"]


def test_extract_sectors_no_duplicates():
    assert enrichment.extract_sectors("hospital hospital medical") == ["Saúde"]


def test_extract_sectors_empty():
    assert enrichment.extract_sectors("") == []
    assert enrichment.extract_sectors(None) == []


# ── Países ─────────────────────────────────────────────────────────────
def test_extract_countries_demonym():
    assert "Rússia" in enrichment.extract_countries("Russian state-sponsored actors")


def test_extract_countries_with_punctuation_token():
    assert "Estados Unidos" in enrichment.extract_countries("targets across the U.S. and beyond")


def test_extract_countries_no_substring_false_positive():
    # "iran" não deve casar dentro de "environment".
    assert "Irã" not in enrichment.extract_countries("a hostile environment for defenders")


def test_extract_countries_empty():
    assert enrichment.extract_countries("") == []


# ── TTPs (MITRE ATT&CK) ────────────────────────────────────────────────
def test_extract_ttps_phishing():
    assert "T1566 — Phishing" in enrichment.extract_ttps("a large phishing campaign")


def test_extract_ttps_ransomware_impact():
    assert "T1486 — Data Encrypted for Impact" in enrichment.extract_ttps("the ransomware encrypts files")


def test_extract_ttps_portuguese_keyword():
    assert "T1498 — Network Denial of Service" in enrichment.extract_ttps("ataque de negação de serviço")


def test_extract_ttps_no_substring_false_positive():
    # "rce" não deve casar dentro de "source".
    assert "T1190 — Exploit Public-Facing Application" not in enrichment.extract_ttps("open source project")


def test_extract_ttps_no_duplicates():
    ttps = enrichment.extract_ttps("powershell powershell powershell")
    assert ttps.count("T1059.001 — PowerShell") == 1


def test_extract_ttps_empty():
    assert enrichment.extract_ttps("") == []
    assert enrichment.extract_ttps(None) == []
