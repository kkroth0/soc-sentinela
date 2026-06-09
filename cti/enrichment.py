"""
cti/enrichment.py — Extração de contexto de ameaça a partir de texto livre.

Funções puras (sem rede/banco) que isolam a heurística de extração de CWEs,
ameaças (TTPs/malware) e atores (grupos APT) do orquestrador do pipeline,
tornando-as unitariamente testáveis.
"""
import re

from core.constants import KEYWORD_THREATS, TARGET_SECTORS, TARGET_COUNTRIES, ATTACK_TTPS

_CWE_RE = re.compile(r"\b(CWE-\d+)\b", re.IGNORECASE)
_CVE_RE = re.compile(r"\b(CVE-\d{4}-\d{4,10})\b", re.IGNORECASE)
_APT_RE = re.compile(
    r"\b(storm-\d{4}|unc\d{4}|lazarus|lockbit|blackcat|alphv|apt\d+|"
    r"fancy bear|cozy bear|sandworm)\b",
    re.IGNORECASE,
)


def extract_cwes(text: str) -> set[str]:
    """Retorna o conjunto de CWEs (normalizados em maiúsculas) citados no texto."""
    return {m.upper() for m in _CWE_RE.findall(text or "")}


def extract_cve_ids(text: str) -> list[str]:
    """Retorna a lista ordenada e única de IDs CVE citados no texto."""
    return sorted({m.upper() for m in _CVE_RE.findall(text or "")})


def extract_threats(text: str) -> list[str]:
    """Extrai ameaças (palavras-chave de TTP/malware) e atores (grupos APT).

    A ordem é determinística: primeiro as ameaças por palavra-chave (na ordem
    de KEYWORD_THREATS), depois os grupos detectados.
    """
    threats: list[str] = []
    lowered = (text or "").lower()

    for keyword, label in KEYWORD_THREATS.items():
        if keyword in lowered and label not in threats:
            threats.append(label)

    for group in _APT_RE.findall(lowered):
        if group.startswith(("storm", "unc", "apt")):
            formatted = f"Grupo APT ({group.upper()})"
        else:
            formatted = f"Ameaça ({group.capitalize()})"
        if formatted not in threats:
            threats.append(formatted)

    # Se um grupo APT específico foi identificado, o rótulo genérico "Grupo APT"
    # (vindo da palavra-chave "apt") vira ruído redundante.
    if "Grupo APT" in threats and any(t.startswith("Grupo APT (") for t in threats):
        threats.remove("Grupo APT")

    return threats


def _compile_keyword_map(mapping: dict[str, tuple[str, ...]]) -> dict[str, list[re.Pattern[str]]]:
    """Pré-compila os padrões de cada rótulo com casamento por limite de palavra.

    Usa lookarounds (e não \\b) para casar corretamente termos com pontuação,
    como "u.s." ou "e-commerce", sem falsos positivos por substring.
    """
    return {
        label: [re.compile(rf"(?<!\w){re.escape(kw.lower())}(?!\w)") for kw in keywords]
        for label, keywords in mapping.items()
    }


_SECTOR_PATTERNS = _compile_keyword_map(TARGET_SECTORS)
_COUNTRY_PATTERNS = _compile_keyword_map(TARGET_COUNTRIES)
_TTP_PATTERNS = _compile_keyword_map(ATTACK_TTPS)


def _match_labels(text: str, compiled: dict[str, list[re.Pattern[str]]]) -> list[str]:
    """Retorna os rótulos cujas palavras-chave aparecem no texto (ordem do mapa)."""
    lowered = (text or "").lower()
    return [label for label, patterns in compiled.items() if any(p.search(lowered) for p in patterns)]


def extract_sectors(text: str) -> list[str]:
    """Identifica setores-alvo citados no texto (rótulos em PT, sem duplicatas)."""
    return _match_labels(text, _SECTOR_PATTERNS)


def extract_countries(text: str) -> list[str]:
    """Identifica países/regiões citados no texto (rótulos em PT, sem duplicatas)."""
    return _match_labels(text, _COUNTRY_PATTERNS)


def extract_ttps(text: str) -> list[str]:
    """Mapeia o texto para técnicas MITRE ATT&CK ("Txxxx — Nome"), sem duplicatas."""
    return _match_labels(text, _TTP_PATTERNS)
