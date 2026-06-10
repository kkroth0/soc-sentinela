"""
cve/msrc_client.py — Ingestão do Patch Tuesday da Microsoft via MSRC CVRF API v3.0.

A Microsoft publica um documento de segurança por mês com ID no formato
``YYYY-Mon`` (ex.: ``2026-Jun``), listado em ``/cvrf/v3.0/updates`` e disponível
na íntegra em ``/cvrf/v3.0/cvrf/{ID}``. Cada documento traz todas as
``Vulnerability`` corrigidas no mês, com CVSS, severidade MSRC, tipo de impacto,
status de exploração/divulgação e as KBs de correção.
"""

import re
import time
from datetime import datetime, timezone
from typing import Any

import config
from core.clients import http_client
from core.logger import get_logger

logger = get_logger("cve.msrc_client")

# Abreviações de mês em inglês usadas pela MSRC no ID do documento.
# strftime("%b") depende do locale do SO, então fixamos a lista.
_MONTH_ABBR: tuple[str, ...] = (
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
)

# Tipos de Threat no CVRF: 0=Impacto, 1=Exploit Status, 2=Target Set, 3=Severidade.
_THREAT_IMPACT = 0
_THREAT_EXPLOIT_STATUS = 1
_THREAT_SEVERITY = 3

# Tipo de Remediation 2 = Vendor Fix (a KB de correção).
_REMEDIATION_VENDOR_FIX = 2

# Ordem de criticidade da severidade MSRC (para escolher a "pior" entre produtos).
_SEVERITY_ORDER = {"Critical": 4, "Important": 3, "Moderate": 2, "Low": 1, "": 0}


def get_patch_tuesday_doc_id(when: datetime | None = None) -> str:
    """Retorna o ID do documento MSRC do mês (ex.: ``2026-Jun``)."""
    dt = when or datetime.now(timezone.utc)
    return f"{dt.year}-{_MONTH_ABBR[dt.month - 1]}"


def _build_product_map(doc: dict[str, Any]) -> dict[str, str]:
    """Mapeia ProductID -> nome legível a partir do ProductTree."""
    product_map: dict[str, str] = {}
    for fp in doc.get("ProductTree", {}).get("FullProductName", []):
        pid = fp.get("ProductID")
        value = fp.get("Value")
        if pid and value:
            product_map[pid] = value
    return product_map


def _product_family(name: str) -> str:
    """Colapsa um nome de produto numa família (remove versões/arquitetura/SKU)."""
    # Corta a partir de marcadores comuns de variação de SKU.
    cut = re.split(r"\s+(?:Version|for|\(|x64|x86|32-bit|64-bit|ARM64)\b", name, maxsplit=1)[0]
    return cut.strip(" -") or name


def _parse_exploit_status(threats: list[dict[str, Any]]) -> dict[str, Any]:
    """Extrai exploração/divulgação do Threat Type 1 (ex.: 'Exploited:Yes')."""
    exploited = False
    publicly_disclosed = False
    exploitability = ""
    for t in threats:
        if t.get("Type") != _THREAT_EXPLOIT_STATUS:
            continue
        blob = t.get("Description", {}).get("Value", "")
        if "Exploited:Yes" in blob:
            exploited = True
        if "Publicly Disclosed:Yes" in blob:
            publicly_disclosed = True
        m = re.search(r"Latest Software Release:([^;]+)", blob)
        if m:
            exploitability = m.group(1).strip()
    return {
        "exploited": exploited,
        "publicly_disclosed": publicly_disclosed,
        "exploitability": exploitability,
    }


def _max_severity(threats: list[dict[str, Any]]) -> str:
    """Retorna a maior severidade MSRC entre os produtos afetados."""
    best = ""
    for t in threats:
        if t.get("Type") != _THREAT_SEVERITY:
            continue
        sev = t.get("Description", {}).get("Value", "") or ""
        if _SEVERITY_ORDER.get(sev, 0) > _SEVERITY_ORDER.get(best, 0):
            best = sev
    return best


def _primary_impact(threats: list[dict[str, Any]]) -> str:
    """Retorna o tipo de impacto mais frequente (Threat Type 0)."""
    counts: dict[str, int] = {}
    for t in threats:
        if t.get("Type") != _THREAT_IMPACT:
            continue
        val = t.get("Description", {}).get("Value", "") or ""
        if val:
            counts[val] = counts.get(val, 0) + 1
    if not counts:
        return ""
    return max(counts, key=counts.get)


def _max_cvss(vuln: dict[str, Any]) -> tuple[float | None, str]:
    """Maior BaseScore entre os CVSSScoreSets e o vetor correspondente."""
    best_score: float | None = None
    best_vector = ""
    for css in vuln.get("CVSSScoreSets", []) or []:
        score = css.get("BaseScore")
        if score is None:
            continue
        score = float(score)
        if best_score is None or score > best_score:
            best_score = score
            best_vector = css.get("Vector", "") or ""
    return best_score, best_vector


def _extract_kbs(vuln: dict[str, Any]) -> list[dict[str, str]]:
    """Extrai as KBs de correção (Remediation Type 2 = Vendor Fix)."""
    seen: set[str] = set()
    kbs: list[dict[str, str]] = []
    for rem in vuln.get("Remediations", []) or []:
        if rem.get("Type") != _REMEDIATION_VENDOR_FIX:
            continue
        kb = (rem.get("Description", {}) or {}).get("Value", "").strip()
        if not kb or kb in seen:
            continue
        seen.add(kb)
        kbs.append({"kb": kb, "url": rem.get("URL", "") or ""})
    return kbs


def _action_category(severity: str, families: list[str], kbs: list[dict[str, str]]) -> str:
    """
    Classifica a CVE quanto à acionabilidade:
      'edge'         — Microsoft Edge/Chromium (auto-atualiza)
      'azure_linux'  — pacotes do Azure Linux/Mariner
      'cloud'        — serviço cloud corrigido server-side (sem KB numérica)
      ''             — patch on-prem normal (Windows/Office/Server) — acionável
    """
    fams = [f.lower() for f in families]
    # "Microsoft Edge" (navegador Chromium) — NÃO confundir com "Azure Stack Edge".
    if fams and all("microsoft edge" in f for f in fams):
        return "edge"
    if any("azure linux" in f or f.startswith("azl") for f in fams):
        return "azure_linux"
    has_numeric_kb = any(k.get("kb", "").isdigit() for k in kbs)
    if not has_numeric_kb:
        return "cloud"
    return ""


def _publication_date(vuln: dict[str, Any]) -> str:
    """Data de publicação da CVE (YYYY-MM-DD) — menor data do RevisionHistory."""
    dates = [
        r.get("Date", "")
        for r in (vuln.get("RevisionHistory") or [])
        if r.get("Date") and not r["Date"].startswith("0001")
    ]
    if dates:
        return min(dates)[:10]
    rd = vuln.get("ReleaseDate", "")
    if rd and not rd.startswith("0001"):
        return rd[:10]
    return ""


def _affected_products(vuln: dict[str, Any], product_map: dict[str, str]) -> list[str]:
    """Lista os nomes dos produtos afetados (ProductStatuses 'Known Affected')."""
    names: list[str] = []
    seen: set[str] = set()
    for status in vuln.get("ProductStatuses", []) or []:
        for pid in status.get("ProductID", []) or []:
            name = product_map.get(pid)
            if name and name not in seen:
                seen.add(name)
                names.append(name)
    return names


def parse_vulnerability(vuln: dict[str, Any], product_map: dict[str, str]) -> dict[str, Any] | None:
    """Normaliza uma entrada Vulnerability do CVRF na estrutura interna."""
    cve_id = (vuln.get("CVE") or "").strip()
    if not cve_id:
        return None

    threats = vuln.get("Threats", []) or []
    cvss_score, cvss_vector = _max_cvss(vuln)
    exploit = _parse_exploit_status(threats)
    products = _affected_products(vuln, product_map)
    families = sorted({_product_family(p) for p in products})
    severity = _max_severity(threats)
    kbs = _extract_kbs(vuln)

    raw_cwe = vuln.get("CWE")
    if isinstance(raw_cwe, dict):  # alguns docs trazem CWE como objeto único
        cwes = [raw_cwe["ID"]] if raw_cwe.get("ID") else []
    else:
        cwes = [c.get("ID", "") for c in (raw_cwe or []) if isinstance(c, dict) and c.get("ID")]

    return {
        "cve_id": cve_id,
        "title": (vuln.get("Title", {}) or {}).get("Value", "") or "",
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "severity": severity,
        "impact": _primary_impact(threats),
        "published": _publication_date(vuln),
        "action_category": _action_category(severity, families, kbs),
        "products": products,
        "product_families": families,
        "kbs": kbs,
        "cwes": cwes,
        "exploited": exploit["exploited"],
        "publicly_disclosed": exploit["publicly_disclosed"],
        "exploitability": exploit["exploitability"],
        "url": f"{config.MSRC_UPDATE_GUIDE_URL}/{cve_id}",
    }


def _fetch_document(doc_id: str) -> dict[str, Any] | None:
    """Baixa um documento CVRF cru pela API. Retorna None se indisponível."""
    url = f"{config.MSRC_CVRF_BASE_URL}/{doc_id}"
    try:
        resp = http_client.get(url, headers={"Accept": "application/json"}, timeout=60)
    except Exception as exc:
        logger.warning("MSRC: falha de rede ao buscar %s: %s", doc_id, exc)
        return None

    if resp.status_code == 404:
        logger.info("MSRC: documento %s ainda não publicado (404).", doc_id)
        return None
    if resp.status_code != 200:
        logger.warning("MSRC: HTTP %d ao buscar %s.", resp.status_code, doc_id)
        return None

    try:
        return resp.json()
    except Exception as exc:
        logger.warning("MSRC: JSON inválido para %s: %s", doc_id, exc)
        return None


def parse_document(doc: dict[str, Any], doc_id: str) -> dict[str, Any]:
    """Converte um documento CVRF cru em meta + lista de vulnerabilidades parseadas."""
    product_map = _build_product_map(doc)
    vulns: list[dict[str, Any]] = []
    for raw in doc.get("Vulnerability", []) or []:
        parsed = parse_vulnerability(raw, product_map)
        if parsed:
            vulns.append(parsed)

    tracking = doc.get("DocumentTracking", {}) or {}
    return {
        "doc_id": doc_id,
        "title": (doc.get("DocumentTitle", {}) or {}).get("Value", "") or doc_id,
        "release_date": tracking.get("InitialReleaseDate", "")
        or tracking.get("CurrentReleaseDate", ""),
        "vulns": vulns,
    }


def fetch_patch_tuesday(
    doc_id: str | None = None,
    poll: bool = True,
    retries: int | None = None,
    retry_sleep: int | None = None,
    sleep_fn: Any = time.sleep,
) -> dict[str, Any] | None:
    """
    Busca o documento do Patch Tuesday do mês, com poll opcional.

    Se ``poll`` for True e o documento ainda não estiver publicado, aguarda e
    repete até ``retries`` vezes (espaçadas por ``retry_sleep`` segundos) — útil
    quando o job dispara junto com a publicação da Microsoft.
    """
    doc_id = doc_id or get_patch_tuesday_doc_id()
    retries = config.MSRC_FETCH_RETRIES if retries is None else retries
    retry_sleep = config.MSRC_FETCH_RETRY_SLEEP if retry_sleep is None else retry_sleep

    attempts = (retries + 1) if poll else 1
    for attempt in range(1, attempts + 1):
        doc = _fetch_document(doc_id)
        if doc and doc.get("Vulnerability"):
            result = parse_document(doc, doc_id)
            logger.info(
                "MSRC: documento %s pronto — %d vulnerabilidades (tentativa %d).",
                doc_id, len(result["vulns"]), attempt,
            )
            return result

        if attempt < attempts:
            logger.info(
                "MSRC: %s indisponível — aguardando %ds (tentativa %d/%d).",
                doc_id, retry_sleep, attempt, attempts,
            )
            sleep_fn(retry_sleep)

    logger.error("MSRC: documento %s não disponível após %d tentativa(s).", doc_id, attempts)
    return None
