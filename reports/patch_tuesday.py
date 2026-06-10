"""
reports/patch_tuesday.py — Orquestrador do relatório mensal de Patch Tuesday.

Fluxo: coleta o documento CVRF do mês (cve.msrc_client) → agrega KPIs → gera os
anexos (PDF/CSV/XLSX conforme config) → envia o resumo + anexos no Telegram →
grava o estado para não reenviar o mesmo mês.
"""

import os
from collections import Counter
from typing import Any

import config
from core import storage
from core.logger import get_logger
from core.notifications import telegram_dispatcher
from core.notifications.telegram_notifier import TelegramNotifier
from cve import msrc_client
from reports import patch_tuesday_export, patch_tuesday_pdf

logger = get_logger("reports.patch_tuesday")

_STATE_KEY = "patch_tuesday_last_sent"

_MONTHS_PT = (
    "Janeiro", "Fevereiro", "Março", "Abril", "Maio", "Junho",
    "Julho", "Agosto", "Setembro", "Outubro", "Novembro", "Dezembro",
)


# Rótulos legíveis de cada bucket de acionabilidade.
BUCKET_LABELS = {
    "core": "Patch Tuesday (on-prem)",
    "out_of_band": "Out-of-band (antes do patch oficial)",
    "edge": "Edge/Chromium (auto-update)",
    "cloud": "Serviço cloud (corrigido pela Microsoft)",
    "azure_linux": "Azure Linux",
}


def _period_label(meta: dict[str, Any]) -> str:
    """Deriva 'Junho/2026' a partir da data de release do documento."""
    rd = meta.get("release_date", "")
    if len(rd) >= 7 and rd[4] == "-":
        try:
            return f"{_MONTHS_PT[int(rd[5:7]) - 1]}/{int(rd[:4])}"
        except (ValueError, IndexError):
            pass
    return meta.get("doc_id", "")


def _validate_document_month(meta: dict[str, Any]) -> bool:
    """Confere se o mês do documento bate com o ID solicitado (guarda doc errado)."""
    doc_id = meta.get("doc_id", "")
    rd = meta.get("release_date", "")
    try:
        want_month = msrc_client._MONTH_ABBR[int(rd[5:7]) - 1]
    except (ValueError, IndexError):
        return True  # sem data confiável, não bloqueia
    ok = doc_id.endswith(want_month)
    if not ok:
        logger.warning(
            "Patch Tuesday: mês do documento (%s) diverge do ID solicitado (%s) — "
            "possível documento incorreto/stale.", rd[:10], doc_id,
        )
    return ok


def classify_vulns(meta: dict[str, Any]) -> str:
    """
    Estampa `bucket` e `requires_action` em cada CVE (in-place) e devolve a data
    oficial do patch. Prioridade: edge/cloud (sem ação) > out_of_band (publicada
    antes da data oficial) > core (acionável, on-prem, na data oficial).
    """
    official = (meta.get("release_date") or "")[:10]
    strict = config.PATCH_TUESDAY_OFFICIAL_DATE_ONLY
    noaction = config.PATCH_TUESDAY_NOACTION

    for v in meta.get("vulns", []):
        cat = v.get("action_category", "")
        pub = v.get("published", "")
        if cat in noaction:
            bucket = cat
        elif strict and official and pub and pub != official:
            bucket = "out_of_band"
        else:
            bucket = "core"
        v["bucket"] = bucket
        v["requires_action"] = bucket == "core"
    return official


def aggregate_stats(meta: dict[str, Any]) -> dict[str, Any]:
    """Calcula os KPIs sobre o conjunto `core` (acionável + na data oficial)."""
    official = classify_vulns(meta)
    _validate_document_month(meta)

    vulns = meta.get("vulns", [])
    core = [v for v in vulns if v.get("bucket") == "core"]

    severity = Counter()
    impact = Counter()
    products = Counter()
    for v in core:
        if v.get("severity"):
            severity[v["severity"]] += 1
        if v.get("impact"):
            impact[v["impact"]] += 1
        for fam in v.get("product_families", []):
            products[fam] += 1

    # Exploradas/divulgadas: considera TODAS (nunca esconder um zero-day).
    exploited = [v["cve_id"] for v in vulns if v.get("exploited")]
    disclosed = [v["cve_id"] for v in vulns if v.get("publicly_disclosed")]

    bucket_counts = Counter(v.get("bucket", "core") for v in vulns)

    return {
        "doc_id": meta.get("doc_id", ""),
        "release_date": meta.get("release_date", ""),
        "official_date": official,
        "period_label": _period_label(meta),
        "total": len(core),               # destaque = só acionáveis na data oficial
        "total_all": len(vulns),
        "bucket_counts": dict(bucket_counts),
        "severity_breakdown": dict(severity),
        "impact_breakdown": dict(impact),
        "top_products": products.most_common(10),
        "exploited": exploited,
        "publicly_disclosed": disclosed,
    }


def _generate_attachments(meta: dict[str, Any], stats: dict[str, Any]) -> list[str]:
    """Gera os arquivos de anexo conforme config.PATCH_TUESDAY_FORMATS."""
    os.makedirs(config.REPORTS_OUTPUT_DIR, exist_ok=True)
    base = os.path.join(config.REPORTS_OUTPUT_DIR, f"patch_tuesday_{meta['doc_id']}")
    paths: list[str] = []

    builders = {
        "pdf": lambda p: patch_tuesday_pdf.build_patch_tuesday_pdf(meta, stats, p),
        "csv": lambda p: patch_tuesday_export.build_patch_tuesday_csv(meta, p),
        "xlsx": lambda p: patch_tuesday_export.build_patch_tuesday_xlsx(meta, p),
    }
    for fmt in config.PATCH_TUESDAY_FORMATS:
        builder = builders.get(fmt)
        if not builder:
            continue
        try:
            paths.append(builder(f"{base}.{fmt}"))
        except Exception as exc:
            logger.error("Falha ao gerar anexo %s do Patch Tuesday: %s", fmt, exc)

    return paths


def run_patch_tuesday(
    doc_id: str | None = None,
    force: bool = False,
    poll: bool = True,
    notifier: TelegramNotifier = telegram_dispatcher,
    db_module: Any = storage,
) -> bool:
    """
    Executa o relatório de Patch Tuesday do mês.

    ``force=True`` reenvia mesmo que o mês já tenha sido enviado (útil em testes
    e no trigger manual). ``poll`` controla se aguarda a publicação do documento.
    """
    logger.info("═══ Relatório Patch Tuesday iniciado ═══")

    target_id = doc_id or msrc_client.get_patch_tuesday_doc_id()
    if not force and db_module.get_state(_STATE_KEY) == target_id:
        logger.info("Patch Tuesday %s já enviado anteriormente — ignorando.", target_id)
        return False

    meta = msrc_client.fetch_patch_tuesday(doc_id=target_id, poll=poll)
    if not meta or not meta.get("vulns"):
        logger.error("Patch Tuesday %s indisponível — relatório não enviado.", target_id)
        return False

    stats = aggregate_stats(meta)
    logger.info(
        "Patch Tuesday %s: %d CVEs (%d exploradas, %d divulgadas).",
        target_id, stats["total"], len(stats["exploited"]), len(stats["publicly_disclosed"]),
    )

    attachments = _generate_attachments(meta, stats)
    if not attachments:
        logger.error("Nenhum anexo gerado para o Patch Tuesday %s — abortando envio.", target_id)
        return False

    sent = notifier.send_patch_tuesday_report(stats, attachments)
    if sent:
        db_module.set_state(_STATE_KEY, target_id)
        logger.info("Patch Tuesday %s enviado com sucesso.", target_id)
    else:
        logger.error("Falha ao enviar o Patch Tuesday %s no Telegram.", target_id)

    return sent
