"""
reports/patch_tuesday_pdf.py — Geração do PDF do relatório de Patch Tuesday.

Layout A4 paisagem: cabeçalho com KPIs + tabela paginada com TODAS as CVEs do
documento MSRC do mês (CVE, severidade, CVSS, impacto, produtos, KB, status).
"""

from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    LongTable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    TableStyle,
)

from core.logger import get_logger

logger = get_logger("reports.patch_tuesday_pdf")

# Cores por severidade MSRC.
_SEVERITY_COLORS = {
    "Critical": colors.HexColor("#c0392b"),
    "Important": colors.HexColor("#e67e22"),
    "Moderate": colors.HexColor("#f1c40f"),
    "Low": colors.HexColor("#27ae60"),
}

_HEADER_BG = colors.HexColor("#1f2d3d")
_ROW_ALT = colors.HexColor("#f4f6f8")


def _cell_style() -> ParagraphStyle:
    styles = getSampleStyleSheet()
    return ParagraphStyle(
        "cell", parent=styles["BodyText"], fontSize=7, leading=8.5, alignment=TA_LEFT
    )


def _status_label(v: dict[str, Any]) -> str:
    parts = []
    if v.get("exploited"):
        parts.append("Explorada")
    if v.get("publicly_disclosed"):
        parts.append("Divulgada")
    return " / ".join(parts)


def _sort_key(v: dict[str, Any]) -> tuple:
    """Ordena: exploradas/divulgadas primeiro, depois por CVSS desc."""
    sev_rank = {"Critical": 4, "Important": 3, "Moderate": 2, "Low": 1}.get(v.get("severity", ""), 0)
    return (
        0 if v.get("exploited") else 1,
        0 if v.get("publicly_disclosed") else 1,
        -sev_rank,
        -(v.get("cvss_score") or 0.0),
    )


def build_patch_tuesday_pdf(
    meta: dict[str, Any],
    stats: dict[str, Any],
    out_path: str,
) -> str:
    """Gera o PDF do Patch Tuesday em ``out_path`` e retorna o caminho."""
    doc = SimpleDocTemplate(
        out_path,
        pagesize=landscape(A4),
        leftMargin=10 * mm,
        rightMargin=10 * mm,
        topMargin=12 * mm,
        bottomMargin=12 * mm,
        title=f"Patch Tuesday — {meta.get('doc_id', '')}",
        author="SOC Sentinel",
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("ptTitle", parent=styles["Title"], fontSize=18, spaceAfter=2)
    sub_style = ParagraphStyle("ptSub", parent=styles["Normal"], fontSize=9, textColor=colors.grey)
    kpi_style = ParagraphStyle("ptKpi", parent=styles["Normal"], fontSize=9, leading=13)
    cell = _cell_style()

    elements: list[Any] = []

    period = stats.get("period_label") or meta.get("doc_id", "")
    elements.append(Paragraph(f"🩹 Patch Tuesday — {period}", title_style))
    elements.append(Paragraph("Microsoft Security Updates (MSRC) — SOC Sentinel", sub_style))
    elements.append(Spacer(1, 6 * mm))

    sev = stats.get("severity_breakdown", {})
    kpi_text = (
        f"<b>Total de CVEs:</b> {stats.get('total', 0)} &nbsp;&nbsp;|&nbsp;&nbsp; "
        f"<b>Críticas:</b> {sev.get('Critical', 0)} &nbsp;|&nbsp; "
        f"<b>Importantes:</b> {sev.get('Important', 0)} &nbsp;|&nbsp; "
        f"<b>Moderadas:</b> {sev.get('Moderate', 0)} &nbsp;|&nbsp; "
        f"<b>Baixas:</b> {sev.get('Low', 0)}<br/>"
        f"<b>Exploradas ativamente:</b> {len(stats.get('exploited', []))} &nbsp;&nbsp;|&nbsp;&nbsp; "
        f"<b>Publicamente divulgadas:</b> {len(stats.get('publicly_disclosed', []))} &nbsp;&nbsp;|&nbsp;&nbsp; "
        f"<b>Publicado em:</b> {meta.get('release_date', 'N/A')[:10]}"
    )
    elements.append(Paragraph(kpi_text, kpi_style))
    elements.append(Spacer(1, 5 * mm))

    # ── Tabela de CVEs ────────────────────────────────────────────────
    header = ["CVE", "Sev.", "CVSS", "Impacto", "Produto(s)", "KB", "Status"]
    data: list[list[Any]] = [[Paragraph(f"<b>{h}</b>", cell) for h in header]]

    vulns = sorted(meta.get("vulns", []), key=_sort_key)
    sev_row_colors: list[tuple[int, Any]] = []

    for idx, v in enumerate(vulns, start=1):
        families = v.get("product_families") or v.get("products") or []
        prod = ", ".join(families[:3])
        if len(families) > 3:
            prod += f" +{len(families) - 3}"
        kbs = ", ".join(k["kb"] for k in v.get("kbs", [])[:4]) or "—"
        score = v.get("cvss_score")
        score_txt = f"{score:.1f}" if score is not None else "—"

        data.append([
            Paragraph(v.get("cve_id", ""), cell),
            Paragraph(v.get("severity", "") or "—", cell),
            Paragraph(score_txt, cell),
            Paragraph(v.get("impact", "") or "—", cell),
            Paragraph(prod or "—", cell),
            Paragraph(kbs, cell),
            Paragraph(_status_label(v) or "—", cell),
        ])
        sev_color = _SEVERITY_COLORS.get(v.get("severity", ""))
        if sev_color is not None:
            sev_row_colors.append((idx, sev_color))

    col_widths = [26 * mm, 17 * mm, 12 * mm, 38 * mm, 92 * mm, 38 * mm, 28 * mm]
    table = LongTable(data, colWidths=col_widths, repeatRows=1)

    style = [
        ("BACKGROUND", (0, 0), (-1, 0), _HEADER_BG),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#d5dbe0")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, _ROW_ALT]),
        ("LEFTPADDING", (0, 0), (-1, -1), 3),
        ("RIGHTPADDING", (0, 0), (-1, -1), 3),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]
    # Tarja colorida de severidade na coluna "Sev."
    for row_idx, color in sev_row_colors:
        style.append(("BACKGROUND", (1, row_idx), (1, row_idx), color))
        style.append(("TEXTCOLOR", (1, row_idx), (1, row_idx), colors.white))

    table.setStyle(TableStyle(style))
    elements.append(table)

    doc.build(elements)
    logger.info("PDF do Patch Tuesday gerado: %s (%d CVEs).", out_path, len(vulns))
    return out_path
