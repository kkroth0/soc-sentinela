"""
reports/patch_tuesday_pdf.py — Geração do PDF do relatório de Patch Tuesday.

Layout A4 paisagem: cabeçalho com KPIs + gráfico de vulnerabilidades por ativo
Microsoft + tabela paginada com TODAS as CVEs do documento MSRC do mês
(CVE, severidade, CVSS, data de publicação, impacto, produtos, KB, status).
"""

from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.barcharts import HorizontalBarChart
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


def _nice_step(max_value: int) -> int:
    """Passo 'redondo' para o eixo de valores (~6 marcações)."""
    if max_value <= 6:
        return 1
    raw = max_value / 6
    for step in (1, 2, 5, 10, 20, 25, 50, 100, 200, 500, 1000):
        if step >= raw:
            return step
    return 1000


def build_products_chart(stats: dict[str, Any], max_items: int = 12) -> Drawing | None:
    """Gráfico de barras horizontais: nº de vulnerabilidades por ativo Microsoft."""
    data = stats.get("top_products", [])[:max_items]
    if not data:
        return None

    # Inverte para a maior barra aparecer no topo.
    data = list(reversed(data))
    names = [str(n) for n, _ in data]
    values = [int(c) for _, c in data]
    max_v = max(values)

    drawing_width = 760
    bar_h = 14
    chart_height = max(150, len(values) * (bar_h + 7) + 35)

    d = Drawing(drawing_width, chart_height)
    bc = HorizontalBarChart()
    bc.x = 185           # espaço à esquerda para os nomes dos produtos
    bc.y = 12
    bc.width = drawing_width - bc.x - 45
    bc.height = chart_height - 25
    bc.data = [values]
    bc.barWidth = bar_h
    bc.groupSpacing = 7
    bc.valueAxis.valueMin = 0
    bc.valueAxis.valueMax = max(1, int(max_v * 1.12))
    bc.valueAxis.valueStep = _nice_step(max_v)
    bc.valueAxis.labels.fontSize = 7
    bc.valueAxis.gridStrokeColor = colors.HexColor("#e1e5ea")
    bc.valueAxis.visibleGrid = True
    bc.categoryAxis.categoryNames = names
    bc.categoryAxis.labels.fontSize = 7
    bc.categoryAxis.labels.boxAnchor = "e"
    bc.categoryAxis.labels.dx = -5
    bc.categoryAxis.strokeColor = colors.HexColor("#aab2bd")
    bc.bars[0].fillColor = colors.HexColor("#2e86c1")
    bc.bars[0].strokeColor = colors.HexColor("#1b4f72")
    bc.bars[0].strokeWidth = 0.4
    # Rótulo com o valor na ponta de cada barra.
    bc.barLabels.fontSize = 7
    bc.barLabels.boxAnchor = "w"
    bc.barLabels.dx = 4
    bc.barLabelFormat = "%d"
    bc.barLabelArray = None
    d.add(bc)
    return d


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
    """Ordena: acionáveis primeiro, depois exploradas/divulgadas e CVSS desc."""
    sev_rank = {"Critical": 4, "Important": 3, "Moderate": 2, "Low": 1}.get(v.get("severity", ""), 0)
    return (
        0 if v.get("requires_action") else 1,
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
    total = stats.get("total", 0)
    total_all = stats.get("total_all", total)
    buckets = stats.get("bucket_counts", {})
    official = stats.get("official_date") or meta.get("release_date", "")[:10]

    short = {"edge": "Edge", "cloud": "Cloud", "azure_linux": "Azure Linux", "out_of_band": "Out-of-band"}
    excluded = [(k, buckets.get(k, 0)) for k in short if buckets.get(k)]
    fora_txt = " · ".join(f"{short[k]} {n}" for k, n in excluded) or "nenhum"

    kpi_text = (
        f"<b>Exigem ação (on-prem, na data oficial):</b> {total} de {total_all} &nbsp;&nbsp;|&nbsp;&nbsp; "
        f"<b>Críticas:</b> {sev.get('Critical', 0)} &nbsp;|&nbsp; "
        f"<b>Importantes:</b> {sev.get('Important', 0)} &nbsp;|&nbsp; "
        f"<b>Moderadas:</b> {sev.get('Moderate', 0)} &nbsp;|&nbsp; "
        f"<b>Baixas:</b> {sev.get('Low', 0)}<br/>"
        f"<b>Exploradas ativamente:</b> {len(stats.get('exploited', []))} &nbsp;&nbsp;|&nbsp;&nbsp; "
        f"<b>Publicamente divulgadas:</b> {len(stats.get('publicly_disclosed', []))} &nbsp;&nbsp;|&nbsp;&nbsp; "
        f"<b>Patch oficial:</b> {official}<br/>"
        f"<b>Fora do destaque (auto-update/cloud/out-of-band):</b> {fora_txt}"
    )
    elements.append(Paragraph(kpi_text, kpi_style))
    elements.append(Spacer(1, 5 * mm))

    # ── Gráfico: vulnerabilidades por ativo Microsoft (só acionáveis) ──
    chart = build_products_chart(stats)
    if chart is not None:
        section_style = ParagraphStyle(
            "ptSection", parent=styles["Heading2"], fontSize=12, spaceAfter=4
        )
        elements.append(Paragraph(
            "📊 Vulnerabilidades acionáveis por ativo Microsoft (Top 12)", section_style))
        elements.append(chart)
        elements.append(Spacer(1, 5 * mm))

    # ── Tabela de CVEs ────────────────────────────────────────────────
    header = ["CVE", "Sev.", "CVSS", "Publicada", "Impacto", "Produto(s)", "KB", "Status", "Cat."]
    n_cols = len(header)
    data: list[list[Any]] = [[Paragraph(f"<b>{h}</b>", cell) for h in header]]

    vulns = sorted(meta.get("vulns", []), key=_sort_key)
    sev_row_colors: list[tuple[int, Any]] = []
    divider_row: int | None = None       # linha do separador acionável → resto
    first_noncore_row: int | None = None  # 1ª linha de dados não-acionável

    bucket_short = {
        "edge": "Edge", "cloud": "Cloud", "azure_linux": "Azure Linux",
        "out_of_band": "Out-of-band",
    }
    divider_cell = ParagraphStyle("div", parent=cell, fontSize=7.5, textColor=colors.white)
    grey = colors.HexColor("#7a8694")

    prev_core = True
    row_idx = 0  # índice da linha na matriz `data` (0 = cabeçalho)
    for v in vulns:
        is_core = bool(v.get("requires_action"))

        # Insere o divisor na transição acionável → não-acionável.
        if prev_core and not is_core:
            row_idx += 1
            divider_row = row_idx
            label = "🔕 SEM AÇÃO DE PATCH ON-PREM — auto-update / cloud / out-of-band (na listagem completa para registro)"
            divider_cells = [Paragraph(f"<b>{label}</b>", divider_cell)] + ["" for _ in range(n_cols - 1)]
            data.append(divider_cells)
            first_noncore_row = row_idx + 1
        prev_core = is_core

        families = v.get("product_families") or v.get("products") or []
        prod = ", ".join(families[:3])
        if len(families) > 3:
            prod += f" +{len(families) - 3}"
        kbs = ", ".join(k["kb"] for k in v.get("kbs", [])[:4]) or "—"
        score = v.get("cvss_score")
        score_txt = f"{score:.1f}" if score is not None else "—"
        cat_txt = "—" if is_core else bucket_short.get(v.get("bucket", ""), "—")

        row_idx += 1
        data.append([
            Paragraph(v.get("cve_id", ""), cell),
            Paragraph(v.get("severity", "") or "—", cell),
            Paragraph(score_txt, cell),
            Paragraph(v.get("published", "") or "—", cell),
            Paragraph(v.get("impact", "") or "—", cell),
            Paragraph(prod or "—", cell),
            Paragraph(kbs, cell),
            Paragraph(_status_label(v) or "—", cell),
            Paragraph(cat_txt, cell),
        ])
        # Tarja de severidade só nas linhas acionáveis (core).
        if is_core:
            sev_color = _SEVERITY_COLORS.get(v.get("severity", ""))
            if sev_color is not None:
                sev_row_colors.append((row_idx, sev_color))

    col_widths = [
        22 * mm, 14 * mm, 10 * mm, 19 * mm, 30 * mm, 64 * mm, 33 * mm, 19 * mm, 24 * mm,
    ]
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
    # Tarja colorida de severidade na coluna "Sev." (só acionáveis).
    for r, color in sev_row_colors:
        style.append(("BACKGROUND", (1, r), (1, r), color))
        style.append(("TEXTCOLOR", (1, r), (1, r), colors.white))

    # Linha divisória (faixa escura, mesclada).
    if divider_row is not None:
        style.append(("SPAN", (0, divider_row), (-1, divider_row)))
        style.append(("BACKGROUND", (0, divider_row), (-1, divider_row), _HEADER_BG))
        style.append(("TOPPADDING", (0, divider_row), (-1, divider_row), 4))
        style.append(("BOTTOMPADDING", (0, divider_row), (-1, divider_row), 4))
    # Texto esmaecido nas linhas não-acionáveis.
    if first_noncore_row is not None:
        style.append(("TEXTCOLOR", (0, first_noncore_row), (-1, -1), grey))

    table.setStyle(TableStyle(style))
    elements.append(table)

    doc.build(elements)
    logger.info(
        "PDF do Patch Tuesday gerado: %s (%d CVEs, %d acionáveis).",
        out_path, len(vulns), stats.get("total", 0),
    )
    return out_path
