"""Testes do cartão CTI adaptável por camada (core.notifications.formatters.cti_formatter)."""

from core.models import StandardCTINews
from core.notifications.formatters.cti_formatter import (
    build_news_telegram_message,
    TELEGRAM_MAX_LEN,
)


def _news(layer: int, summary: str, score: int = 0) -> StandardCTINews:
    return StandardCTINews(
        title="Falha crítica explorada ativamente",
        url="https://example.com/post",
        source="BleepingComputer",
        layer=layer,
        summary=summary,
        date="2026-06-08T10:00:00",
        score=score,
    )


def test_regional_layer_uses_context_section_not_mitigation():
    """Camada 4 (Radar Regional) não deve forçar a seção de mitigação."""
    msg = build_news_telegram_message(_news(4, "Fato de mercado.\n\nPor que importa para o setor."))
    assert "Radar Regional" in msg
    assert "🚨" not in msg  # sem alarme falso
    assert "POR QUE IMPORTA" in msg
    assert "MITIGAÇÃO" not in msg


def test_threat_layer_uses_mitigation_section():
    """Camadas de ameaça (1–3) mantêm a seção Impacto & Mitigação."""
    msg = build_news_telegram_message(_news(1, "Ameaça técnica.\n\nAplicaR patch imediatamente."))
    assert "Vendor Advisory" in msg
    assert "MITIGAÇÃO" in msg


def test_header_severity_follows_score_not_layer():
    """A cor do cabeçalho segue o score (urgência), não a camada da fonte."""
    # Item regional (camada 4) com score crítico deve ficar VERMELHO, não verde.
    critical = build_news_telegram_message(_news(4, "Resumo.", score=92))
    assert "🔴" in critical and "CRÍTICO" in critical
    # Mesma camada, score baixo → verde.
    low = build_news_telegram_message(_news(4, "Resumo.", score=10))
    assert "🟢" in low and "BAIXO" in low


def test_single_paragraph_renders_only_summary():
    msg = build_news_telegram_message(_news(3, "Parágrafo único sem mitigação."))
    assert "📝 <b>RESUMO</b>" in msg
    assert "IMPACTO" not in msg


def test_message_is_clamped_to_telegram_limit():
    huge = ("A" * 6000) + "\n\n" + ("B" * 6000)
    msg = build_news_telegram_message(_news(2, huge))
    assert len(msg) <= TELEGRAM_MAX_LEN
    assert "truncada" in msg


def test_accepts_raw_dict_input():
    msg = build_news_telegram_message(
        {"title_pt": "Título", "summary_pt": "Resumo.", "source": "X", "layer": 4, "url": "https://x.y"}
    )
    assert "Título" in msg and "🟢" in msg


def test_html_is_escaped_in_title():
    news = _news(3, "Resumo.")
    news.title = "Ataque <script> & cia"
    msg = build_news_telegram_message(news)
    assert "<script>" not in msg
    assert "&lt;script&gt;" in msg
