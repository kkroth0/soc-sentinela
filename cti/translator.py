"""
cti/translator.py — Tradução literal de artigos CTI para pt-BR.
DeepL (primário) → Groq Llama-3.1 (fallback) → texto original.
O resumo refinado ocorre em cti/summarizer.py (etapa separada).
"""

from typing import Any

import config
from core.clients import http_client
from core.clients.groq_client import chat_completion
from core.logger import get_logger

logger = get_logger("cti.translator")

# ─── Prompt de Tradução CTI (usado no fallback Groq) ─────────────────

_CTI_TRANSLATION_SYSTEM_PROMPT = (
    "Você é um tradutor técnico especializado em cibersegurança. "
    "Traduza o texto do Inglês para o Português do Brasil de forma literal e técnica. "
    "Não resuma, apenas traduza."
)


def _translate_deepl(text: str) -> str | None:
    """Traduz texto via DeepL API."""
    if not config.DEEPL_API_KEY:
        return None

    try:
        response = http_client.post(
            config.DEEPL_BASE_URL,
            headers={"Authorization": f"DeepL-Auth-Key {config.DEEPL_API_KEY}"},
            data={
                "text": text,
                "source_lang": "EN",
                "target_lang": "PT-BR",
            },
        )
        if response.status_code == 200:
            translations = response.json().get("translations", [])
            if translations:
                return translations[0].get("text", "")
        else:
            logger.warning("DeepL retornou HTTP %d", response.status_code)
    except Exception as exc:
        logger.warning("Falha DeepL: %s", exc)
    return None


def _translate_groq_fallback(text: str) -> str | None:
    """Tradução literal via Groq (Llama-3.1). Fallback do DeepL."""
    try:
        messages = [
            {"role": "system", "content": _CTI_TRANSLATION_SYSTEM_PROMPT},
            {"role": "user", "content": text},
        ]
        return chat_completion(messages)
    except Exception as exc:
        logger.warning("Falha Groq na tradução CTI: %s", exc)
    return None


def translate_text(text: str) -> str:
    """Traduz texto para pt-BR. DeepL (primário) → Groq (fallback) → original."""
    if not text or not text.strip():
        return text

    # 1. Tentar DeepL
    result = _translate_deepl(text)
    if result:
        return result

    # 2. Tentar Groq como tradutor
    logger.info("DeepL falhou ou indisponível, usando Groq para tradução...")
    result = _translate_groq_fallback(text)
    if result:
        return result

    logger.warning("Tradução falhou completamente — texto original mantido")
    return text


def translate_article(article: dict[str, Any]) -> dict[str, Any]:
    """
    Traduz um artigo CTI do Inglês para o PT-BR.
    """
    orig_title = article.get("title", "")
    orig_summary = article.get("summary", "")

    # TRADUZIR (DeepL ou Groq literal)
    title_pt = translate_text(orig_title)
    summary_pt = translate_text(orig_summary)

    article["title_pt"] = title_pt
    article["summary_pt"] = summary_pt
    article["translated"] = True

    logger.debug("Artigo traduzido: %s", article.get("title", "?")[:60])
    return article
