"""
cve/translator.py — Tradução de descrições de CVEs para pt-BR.
DeepL (primário) → Groq Llama-3.1 (fallback) → texto original.
"""

from typing import Any

import config
from core.clients import http_client
from core.clients.groq_client import chat_completion
from core.logger import get_logger

logger = get_logger("cve.translator")

# ─── Prompt de Tradução CVE (usado no fallback Groq) ─────────────────

_CVE_TRANSLATION_SYSTEM_PROMPT = (
  "You are a senior CVE analyst at NIST with deep expertise in vulnerability disclosure.\n"
    "Your sole task is to translate CVE descriptions from English to Brazilian Portuguese "
    "with flawless technical accuracy.\n\n"
    "Rules:\n"
    "1. Preserve cybersecurity and computing terms in English when no precise Portuguese "
    "equivalent exists in InfoSec practice — apply judgment, not a fixed list.\n"
    "2. Never produce literal translations that distort technical meaning. "
    "Prioritize semantic accuracy over word-for-word equivalence.\n"
    "3. Translate only what is given. Do not summarize, add context, or invent mitigations.\n"
    "4. Tone: formal, objective, strictly technical.\n"
    "5. Return only the translated text. No introductory or closing sentences."
)


def _translate_deepl(text: str) -> str | None:
    """Traduz texto usando DeepL API."""
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


def _translate_groq(text: str) -> str | None:
    """Tradução técnica rigorosa via Groq (Llama-3.1). Fallback do DeepL."""
    try:
        messages = [
            {"role": "system", "content": _CVE_TRANSLATION_SYSTEM_PROMPT},
            {"role": "user", "content": text},
        ]
        return chat_completion(messages, temperature=0.0)
    except Exception as exc:
        logger.warning("Falha Groq LLM na tradução de CVE: %s", exc)
    return None


def translate_text(text: str) -> str:
    """Traduz texto para pt-BR. DeepL (primário) → Groq (fallback) → original."""
    if not text or not text.strip():
        return text

    # 1. Tentar DeepL (Primário)
    logger.debug("Tentando tradução via DeepL...")
    result = _translate_deepl(text)
    if result:
        return result

    # 2. Tentar Groq como Fallback (Llama 3.1)
    logger.debug("DeepL falhou, usando Groq como fallback...")
    result = _translate_groq(text)
    if result:
        return result

    logger.warning("Tradução falhou — retornando texto original")
    return text


def translate_cve(cve: dict[str, Any]) -> dict[str, Any]:
    """
    Traduz campos textuais de uma CVE para pt-BR.
    Traduz: description (título/descrição combinados).
    Marca cve['translated'] = True ao final.
    """
    cve_id = cve.get("cve_id", "")
    description = cve.get("description", "")

    if description:
        cve["description_pt"] = translate_text(description)
        logger.info("CVE %s — descrição traduzida", cve_id)
    else:
        cve["description_pt"] = ""

    cve["translated"] = True
    return cve
