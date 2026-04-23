"""
cti/summarizer.py — Resumo de artigos CTI via Groq (Llama-3.1).
Recebe textos previamente traduzidos e gera resumo técnico focado no analista de SOC.
"""

from typing import Any
from core.clients.groq_client import chat_completion
from core.logger import get_logger

logger = get_logger("cti.summarizer")

# ─── Prompt de Summarização CTI ──────────────────────────────────────

_SYSTEM_PROMPT = (
    "You are a technical summary engine for SOC analysts."
    "Return only plain text. No Markdown, no greetings, no meta-commentary."
)

_USER_PROMPT_TEMPLATE = (
    "Summarize the article below in up to 3 short paragraphs, in Brazilian Portuguese.\n"
    "RULES:\n"
    "- Every sentence must be complete. Never end mid-sentence.\n"  
    "- Each paragraph must end with a period.\n"                 
    "- If the article lacks enough information for a paragraph, omit it entirely "
    "rather than writing an incomplete one.\n"                     
    "- Do not add information not present in the article.\n\n"     
    "Required structure:\n"
    "1st paragraph: What was discovered or occurred (threat, vulnerability, campaign).\n"
    "2nd paragraph: Impact — who is affected, attack surface, severity.\n"
    "3rd paragraph: Recommended action — patch, IoC, detection, mitigation. "
    "If no clear action is present in the article, omit this paragraph.\n\n"
    "Title: {title}\n"
    "Summary: {summary}"
)


def summarize_article(article: dict[str, Any]) -> dict[str, Any]:
    """
    Refina e resume o título e conteúdo do artigo usando Groq (Llama-3.1).
    A tradução deve ser feita antes (em translator.py) para economizar tokens
    e maximizar a qualidade terminológica em Português-BR.
    """
    title_pt = article.get("title_pt", article.get("title", ""))
    summary_pt = article.get("summary_pt", article.get("summary", ""))

    logger.info("Refinando resumo com Groq (Llama-3.1)...")

    messages = [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "user", "content": _USER_PROMPT_TEMPLATE.format(title=title_pt, summary=summary_pt)},
    ]

    refined_summary = chat_completion(messages)

    if refined_summary:
        article["summary_pt"] = refined_summary

    # Se a API falhar, o dicionário mantém o 'summary_pt' original (tradução crua).
    logger.info("Artigo resumido: %s", title_pt[:60])
    return article
