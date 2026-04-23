"""
cti/summarizer.py — Tradução e Resumo de artigos CTI via Groq (Llama-3.1/3.3).
One-Shot: Lê em Inglês e cospe o título e os 3 parágrafos de resumo em pt-BR.
Possui Guardrails Anti-Alucinação para impedir invenção de IoCs e CVEs.
"""

import json
from typing import Any
from core.clients.groq_client import chat_completion
from core.logger import get_logger

logger = get_logger("cti.summarizer")

# ─── Prompt de Summarização e Tradução CTI ───────────────────────────

_SYSTEM_PROMPT = (
    "You are an expert SOC Analyst and forensic translator. "
    "Your task is to read cyber threat intelligence (CTI) articles in English "
    "and output a structured JSON response translating and summarizing it into Brazilian Portuguese.\n\n"
    "STRICT ANTI-HALLUCINATION GUARDRAILS:\n"
    "- NEVER invent CVE numbers, threat actor names, or Indicators of Compromise (IoCs).\n"
    "- If a detail is not explicitly mentioned in the text, DO NOT include it.\n"
    "- Translate technical cybersecurity jargon accurately (e.g. do not translate 'Buffer Overflow' literally).\n\n"
    "Return ONLY a valid JSON object with the following keys:\n"
    "{\n"
    '  "title_pt": "Translated title in pt-BR",\n'
    '  "summary_pt": "Summary in pt-BR strictly following the 3 paragraph rule"\n'
    "}\n\n"
    "3 Paragraph Rule for 'summary_pt':\n"
    "Paragraph 1: What was discovered or occurred (threat, vulnerability, campaign).\n"
    "Paragraph 2: Impact — who is affected, attack surface, severity.\n"
    "Paragraph 3: Recommended action — patch, IoC, detection, mitigation. If none, omit this paragraph."
)

_USER_PROMPT_TEMPLATE = (
    "Title: {title}\n"
    "Content: {summary}"
)

def summarize_article(article: dict[str, Any]) -> dict[str, Any]:
    """
    Traduz e resume o artigo de forma estruturada (JSON) usando o Groq.
    """
    title_en = article.get("title", "")
    summary_en = article.get("summary", "")

    logger.info("Traduzindo e resumindo com Groq (One-Shot)...")

    messages = [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "user", "content": _USER_PROMPT_TEMPLATE.format(title=title_en, summary=summary_en)},
    ]

    # Usando JSON mode via response format
    # O groq_client suporta response_format={"type": "json_object"} nativamente?
    # Como não temos certeza se o client suporta o kwarg, pedimos no prompt e usamos temperatura 0
    raw_response = chat_completion(messages, temperature=0.0)

    if raw_response:
        try:
            # Tentar parsear o JSON
            # Remover blocos de markdown ```json caso existam
            clean_json = raw_response.replace("```json", "").replace("```", "").strip()
            parsed = json.loads(clean_json)
            
            article["title_pt"] = parsed.get("title_pt", title_en)
            article["summary_pt"] = parsed.get("summary_pt", summary_en)
            article["translated"] = True
            logger.info("Artigo processado via LLM: %s", article["title_pt"][:60])
        except json.JSONDecodeError as exc:
            logger.error("Falha ao parsear JSON do Groq: %s | Raw: %s", exc, raw_response[:100])
            # Fallback seguro: joga o raw no summary
            article["summary_pt"] = raw_response
            article["title_pt"] = title_en
    else:
        logger.error("Groq não retornou resposta para o artigo.")

    return article
