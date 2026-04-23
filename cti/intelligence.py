"""
cti/intelligence.py — Processamento consolidado de IA para CTI (Tradução + Resumo).
Reduz o número de chamadas de API de 3 para 1 por artigo.
"""

import json
from typing import Any
from core.clients.groq_client import chat_completion
from core.logger import get_logger

logger = get_logger("cti.intelligence")

_SYSTEM_PROMPT = (
    "You are a Senior SOC Analyst and CTI Researcher."
    "Your goal is to process security news for an executive/technical audience."
    "CRITICAL RULES for Translation/Titles:\n"
    "- DO NOT translate campaign names or metaphors literally (e.g., 'Snow Flurries' stays 'Snow Flurries' or is translated to a technical context).\n"
    "- AVOID repetitive titles (e.g., instead of 'AI defense for AI threats', use 'Estratégias de Defesa contra Ameaças de IA').\n"
    "- Keep titles CONCISE and TECHNICAL.\n"
    "You MUST return a JSON object with two fields: 'title_pt' and 'summary_pt'."
)

_USER_PROMPT_TEMPLATE = (
    "Analyze and process this CTI article.\n"
    "1. Title (title_pt): Provide a technical, professional title in Brazilian Portuguese. Avoid literalism.\n"
    "2. Summary (summary_pt): Create a 3-paragraph summary in Brazilian Portuguese.\n"
    "   - Paragraph 1: Detailed technical discovery (Actors, TTPs, Vulnerabilities).\n"
    "   - Paragraph 2: Business/Infrastructure impact and risk level.\n"
    "   - Paragraph 3: Clear, actionable recommendations for SOC/Infrastructure teams.\n\n"
    "Return ONLY valid JSON. No markdown, no commentary.\n\n"
    "Original Title: {title}\n"
    "Original Content: {summary}"
)

def process_article_intelligence(article: dict[str, Any]) -> None:
    """
    Consolida Tradução e Summarização em uma única chamada ao Groq.
    Atualiza o dicionário 'article' in-place com 'title_pt' e 'summary_pt'.
    """
    title = article.get("title", "")
    content = article.get("summary", "")

    logger.info("Iniciando processamento inteligente (Groq Llama-3.1)...")

    prompt = _USER_PROMPT_TEMPLATE.format(title=title, summary=content)
    messages = [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "user", "content": prompt}
    ]

    # Ativamos o json_mode para garantir que a API retorne um objeto JSON puro
    response = chat_completion(messages, temperature=0.1, json_mode=True)

    if not response:
        logger.warning("IA não retornou resposta para o artigo.")
        return

    try:
        # Limpeza robusta e extração via regex caso haja meta-texto
        import re
        json_match = re.search(r'(\{.*\})', response, re.DOTALL)
        if json_match:
            clean_response = json_match.group(1)
        else:
            clean_response = response.strip()

        data = json.loads(clean_response)
        
        # Atribuímos os campos traduzidos/resumidos
        article["title_pt"] = data.get("title_pt", title)
        article["summary_pt"] = data.get("summary_pt", content)
        
        logger.info("Artigo processado com sucesso via IA (JSON Mode).")
    except Exception as exc:
        logger.error("Falha ao parsear JSON da IA: %s", exc)
        logger.debug("Resposta bruta: %s", response)
        # Se falhar totalmente, tentamos usar a resposta como resumo (fallback de emergência)
        if len(response) > 50:
             article["summary_pt"] = response
