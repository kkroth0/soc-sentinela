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

# ─── Prompts de IA ──────────────────────────────────────────────────

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

_CVE_HEADLINE_SYSTEM_PROMPT = (
    "You are a cybersecurity specialist tasked with creating alert headlines.\n"
    "Given a CVE description, generate a one-line concise and catchy headline in Brazilian Portuguese.\n"
    "The headline should summarize the impact (e.g., 'O [Produto] está vulnerável à falha [Tipo] devido a [Causa]').\n"
    "Rules:\n"
    """
    cve_id = cve.get("cve_id", "")
    description = cve.get("description", "")
    product = cve.get("product", "N/A")

    if not description:
        cve["description_pt"] = ""
        cve["headline_pt"] = f"Alerta de Segurança para {cve_id}"
        cve["translated"] = True
        return cve

    # 1. Tentar DeepL para Tradução (Mais rápido se funcionar)
    translated_desc = _translate_deepl(description)

    if translated_desc:
        # Se DeepL funcionou, só precisamos da Headline via Groq
        cve["description_pt"] = translated_desc
        cve["headline_pt"] = _generate_headline(description) or f"Alerta de Segurança para {cve_id}"
    else:
        # 2. SE DEEPL FALHAR (403 detectado): Fazer TUDO em uma única chamada Groq
        logger.info("DeepL indisponível. Usando Inteligência Consolidada Groq para CVE %s...", cve_id)
        
        system_prompt = (
            "You are a Senior CVE Analyst. Process the vulnerability description.\n"
            "Return a JSON object with: 'description_pt' (technical translation) and 'headline_pt' (concise technical alert headline).\n"
            "Rules:\n"
            "- Headline: Professional, max 100 chars, e.g., 'O [Produto] está vulnerável...'\n"
            "- Description: Technical, formal, Brazilian Portuguese.\n"
            "Return ONLY JSON."
        )
        
        user_prompt = f"CVE ID: {cve_id}\nProduct: {product}\nDescription: {description}"
        
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]
        
        import json
        import re

        response = chat_completion(messages, temperature=0.1, json_mode=True)
        
        if response:
            try:
                # Extração via regex caso haja meta-texto
                json_match = re.search(r'(\{.*\})', response, re.DOTALL)
                clean_response = json_match.group(1) if json_match else response
                data = json.loads(clean_response)
                
                cve["description_pt"] = data.get("description_pt", description)
                cve["headline_pt"] = data.get("headline_pt", f"Alerta de Segurança para {cve_id}")
                logger.info("CVE %s — Inteligência consolidada concluída", cve_id)
            except Exception as exc:
                logger.error("Falha ao parsear inteligência da CVE %s: %s", cve_id, exc)
                cve["description_pt"] = description
                cve["headline_pt"] = f"Alerta de Segurança para {cve_id}"
        else:
            cve["description_pt"] = description
            cve["headline_pt"] = f"Alerta de Segurança para {cve_id}"

    cve["translated"] = True
    return cve
