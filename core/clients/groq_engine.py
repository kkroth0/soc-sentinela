"""
core/clients/groq_engine.py — Motor centralizado de IA para tradução e resumos.
Unifica a lógica de inferência, tratamento de erros e retentativas.
"""
import json
import re
from typing import Any, Optional

import config
from core.clients import http_client
from core.logger import get_logger

logger = get_logger("core.clients.groq_engine")

def _clean_json_string(text: str) -> str:
    """Remove blocos de código Markdown e espaços extras da resposta da IA."""
    if not text: return ""
    # Remove blocos de código tipo ```json ... ``` ou ``` ... ```
    text = re.sub(r"```(?:json)?\s*(.*?)\s*```", r"\1", text, flags=re.DOTALL)
    return text.strip()

def chat_completion(messages: list[dict[str, str]], model: str = None, temperature: float = 0.1, json_mode: bool = False) -> Optional[str]:
    """Chamada de baixo nível para a API da Groq."""
    url = f"{config.GROQ_BASE_URL}/chat/completions"
    headers = {
        "Authorization": f"Bearer {config.GROQ_API_KEY}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": model or config.GROQ_MODEL,
        "messages": messages,
        "temperature": temperature,
    }
    if json_mode:
        payload["response_format"] = {"type": "json_object"}

    try:
        response = http_client.post(url, headers=headers, json=payload)
        if response.status_code == 200:
            data = response.json()
            return data["choices"][0]["message"]["content"].strip()
        else:
            logger.error("Groq API erro %d: %s", response.status_code, response.text[:200])
    except Exception as exc:
        logger.error("Falha ao chamar Groq API: %s", exc)
    return None

def ask_json(prompt: str, system_prompt: str, model: str = "llama-3.3-70b-versatile") -> Optional[dict[str, Any]]:
    """Envia pergunta para a Groq e espera resposta em JSON (com limpeza robusta)."""
    try:
        response_text = chat_completion(
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ],
            model=model,
            json_mode=True
        )
        if not response_text: return None
        
        cleaned_text = _clean_json_string(response_text)
        return json.loads(cleaned_text)
    except Exception as exc:
        logger.error("Erro na inferência/parsing Groq: %s", exc)
    return None

def process_cve_intelligence(cve: dict[str, Any]) -> None:
    """Traduz e gera headline para uma CVE."""
    cve_id = cve.get("cve_id", "N/A")
    description = cve.get("description", "")
    
    system_prompt = (
        "Você é um analista de SOC sênior. Traduza a descrição da CVE para Português (Brasil) "
        "mantendo o tom técnico. Além disso, crie um 'headline' curto e impactante (máx 80 caracteres). "
        "Responda EXCLUSIVAMENTE em formato JSON: {'description_pt': '...', 'headline_pt': '...'}"
    )
    
    prompt = f"CVE: {cve_id}\nDescrição original: {description}"
    
    result = ask_json(prompt, system_prompt)
    if result:
        cve["description_pt"] = result.get("description_pt", "")
        cve["headline_pt"] = result.get("headline_pt", "")
        logger.debug("Inteligência aplicada à CVE %s", cve_id)

def process_news_intelligence(article: dict[str, Any]) -> None:
    """Traduz e resume um artigo de notícia CTI."""
    title = article.get("title", "")
    summary = article.get("summary", "")
    
    system_prompt = (
        "Você é um analista de Cyber Threat Intelligence. Traduza o título e faça um resumo executivo "
        "em Português (Brasil) para o artigo fornecido. O resumo deve ser objetivo e focado em impacto. "
        "Responda EXCLUSIVAMENTE em formato JSON: {'title_pt': '...', 'summary_pt': '...'}"
    )
    
    prompt = f"Título: {title}\nResumo Original: {summary}"
    
    result = ask_json(prompt, system_prompt)
    if result:
        article["title_pt"] = result.get("title_pt", "")
        article["summary_pt"] = result.get("summary_pt", "")
        logger.debug("Inteligência aplicada à notícia: %s", title[:40])
