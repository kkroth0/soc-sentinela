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

# Lista de modelos para Fallback em caso de Rate Limit (429)
# O Groq aplica limites de tokens por modelo, então alternar modelos resolve o bloqueio.
FALLBACK_MODELS = [
    config.GROQ_MODEL,         # llama-3.3-70b-versatile
    "llama-3.1-8b-instant",
    "mixtral-8x7b-32768",
    "gemma2-9b-it"
]

def _clean_json_string(text: str) -> str:
    """Remove blocos de código Markdown e espaços extras da resposta da IA."""
    if not text: return ""
    # Remove blocos de código tipo ```json ... ``` ou ``` ... ```
    text = re.sub(r"```(?:json)?\s*(.*?)\s*```", r"\1", text, flags=re.DOTALL)
    return text.strip()

def chat_completion(messages: list[dict[str, str]], temperature: float = 0.1, json_mode: bool = False) -> Optional[str]:
    """
    Chamada para a API da Groq com estratégia de Fallback Multi-Modelo.
    Se um modelo retornar 429 (Rate Limit), tenta o próximo da lista.
    """
    url = f"{config.GROQ_BASE_URL}/chat/completions"
    headers = {
        "Authorization": f"Bearer {config.GROQ_API_KEY}",
        "Content-Type": "application/json",
    }

    for model in FALLBACK_MODELS:
        payload = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
        }
        if json_mode:
            payload["response_format"] = {"type": "json_object"}

        try:
            # Desativamos o retry interno do http_client (max_429_retries=0) para 
            # não esperar o Retry-After longo e trocar de modelo IMEDIATAMENTE.
            response = http_client.post(url, headers=headers, json=payload, max_429_retries=0)
            
            if response.status_code == 200:
                data = response.json()
                return data["choices"][0]["message"]["content"].strip()
            
            if response.status_code == 429:
                logger.warning("Groq: Rate Limit no modelo '%s'. Tentando próximo fallback...", model)
                continue
            
            logger.error("Groq API erro %d no modelo %s: %s", response.status_code, model, response.text[:200])
        except Exception as exc:
            logger.error("Falha ao chamar Groq API (%s): %s", model, exc)
    
    return None

def ask_json(prompt: str, system_prompt: str, model: str = "llama-3.3-70b-versatile") -> Optional[dict[str, Any]]:
    """Envia pergunta para a Groq e espera resposta em JSON (com limpeza robusta)."""
    try:
        response_text = chat_completion(
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ],
            json_mode=True
        )
        if not response_text: return None
        
        cleaned_text = _clean_json_string(response_text)
        return json.loads(cleaned_text)
    except Exception as exc:
        logger.error("Erro na inferência/parsing Groq: %s", exc)
    return None

def _apply_intelligence(item: dict[str, Any], prompt: str, field_map: dict[str, str], log_label: str) -> None:
    """Helper genérico para aplicar inteligência artificial a um item (CVE ou Notícia)."""
    # Verifica se já está processado (se o primeiro campo do field_map já existe)
    first_field = list(field_map.keys())[0]
    if item.get(first_field):
        return

    # Constrói o prompt concatenando os valores das chaves de entrada (field_map.values())
    # No caso da Groq Engine, as chaves de entrada são passadas via prompt formatado
    result = ask_json(prompt, log_label)
    
    if result:
        for target_field, source_field in field_map.items():
            item[target_field] = result.get(source_field, "")
        logger.debug("Inteligência aplicada: %s", log_label[:40])
    else:
        # Fallback silencioso: garante campos vazios para não quebrar formatters
        for target_field in field_map.keys():
            item[target_field] = ""

def process_cve_intelligence(cve: dict[str, Any]) -> None:
    """Traduz e gera headline para uma CVE (com fallback)."""
    cve_id = cve.get("cve_id", "N/A")
    description = cve.get("description", "")
    cvss = cve.get("cvss_score", "N/A")
    vendor = cve.get("vendor", "N/A")
    product = cve.get("product", "N/A")
    
    prompt = (
        f"CVE ID: {cve_id}\n"
        f"Fabricante: {vendor}\n"
        f"Produto: {product}\n"
        f"CVSS Score: {cvss}\n"
        f"Descrição original (Inglês): {description}"
    )
    _apply_intelligence(
        cve, 
        prompt, 
        {"description_pt": "description_pt", "headline_pt": "headline_pt"},
        config.PROMPT_CVE_INTEL
    )

def process_news_intelligence(article: dict[str, Any]) -> None:
    """Traduz e resume um artigo de notícia CTI (com fallback)."""
    title = article.get("title", "")
    summary = article.get("summary", "")
    
    prompt = f"Título: {title}\nResumo Original: {summary}"
    _apply_intelligence(
        article, 
        prompt, 
        {"title_pt": "title_pt", "summary_pt": "summary_pt"},
        config.PROMPT_NEWS_INTEL
    )
