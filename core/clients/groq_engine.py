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
    """Remove blocos de código Markdown e resíduos de texto antes/depois do JSON."""
    if not text: return ""
    # Remove blocos ```json ... ```
    text = re.sub(r"```(?:json)?\s*(.*?)\s*```", r"\1", text, flags=re.DOTALL)
    # Tenta encontrar o primeiro { e o último } para isolar o objeto
    start = text.find('{')
    end = text.rfind('}')
    if start != -1 and end != -1:
        text = text[start:end+1]
    return text.strip()

def chat_completion(messages: list[dict[str, str]], temperature: float = 0.1, json_mode: bool = False) -> Optional[str]:
    """
    Chamada para a API da Groq com estratégia de Fallback Multi-Modelo e Timeouts Curtos.
    """
    url = f"{config.GROQ_BASE_URL}/chat/completions"
    headers = {
        "Authorization": f"Bearer {config.GROQ_API_KEY}",
        "Content-Type": "application/json",
    }

    # Janelas de contexto aproximadas (em caracteres, margem de segurança)
    CONTEXT_WINDOWS = {
        "llama-3.3-70b-versatile": 100000,
        "llama-3.1-8b-instant": 100000,
        "mixtral-8x7b-32768": 28000,
        "gemma2-9b-it": 7000
    }

    for model in FALLBACK_MODELS:
        # Ajusta o truncamento dinamicamente para o modelo atual
        limit = CONTEXT_WINDOWS.get(model, 7000)
        adjusted_messages = []
        for msg in messages:
            adjusted_messages.append({
                "role": msg["role"],
                "content": msg["content"][:limit] if msg["role"] == "user" else msg["content"]
            })

        payload = {
            "model": model,
            "messages": adjusted_messages,
            "temperature": temperature,
        }
        if json_mode:
            payload["response_format"] = {"type": "json_object"}

        try:
            # Timeout agressivo (20s) para não prender o pipeline CTI
            response = http_client.post(url, headers=headers, json=payload, timeout=20, max_429_retries=0)
            
            if response.status_code == 200:
                data = response.json()
                return data["choices"][0]["message"]["content"].strip()
            
            # Se for 400 (Validation Error), tentamos desativar o json_mode no fallback ou pular
            logger.warning("Groq: Erro %d no modelo '%s'. Tentando próximo fallback...", response.status_code, model)
            continue
            
        except Exception as exc:
            logger.warning("Falha rápida no modelo %s: %s. Pulando...", model, exc)
    
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

def _apply_intelligence(item: dict[str, Any], prompt: str, field_map: dict[str, str], system_prompt: str) -> None:
    """Helper genérico para aplicar inteligência artificial a um item (CVE ou Notícia)."""
    # Verifica se já está processado
    first_field = list(field_map.keys())[0]
    if item.get(first_field):
        return

    result = ask_json(prompt, system_prompt)
    
    if result:
        for target_field, source_field in field_map.items():
            item[target_field] = result.get(source_field, "")
        logger.info("Inteligência aplicada com sucesso.")
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
    # Prioridade: full_content (raspado pelo Scrapling) > summary (RSS)
    content = article.get("full_content") or article.get("summary", "")
    
    # Truncamento de segurança alinhado com o scraping (35k chars)
    truncated_content = content[:35000]
    
    prompt = f"Título: {title}\nConteúdo Original: {truncated_content}"
    _apply_intelligence(
        article, 
        prompt, 
        {"title_pt": "title_pt", "summary_pt": "summary_pt", "iocs": "iocs_pt"},
        config.PROMPT_NEWS_INTEL
    )
