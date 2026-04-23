"""
core/clients/groq_client.py — Cliente HTTP para a API da Groq (Llama-3.1).
Responsabilidade ÚNICA: chamada HTTP genérica de chat completion.
Prompts de domínio vivem nos módulos que os utilizam (cti/, cve/).
"""

import config
from core.clients import http_client
from core.logger import get_logger

logger = get_logger("core.clients.groq_client")


def chat_completion(messages: list[dict[str, str]], temperature: float = 0.0, json_mode: bool = False) -> str | None:
    """
    Realiza uma chamada de chat completion para a Groq.
    """
    if not config.GROQ_API_KEY:
        logger.error("GROQ_API_KEY não configurada")
        return None

    url = f"{config.GROQ_BASE_URL}/chat/completions"
    headers = {
        "Authorization": f"Bearer {config.GROQ_API_KEY}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": config.GROQ_MODEL,
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
