"""
core/clients/http_client.py — Sessão HTTP compartilhada com retry, pooling e respeito ao Retry-After.
Bug fix #6: Ao receber 429, lê o header Retry-After e aguarda exatamente esse tempo.
"""

import time
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from core.logger import get_logger

logger = get_logger("core.clients.http_client")

_DEFAULT_TIMEOUT: int = 90
_MAX_RETRIES: int = 3
_BACKOFF_FACTOR: float = 1.0
_POOL_CONNECTIONS: int = 10
_POOL_MAXSIZE: int = 20

_session: requests.Session | None = None


def get_session() -> requests.Session:
    """Retorna sessão HTTP singleton com retry e connection pooling."""
    global _session
    if _session is not None:
        return _session

    _session = requests.Session()
    _session.headers.update({
        "User-Agent": "SOC-Sentinel/1.0 (Threat Intelligence Bot; SOC Team)",
        "Accept": "application/json, text/plain, */*"
    })

    retry_strategy = Retry(
        total=_MAX_RETRIES,
        backoff_factor=_BACKOFF_FACTOR,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=["GET", "POST"],
        raise_on_status=False,
    )

    adapter = HTTPAdapter(
        max_retries=retry_strategy,
        pool_connections=_POOL_CONNECTIONS,
        pool_maxsize=_POOL_MAXSIZE,
    )
    _session.mount("https://", adapter)
    _session.mount("http://", adapter)

    logger.info("Sessão HTTP v7.0: pool=%d, agent=SOC-Sentinel", _POOL_CONNECTIONS)
    return _session


def request_with_retry_after(
    method: str,
    url: str,
    max_429_retries: int = 3,
    timeout: int = _DEFAULT_TIMEOUT,
    use_retry: bool = True,
    **kwargs: Any,
) -> requests.Response:
    """
    Faz request HTTP respeitando o header Retry-After em respostas 429.
    Se use_retry for False, ignora a estratégia de retry do pooling.
    """
    session = get_session()
    
    # Se não quiser retry, podemos usar a sessão mas passar um adapter sem retry
    # Ou mais simples: apenas controlar o loop do 429. 
    # Para o retry do urllib3 (timeouts), precisamos de outro approach.
    
    # Se use_retry for False, vamos usar o requests puro para evitar o adapter do singleton
    if not use_retry:
        return requests.request(method, url, timeout=timeout, **kwargs)

    # Realiza pelo menos uma tentativa. O loop range(max_429_retries + 1) garante isso.
    # Ex: se max_429_retries=0, o loop roda 1 vez (tentativa inicial).
    # Se max_429_retries=3, o loop roda até 4 vezes (1 inicial + 3 retries).
    response = None
    for attempt_idx in range(max_429_retries + 1):
        attempt_num = attempt_idx + 1
        response = session.request(method, url, timeout=timeout, **kwargs)

        if response.status_code != 429:
            return response

        # Se for um 429 e não houver mais tentativas de retry permitidas, aborta o loop
        if attempt_idx >= max_429_retries:
            break

        # Lógica de espera do Retry-After
        retry_after = response.headers.get("Retry-After")
        if retry_after is not None:
            try:
                wait_seconds = int(retry_after)
            except ValueError:
                wait_seconds = 30
        else:
            wait_seconds = min(30, 2 ** attempt_num)
        
        if wait_seconds > 120:
            logger.error("Retry-After muito longo (%ds) para %s — abortando requisição.", wait_seconds, url)
            return response

        logger.warning(
            "429 Too Many Requests em %s — aguardando %ds (tentativa %d/%d)",
            url, wait_seconds, attempt_num, max_429_retries,
        )
        time.sleep(wait_seconds)

    if response and response.status_code == 429:
        logger.error("Esgotou retentativas 429 para %s", url)
    return response


def get(url: str, use_retry: bool = True, **kwargs: Any) -> requests.Response:
    """GET com suporte a Retry-After."""
    return request_with_retry_after(method="GET", url=url, use_retry=use_retry, **kwargs)


def post(url: str, use_retry: bool = True, **kwargs: Any) -> requests.Response:
    """POST com suporte a Retry-After."""
    return request_with_retry_after(method="POST", url=url, use_retry=use_retry, **kwargs)


def close_session() -> None:
    """Encerra a sessão HTTP singleton."""
    global _session
    if _session:
        _session.close()
        _session = None
        logger.info("Sessão HTTP encerrada com sucesso.")
