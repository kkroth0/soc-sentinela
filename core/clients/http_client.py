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

_DEFAULT_TIMEOUT: int = 30
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

    logger.info("Sessão HTTP inicializada com retry=%d, pool=%d", _MAX_RETRIES, _POOL_CONNECTIONS)
    return _session


def request_with_retry_after(
    method: str,
    url: str,
    max_429_retries: int = 3,
    timeout: int = _DEFAULT_TIMEOUT,
    **kwargs: Any,
) -> requests.Response:
    """
    Faz request HTTP respeitando o header Retry-After em respostas 429.
    Tenta até max_429_retries vezes quando receber Too Many Requests.
    """
    session = get_session()

    for attempt in range(1, max_429_retries + 1):
        response = session.request(method, url, timeout=timeout, **kwargs)

        if response.status_code != 429:
            return response

        retry_after = response.headers.get("Retry-After")
        if retry_after is not None:
            try:
                wait_seconds = int(retry_after)
            except ValueError:
                wait_seconds = 30
        else:
            wait_seconds = min(30, 2 ** attempt)

        logger.warning(
            "429 Too Many Requests em %s — aguardando %ds (tentativa %d/%d)",
            url, wait_seconds, attempt, max_429_retries,
        )
        time.sleep(wait_seconds)

    logger.error("Esgotou retentativas 429 para %s", url)
    return response


def get(url: str, **kwargs: Any) -> requests.Response:
    """GET com suporte a Retry-After."""
    return request_with_retry_after("GET", url, **kwargs)


def post(url: str, **kwargs: Any) -> requests.Response:
    """POST com suporte a Retry-After."""
    return request_with_retry_after("POST", url, **kwargs)
