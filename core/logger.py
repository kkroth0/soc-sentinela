"""
core/logger.py — Logging centralizado.
Todos os módulos importam daqui. Nunca usar print() ou logging.getLogger() diretamente.
"""

import logging
import os
import sys
import config

_LOG_FORMAT = "[%(asctime)s] %(levelname)s %(name)s — %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
_INITIALIZED: bool = False


def _setup_root_logger() -> None:
    """Configura o root logger uma única vez."""
    global _INITIALIZED
    if _INITIALIZED:
        return

    log_level = getattr(logging, config.LOG_LEVEL, logging.INFO)

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_handler.setFormatter(logging.Formatter(_LOG_FORMAT, datefmt=_DATE_FORMAT))

    root.addHandler(console_handler)
    _INITIALIZED = True


def get_logger(name: str) -> logging.Logger:
    """Retorna um logger nomeado. Único ponto de criação de loggers no projeto."""
    _setup_root_logger()
    return logging.getLogger(name)
