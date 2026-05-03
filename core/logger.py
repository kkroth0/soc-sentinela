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

    # 1. Console Handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_handler.setFormatter(logging.Formatter(_LOG_FORMAT, datefmt=_DATE_FORMAT))
    root.addHandler(console_handler)

    # 2. Rotating File Handler (Logs em disco com rotação para não encher o HD)
    try:
        log_dir = os.path.join(config.BASE_DIR, "logs")
        os.makedirs(log_dir, exist_ok=True)
        log_file = os.path.join(log_dir, "sentinel.log")
        
        from logging.handlers import RotatingFileHandler
        file_handler = RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=5, encoding="utf-8")
        file_handler.setLevel(log_level)
        file_handler.setFormatter(logging.Formatter(_LOG_FORMAT, datefmt=_DATE_FORMAT))
        root.addHandler(file_handler)
    except Exception as exc:
        print(f"Erro ao inicializar log em arquivo: {exc}")

    _INITIALIZED = True


def get_logger(name: str) -> logging.Logger:
    """Retorna um logger nomeado. Único ponto de criação de loggers no projeto."""
    _setup_root_logger()
    return logging.getLogger(name)
