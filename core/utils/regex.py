"""
core/utils/regex.py — Cache centralizado de padrões Regex compilados para otimização de performance.
"""
import re

_REGEX_CACHE: dict[str, re.Pattern] = {}

def get_pattern(term: str) -> re.Pattern:
    """Retorna um padrão de Regex pré-compilado com word boundaries e case-insensitive."""
    if term not in _REGEX_CACHE:
        _REGEX_CACHE[term] = re.compile(r'\b' + re.escape(term) + r'\b', re.IGNORECASE)
    return _REGEX_CACHE[term]
