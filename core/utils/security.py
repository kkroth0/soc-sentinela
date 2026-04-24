"""
core/utils/security.py — Utilitários de sanitização e segurança.
"""
import re

def escape_adaptive_card_markdown(text: str) -> str:
    """
    Escapa caracteres de Markdown suportados por Adaptive Cards do Teams.
    Evita quebra de layout e ataques de injeção visual (phishing).
    """
    if not text:
        return ""
    
    # Adaptive Cards suportam um subconjunto de Markdown.
    # Escapamos colchetes e parênteses para evitar injeção de links maliciosos.
    # Também escapamos asteriscos e underscores para evitar quebra de formatação.
    chars_to_escape = r"([\[\]\(\)\*\_])"
    return re.sub(chars_to_escape, r"\\\1", text)

def sanitize_url(url: str) -> str:
    """Garante que a URL seja segura (apenas http/https)."""
    if not url:
        return ""
    if url.lower().startswith(("http://", "https://")):
        return url
    return ""

def sanitize_csv_value(value: str) -> str:
    """
    Escapa valores que podem ser interpretados como fórmulas no Excel/CSV.
    Previne ataques de CSV Injection (DDE).
    """
    if not value:
        return ""
    # Se começar com caracteres de fórmula, adiciona uma aspa simples para neutralizar
    if str(value).startswith(("=", "+", "-", "@")):
        return f"'{value}"
    return value
