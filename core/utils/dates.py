"""
core/utils/dates.py — Utilitários para manipulação de datas e timezones.
Garante que todo o projeto use o mesmo padrão ISO com UTC.
"""
from datetime import datetime, timezone, timedelta
from typing import Optional

def now_iso() -> str:
    """Retorna o timestamp UTC atual em formato ISO."""
    return datetime.now(timezone.utc).isoformat()

def parse_iso(iso_str: str) -> Optional[datetime]:
    """Converte string ISO para objeto datetime com segurança."""
    if not iso_str: return None
    try:
        return datetime.fromisoformat(iso_str)
    except (ValueError, TypeError):
        return None

def format_brazilian(iso_str: str) -> str:
    """Converte ISO para formato brasileiro DD/MM/YYYY."""
    dt = parse_iso(iso_str)
    if not dt: return ""
    return dt.strftime("%d/%m/%Y")

def get_relative_date(days: int = 0) -> datetime:
    """Retorna uma data relativa ao agora (UTC)."""
    return datetime.now(timezone.utc) + timedelta(days=days)
