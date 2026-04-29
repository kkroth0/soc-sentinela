"""
core/notifications/formatters/component_factory.py — Fábrica de UI para Adaptive Cards.
Centraliza o design premium e evita duplicação de boilerplate.
"""
from typing import Any
from core.utils.security import escape_adaptive_card_markdown

def build_header(title: str, subtitle: str, color: str = "accent") -> dict:
    """Cria o banner superior padronizado."""
    return {
        "type": "Container",
        "style": color,
        "bleed": True,
        "items": [
            {
                "type": "TextBlock",
                "text": title,
                "weight": "Bolder",
                "size": "Medium",
                "wrap": True,
                "color": "Light" if color != "default" else "Default"
            },
            {
                "type": "TextBlock",
                "text": subtitle,
                "size": "Small",
                "isSubtle": True,
                "spacing": "None",
                "color": "Light" if color != "default" else "Default"
            }
        ]
    }

def wrap_card(body: list, actions: list = None) -> dict:
    """Envelopa o corpo no formato padrão de Adaptive Card v1.4."""
    card = {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.4",
        "body": body,
        "msteams": {"width": "Full"}
    }
    if actions:
        card["actions"] = actions
    return card

def build_fact_set(facts: list[tuple[str, str]]) -> dict:
    """Cria um conjunto de fatos (chave/valor)."""
    return {
        "type": "FactSet",
        "facts": [{"title": f, "value": v} for f, v in facts],
        "spacing": "Medium"
    }

def build_section_title(text: str, separator: bool = True) -> dict:
    """Cria um título de seção padronizado."""
    return {
        "type": "TextBlock",
        "text": text,
        "weight": "Bolder",
        "spacing": "Large",
        "size": "Small",
        "separator": separator
    }
