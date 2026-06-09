"""
cve/advisories.py — Vincula o vendor de uma CVE ao seu advisory oficial.

Carrega de um JSON externo (data/vendor_advisories.json) o mapa
vendor canônico -> URL do advisory. Quando a URL contém o placeholder
``{cve}``, o link é montado por CVE; caso contrário aponta para a página
geral de advisories do vendor. O vendor da CVE é resolvido via aliases para
casar variações de nome (ex.: "windows" -> "microsoft").
"""
import json
import os

import config
from core.logger import get_logger
from cve.aliases import get_aliases_for_vendor

logger = get_logger("cve.advisories")

# Mapa vendor canônico (lower) -> template/URL do advisory.
_ADVISORIES: dict[str, str] = {}


def _initialize_advisories() -> None:
    """Lê o JSON de advisories e o carrega em memória (chaves normalizadas)."""
    global _ADVISORIES

    path = config.VENDOR_ADVISORIES_PATH
    if not os.path.exists(path):
        logger.warning("Arquivo de advisories não encontrado em %s. Sem links de vendor.", path)
        _ADVISORIES = {}
        return

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        # Ignora chaves de metadados (prefixo "_") e normaliza para lower.
        _ADVISORIES = {
            k.lower().strip(): v
            for k, v in data.items()
            if not k.startswith("_") and isinstance(v, str) and v.strip()
        }
        logger.debug("Advisories de vendor carregados: %d entradas.", len(_ADVISORIES))
    except Exception as exc:
        logger.error("Falha ao carregar advisories do JSON: %s", exc)
        _ADVISORIES = {}


_initialize_advisories()


def get_advisory_url(vendor: str, cve_id: str = "") -> str | None:
    """Retorna a URL do advisory para o vendor (resolvendo aliases), ou None.

    Se o template contiver ``{cve}``, substitui pelo ``cve_id`` (em maiúsculas).
    """
    if not vendor:
        return None

    candidates = [vendor.lower().strip(), *get_aliases_for_vendor(vendor)]
    for cand in candidates:
        template = _ADVISORIES.get(cand)
        if template:
            return template.replace("{cve}", (cve_id or "").upper())
    return None


def reload_advisories() -> None:
    """Recarrega o mapa de advisories (útil após editar o JSON)."""
    _initialize_advisories()
