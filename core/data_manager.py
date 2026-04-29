"""
core/data_manager.py — Leitura do Excel de ativos: asset_map e blacklist.
Bug fix #4: Invalidação imediata do cache em memória ao detectar hash diferente.
"""

import hashlib
import os
import threading
from typing import Any

import openpyxl
import time

import config
from core.logger import get_logger

logger = get_logger("core.data_manager")

_cache_lock = threading.Lock()
_asset_map: dict[str, dict[str, Any]] = {}
_blacklist: list[dict[str, Any]] = []
_file_hash: str = ""


def _compute_file_hash(filepath: str) -> str:
    """Calcula SHA-256 do arquivo para detectar mudanças."""
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def _load_excel(filepath: str) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    """
    Lê o Excel e retorna (asset_map, blacklist) dinamicamente.
    """
    wb = openpyxl.load_workbook(filepath, read_only=True, data_only=True)
    asset_map: dict[str, dict[str, Any]] = {}
    blacklist: list[dict[str, Any]] = []

    # ── Assets sheet ──────────────────────────────────────────────────
    if "Assets" in wb.sheetnames:
        ws = wb["Assets"]
        rows = ws.iter_rows(values_only=True)
        try:
            headers = [str(h).lower().strip() if h else "" for h in next(rows)]
        except StopIteration:
            headers = []
            
        if not all(h in headers for h in ["client", "vendor", "product"]):
            logger.warning("Cabeçalhos críticos ausentes no Excel (esperado: client, vendor, product). Usando índices padrão (0, 1, 2).")

        c_idx = headers.index("client") if "client" in headers else 0
        v_idx = headers.index("vendor") if "vendor" in headers else 1
        p_idx = headers.index("product") if "product" in headers else 2
        a_idx = headers.index("aliases") if "aliases" in headers else -1

        from core.utils.security import sanitize_csv_value
        
        for row in rows:
            r = list(row) if row else []
            if len(r) <= max(c_idx, v_idx, p_idx) or not r[c_idx]:
                continue
                
            client = sanitize_csv_value(str(r[c_idx]).strip())
            vendor = sanitize_csv_value(str(r[v_idx]).strip().lower()) if r[v_idx] else ""
            product = sanitize_csv_value(str(r[p_idx]).strip().lower()) if r[p_idx] else ""
            raw_aliases = str(r[a_idx]).strip().lower() if a_idx >= 0 and len(r) > a_idx and r[a_idx] else ""
            aliases = [sanitize_csv_value(a.strip()) for a in raw_aliases.split(",") if a.strip()]

            if vendor:
                key = f"{vendor}:{product}"
                if key not in asset_map:
                    asset_map[key] = {"clients": [], "aliases": aliases}
                if client not in asset_map[key]["clients"]:
                    asset_map[key]["clients"].append(client)
                # Mescla novos aliases, se houver
                for alias in aliases:
                    if alias not in asset_map[key]["aliases"]:
                        asset_map[key]["aliases"].append(alias)
    else:
        logger.warning("Sheet 'Assets' não encontrada no Excel")

    # ── Blacklist sheet ───────────────────────────────────────────────
    if "Blacklist" in wb.sheetnames:
        ws = wb["Blacklist"]
        rows = ws.iter_rows(values_only=True)
        try:
            headers = [str(h).lower().strip() if h else "" for h in next(rows)]
        except StopIteration:
            headers = []
            
        v_idx = headers.index("vendor") if "vendor" in headers else 0
        p_idx = headers.index("product") if "product" in headers else 1
        a_idx = headers.index("aliases") if "aliases" in headers else -1

        for row in rows:
            r = list(row) if row else []
            if not r:
                continue
            
            vendor = str(r[v_idx]).strip().lower() if len(r) > v_idx and r[v_idx] else ""
            product = str(r[p_idx]).strip().lower() if len(r) > p_idx and r[p_idx] else ""
            aliases_str = str(r[a_idx]).strip().lower() if a_idx >= 0 and len(r) > a_idx and r[a_idx] else ""
            aliases = [a.strip() for a in aliases_str.split(",") if a.strip()]

            if product:
                blacklist.append({
                    "vendor": vendor,
                    "product": product,
                    "aliases": aliases
                })
    else:
        logger.info("Sheet 'Blacklist' não encontrada — blacklist vazia")

    wb.close()
    logger.info(
        "Excel carregado: %d chaves no asset_map, %d itens na blacklist",
        len(asset_map), len(blacklist),
    )
    return asset_map, blacklist


_last_check_time = 0.0
_CHECK_INTERVAL = 5.0 # Segundos

def _refresh_if_needed() -> None:
    """Recarrega o Excel se o hash do arquivo mudou (limitado a 1 check a cada 5s)."""
    global _asset_map, _blacklist, _file_hash, _last_check_time

    now = time.time()
    if now - _last_check_time < _CHECK_INTERVAL:
        return

    filepath = config.ASSETS_CACHE_PATH
    if not os.path.exists(filepath):
        logger.warning("Arquivo de ativos não encontrado: %s", filepath)
        return

    current_hash = _compute_file_hash(filepath)
    _last_check_time = now

    if current_hash == _file_hash:
        return

    logger.info("Hash do Excel mudou — recarregando asset_map e blacklist IMEDIATAMENTE")
    new_map, new_bl = _load_excel(filepath)

    with _cache_lock:
        _asset_map = new_map
        _blacklist = new_bl
        _file_hash = current_hash


def get_asset_map() -> dict[str, dict[str, Any]]:
    """
    Retorna o mapa de ativos com estrutura de aliases:
    {'vendor:product': {'clients': ['C1'], 'aliases': ['p1', 'p2']}}
    """
    _refresh_if_needed()
    with _cache_lock:
        # Shallow copy intencional — os consumers NÃO devem mutar os dicts internos.
        return dict(_asset_map)


def get_blacklist() -> list[dict[str, Any]]:
    """
    Retorna lista de dicionários de blacklist.
    Recarrega automaticamente se o arquivo mudou.
    """
    _refresh_if_needed()
    with _cache_lock:
        return list(_blacklist)


def force_reload() -> None:
    """Força recarga do Excel ignorando cache de hash."""
    global _file_hash
    with _cache_lock:
        _file_hash = ""
    _refresh_if_needed()


def sync_assets_from_cloud() -> bool:
    """
    Tenta baixar a planilha atualizada da nuvem (SharePoint ou OneDrive).
    Se tiver sucesso, força a recarga imediata para a memória.
    Retorna True se houve sucesso no download.
    """
    from core.clients.graph_client import download_assets
    
    logger.info("Iniciando sincronização de ativos na nuvem...")
    success = download_assets()
    if success:
        logger.info("Download concluído. Forçando recarga in-memory da planilha...")
        force_reload()
        return True
    return False
