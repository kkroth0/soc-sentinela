"""
core/clients/graph_client.py — Integração com Microsoft Graph & OneDrive.
Lida com a autenticação no Entra ID (Azure AD) via Client Credentials e 
com o download de arquivos em nuvem (SharePoint ou OneDrive link direto).
"""

import os
from typing import Optional

import msal
import requests

import config
from core.clients import http_client
from core.logger import get_logger

logger = get_logger("core.clients.graph_client")


def _get_access_token() -> Optional[str]:
    """Obtém token Oauth2 Client Credentials (App Registration)."""
    if not all([config.GRAPH_TENANT_ID, config.GRAPH_CLIENT_ID, config.GRAPH_CLIENT_SECRET]):
        logger.debug("Credenciais da Graph API ausentes ou incompletas.")
        return None

    authority = f"https://login.microsoftonline.com/{config.GRAPH_TENANT_ID}"
    app = msal.ConfidentialClientApplication(
        config.GRAPH_CLIENT_ID,
        authority=authority,
        client_credential=config.GRAPH_CLIENT_SECRET,
    )

    scopes = ["https://graph.microsoft.com/.default"]
    result = app.acquire_token_silent(scopes, account=None)

    if not result:
        result = app.acquire_token_for_client(scopes=scopes)

    if result and "access_token" in result:
        return result["access_token"]

    logger.error("Falha ao obter token Graph: %s", result.get("error_description", result.get("error")))
    return None


def _download_from_graph(token: str, save_path: str) -> bool:
    """
    Baixa arquivo via Microsoft Graph API.
    Requer que as variáveis de site e caminho estejam precisas.
    Exemplo de SHAREPOINT_SITE_URL: "contoso.sharepoint.com:/sites/SOC"
    Exemplo de SHAREPOINT_FILE_PATH: "/Documentos Compartilhados/clients_assets.xlsx"
    """
    if not config.SHAREPOINT_SITE_URL or not config.SHAREPOINT_FILE_PATH:
        logger.warning("SHAREPOINT_SITE_URL ou SHAREPOINT_FILE_PATH não configurados.")
        return False

    # Extrai o site path no formato suportado pela Graph API
    site_url = config.SHAREPOINT_SITE_URL.replace("https://", "").strip("/")
    file_path = config.SHAREPOINT_FILE_PATH.strip("/")
    
    # Endpoint Graph API para obter o conteúdo diretamente via site_path
    url = f"{config.GRAPH_BASE_URL}/sites/{site_url}:/drive/root:/{file_path}:/content"

    try:
        logger.info("Baixando planilha via Graph API...")
        response = requests.get(
            url,
            headers={"Authorization": f"Bearer {token}"},
            timeout=15,
            stream=True
        )
        if response.status_code == 200:
            with open(save_path, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            logger.info("Download via Graph API concluído com sucesso.")
            return True
        else:
            logger.error("Erro na Graph API HTTP %d: %s", response.status_code, response.text)
            return False
    except Exception as exc:
        logger.error("Exceção ao baixar do SharePoint: %s", exc)
        return False


def _download_from_direct_link(save_path: str) -> bool:
    """
    Baixa o arquivo através de um Link Direto anônimo (OneDrive / Drive / Cdn).
    """
    url = config.ONEDRIVE_DIRECT_URL
    if not url:
        logger.debug("ONEDRIVE_DIRECT_URL não configurado.")
        return False

    try:
        logger.info("Tentando baixar planilha via Link Direto (Fallback)...")
        response = http_client.get(url, timeout=15)
        if response.status_code == 200:
            with open(save_path, "wb") as f:
                f.write(response.content)
            logger.info("Download via Link Direto concluído com sucesso.")
            return True
        else:
            logger.warning("Erro HTTP %d ao baixar via link direto.", response.status_code)
            return False
    except Exception as exc:
        logger.error("Exceção no download do link direto: %s", exc)
        return False


def download_assets() -> bool:
    """
    Tenta baixar a planilha clients_assets.xlsx da nuvem.
    Ordem de tentativa:
    1. Microsoft Graph API (SharePoint corporativo).
    2. Link Direto HTTP (OneDrive / Alternativo).
    Retorna True se salvou o arquivo em config.ASSETS_CACHE_PATH.
    """
    save_path = config.ASSETS_CACHE_PATH
    
    # Tenta via Graph API (Recomendado para corporativo)
    token = _get_access_token()
    if token:
        success = _download_from_graph(token, save_path)
        if success:
            return True

    # Tenta via Link Direto (Fallback)
    if _download_from_direct_link(save_path):
        return True

    logger.warning("Sincronização em nuvem não foi possível. O bot usará o cache local se existir.")
    return False
