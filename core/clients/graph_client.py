"""
core/clients/graph_client.py — Integração performática com Microsoft Graph & OneDrive.
Implementa cache de token MSAL para evitar round-trips desnecessários.
"""
import msal
from typing import Optional, Any
import config
from core.clients import http_client
from core.logger import get_logger

logger = get_logger("core.clients.graph_client")

# Singleton do MSAL para persistência de cache de token em memória
_msal_app: Optional[msal.ConfidentialClientApplication] = None

def _get_msal_app() -> Optional[msal.ConfidentialClientApplication]:
    """Retorna ou inicializa o Singleton do MSAL."""
    global _msal_app
    if _msal_app is not None:
        return _msal_app

    if not all([config.GRAPH_TENANT_ID, config.GRAPH_CLIENT_ID, config.GRAPH_CLIENT_SECRET]):
        logger.debug("Credenciais Graph API incompletas — ignorando autenticação Entra ID.")
        return None

    authority = f"https://login.microsoftonline.com/{config.GRAPH_TENANT_ID}"
    _msal_app = msal.ConfidentialClientApplication(
        config.GRAPH_CLIENT_ID,
        authority=authority,
        client_credential=config.GRAPH_CLIENT_SECRET,
    )
    return _msal_app

def _get_access_token() -> Optional[str]:
    """Obtém token de acesso usando cache em RAM sempre que possível."""
    app = _get_msal_app()
    if not app:
        return None

    scopes = ["https://graph.microsoft.com/.default"]
    
    # 1. Tenta buscar no cache (RAM)
    result = app.acquire_token_silent(scopes, account=None)
    if result:
        return result.get("access_token")

    # 2. Busca novo token na Microsoft
    logger.info("Solicitando novo token de acesso ao Entra ID...")
    result = app.acquire_token_for_client(scopes=scopes)
    
    if "access_token" in result:
        return result["access_token"]
    
    error_msg = result.get("error_description") or result.get("error", "Erro desconhecido")
    logger.error("Falha na autenticação Microsoft: %s", error_msg)
    return None

def download_file(url: str, local_path: str) -> bool:
    """Download de arquivo via Graph API ou Link Direto OneDrive."""
    try:
        headers = {}
        # Se for Graph API, injeta o token
        if "graph.microsoft.com" in url:
            token = _get_access_token()
            if not token:
                logger.error("Download abortado: não foi possível obter token Graph.")
                return False
            headers["Authorization"] = f"Bearer {token}"

        response = http_client.get(url, headers=headers, stream=True)
        if response.status_code == 200:
            with open(local_path, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            logger.info("Download concluído: %s", local_path)
            return True
        else:
            logger.error("Falha no download (HTTP %d): %s", response.status_code, url)
            return False
    except Exception as exc:
        logger.error("Erro no download de arquivo: %s", exc)
        return False

def download_assets() -> bool:
    """
    Helper específico para baixar a planilha de ativos.
    Tenta SharePoint (Graph) ou OneDrive (Link Direto).
    """
    # 1. Tenta SharePoint via Graph API
    if all([config.GRAPH_CLIENT_ID, config.SHAREPOINT_SITE_URL, config.SHAREPOINT_FILE_PATH]):
        # Monta URL do Graph para download do arquivo (simplificado)
        # Em produção, essa URL deve ser resolvida via Site ID / Drive ID
        url = f"{config.GRAPH_BASE_URL}/sites/{config.SHAREPOINT_SITE_URL}/drive/root:/{config.SHAREPOINT_FILE_PATH}:/content"
        logger.info("Tentando sincronizar ativos via SharePoint...")
        return download_file(url, config.ASSETS_CACHE_PATH)

    # 2. Tenta OneDrive Link Direto
    if config.ONEDRIVE_DIRECT_URL:
        logger.info("Tentando sincronizar ativos via OneDrive Link Direto...")
        return download_file(config.ONEDRIVE_DIRECT_URL, config.ASSETS_CACHE_PATH)

    logger.debug("Nenhuma configuração de nuvem detectada para ativos. Usando cache local.")
    return False
