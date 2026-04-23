"""
tests/core/test_graph_client.py — Testes de Integração com MSAL e Graph API.
Testa autenticação, download via SharePoint, e fallback para Link Direto do OneDrive.
"""

import pytest
from unittest.mock import patch, MagicMock

from core.clients.graph_client import download_assets, _get_access_token


@pytest.fixture
def mock_config(monkeypatch):
    monkeypatch.setattr("config.GRAPH_TENANT_ID", "tenant-id")
    monkeypatch.setattr("config.GRAPH_CLIENT_ID", "client-id")
    monkeypatch.setattr("config.GRAPH_CLIENT_SECRET", "secret")
    monkeypatch.setattr("config.SHAREPOINT_SITE_URL", "https://tenant.sharepoint.com/sites/SOC")
    monkeypatch.setattr("config.SHAREPOINT_FILE_PATH", "Documents/assets.xlsx")
    monkeypatch.setattr("config.ONEDRIVE_DIRECT_URL", "https://onedrive.live.com/download?cid=...")


@patch("core.clients.graph_client.msal.ConfidentialClientApplication")
def test_graph_client_auth_success(mock_msal, mock_config):
    """Testa se o MSAL adquire token com sucesso."""
    mock_app = MagicMock()
    mock_app.acquire_token_silent.return_value = None
    mock_app.acquire_token_for_client.return_value = {"access_token": "mock_token"}
    mock_msal.return_value = mock_app

    token = _get_access_token()
    assert token == "mock_token"
    mock_app.acquire_token_for_client.assert_called_once_with(scopes=["https://graph.microsoft.com/.default"])


@patch("core.clients.graph_client.msal.ConfidentialClientApplication")
def test_graph_client_auth_failure(mock_msal, mock_config):
    """Testa se o client lida com falha de autenticação do MSAL."""
    mock_app = MagicMock()
    mock_app.acquire_token_silent.return_value = None
    mock_app.acquire_token_for_client.return_value = {"error": "invalid_client"}
    mock_msal.return_value = mock_app

    token = _get_access_token()
    assert token is None


@patch("core.clients.graph_client._get_access_token")
@patch("core.clients.graph_client.requests.get")
@patch("core.clients.graph_client.config")
def test_download_assets_sharepoint_success(mock_cfg, mock_requests_get, mock_get_token, tmp_path):
    """Testa download via Graph API (SharePoint) bem sucedido."""
    mock_get_token.return_value = "mock_token"
    
    mock_cfg.SHAREPOINT_SITE_URL = "tenant.sharepoint.com:/sites/SOC"
    mock_cfg.SHAREPOINT_FILE_PATH = "/Documents/assets.xlsx"
    mock_cfg.GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"
    
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.iter_content.return_value = [b"fake-excel-data"]
    mock_requests_get.return_value = mock_resp

    dest_path = tmp_path / "assets.xlsx"
    mock_cfg.ASSETS_CACHE_PATH = str(dest_path)

    result = download_assets()

    assert result is True
    assert dest_path.exists()
    assert dest_path.read_bytes() == b"fake-excel-data"


@patch("core.clients.graph_client._get_access_token")
@patch("core.clients.graph_client.http_client.get")
@patch("core.clients.graph_client.config")
def test_download_assets_fallback_onedrive(mock_cfg, mock_http_get, mock_get_token, tmp_path):
    """Testa o fallback para o OneDrive (link direto) quando SharePoint falha."""
    mock_get_token.return_value = None
    
    mock_cfg.ONEDRIVE_DIRECT_URL = "https://onedrive.live.com/test"
    
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.content = b"fallback-excel-data"
    mock_http_get.return_value = mock_resp

    dest_path = tmp_path / "assets_fallback.xlsx"
    mock_cfg.ASSETS_CACHE_PATH = str(dest_path)

    result = download_assets()

    assert result is True
    assert dest_path.exists()
    assert dest_path.read_bytes() == b"fallback-excel-data"


@patch("core.clients.graph_client._get_access_token")
@patch("core.clients.graph_client.http_client.get")
@patch("core.clients.graph_client.config")
def test_download_assets_total_failure(mock_cfg, mock_http_get, mock_get_token, tmp_path):
    """Testa comportamento quando todas as estratégias falham."""
    mock_get_token.return_value = None
    mock_cfg.ONEDRIVE_DIRECT_URL = "https://onedrive.live.com/test"
    
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_http_get.return_value = mock_resp

    dest_path = tmp_path / "assets_fail.xlsx"
    mock_cfg.ASSETS_CACHE_PATH = str(dest_path)

    result = download_assets()

    assert result is False
    assert not dest_path.exists()
