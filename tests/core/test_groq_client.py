"""
tests/core/test_groq_client.py — Testes de Integração simulados para o cliente Groq.
"""

import pytest
from unittest.mock import patch, MagicMock

from core.clients.groq_client import chat_completion


@pytest.fixture
def mock_config(monkeypatch):
    monkeypatch.setattr("config.GROQ_API_KEY", "fake_groq_key")
    monkeypatch.setattr("config.GROQ_BASE_URL", "https://api.groq.com/openai/v1")
    monkeypatch.setattr("config.GROQ_MODEL", "llama-3.3-70b-versatile")


@patch("core.clients.groq_client.http_client.post")
def test_chat_completion_success(mock_post, mock_config):
    """Testa chamada bem sucedida à API da Groq."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "choices": [
            {
                "message": {
                    "content": "This is a simulated AI response."
                }
            }
        ]
    }
    mock_post.return_value = mock_resp

    messages = [{"role": "user", "content": "Hello"}]
    response = chat_completion(messages)

    assert response == "This is a simulated AI response."
    mock_post.assert_called_once()
    
    # Valida payload
    kwargs = mock_post.call_args.kwargs
    assert kwargs["headers"]["Authorization"] == "Bearer fake_groq_key"
    assert kwargs["json"]["model"] == "llama-3.3-70b-versatile"
    assert kwargs["json"]["messages"] == messages


@patch("core.clients.groq_client.http_client.post")
def test_chat_completion_http_error(mock_post, mock_config):
    """Testa comportamento quando Groq retorna erro HTTP."""
    mock_resp = MagicMock()
    mock_resp.status_code = 500
    mock_resp.text = "Internal Server Error"
    mock_post.return_value = mock_resp

    response = chat_completion([{"role": "user", "content": "Hello"}])
    assert response is None


@patch("core.clients.groq_client.config")
def test_chat_completion_missing_api_key(mock_cfg):
    """Testa comportamento sem API Key configurada."""
    mock_cfg.GROQ_API_KEY = ""
    
    response = chat_completion([{"role": "user", "content": "Hello"}])
    assert response is None
