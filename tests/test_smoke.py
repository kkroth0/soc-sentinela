"""
tests/test_smoke.py — Smoke Test do SOC Sentinel.
Simula o ciclo de inicialização (boot) do container Docker.
Garante que não há erros de import, de banco de dados, ou de configuração fatal.
"""

import os
import pytest
from unittest.mock import patch, MagicMock

# Importa módulos chave para garantir que não há SyntaxError ou ImportError
import config
from core import storage
from core.data_manager import force_reload, get_asset_map
from core.notifications import build_dispatcher


def test_smoke_database_initialization(tmp_path):
    """Testa se o SQLite inicializa as tabelas corretamente num diretório novo."""
    db_path = str(tmp_path / "smoke_test.db")
    
    with patch("config.BOT_DB_PATH", db_path):
        # A inicialização do banco ocorre globalmente ao importar core.storage, 
        # mas podemos chamar init_db() explicitamente para validar
        storage.init_db()
        
        assert os.path.exists(db_path)
        assert os.path.getsize(db_path) > 0


def test_smoke_dispatcher_initialization(monkeypatch):
    """Testa se o Dispatcher sobe corretamente com variáveis preenchidas e vazias."""
    # Teste com configs vazias (não deve explodir, apenas retorna 0 notifiers)
    monkeypatch.setattr("config.TEAMS_WEBHOOK_URL_CVE", "")
    monkeypatch.setattr("config.TEAMS_WEBHOOK_URL_CTI", "")
    monkeypatch.setattr("config.TELEGRAM_BOT_TOKEN", "")
    
    dispatcher_empty = build_dispatcher()
    assert len(dispatcher_empty.notifiers) == 0
    
    # Teste com configs preenchidas
    monkeypatch.setattr("config.TEAMS_WEBHOOK_URL_CVE", "http://teams")
    monkeypatch.setattr("config.TELEGRAM_BOT_TOKEN", "123:abc")
    monkeypatch.setattr("config.TELEGRAM_CHAT_ID_CTI", "999")
    
    dispatcher_full = build_dispatcher()
    # Deve carregar o TeamsNotifier e TelegramNotifier
    assert len(dispatcher_full.notifiers) == 2
    names = [n.name for n in dispatcher_full.notifiers]
    assert "Microsoft Teams" in names
    assert "Telegram" in names


def test_smoke_data_manager_fallback(monkeypatch):
    """Testa se o data_manager retorna dicionários vazios graciosamente sem o arquivo do Excel."""
    from core import data_manager
    monkeypatch.setattr(data_manager, "_asset_map", {})
    monkeypatch.setattr(data_manager, "_blacklist", [])
    
    with patch("config.ASSETS_CACHE_PATH", "/caminho/falso/que/nao/existe.xlsx"):
        # Forçar reload
        force_reload()
        
        am = get_asset_map()
        assert isinstance(am, dict)
        assert len(am) == 0
