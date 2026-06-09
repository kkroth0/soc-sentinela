"""
tests/commands/test_telegram_bot.py — Testes unitários para o listener do Telegram Bot.
"""

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import config
from commands.telegram_bot import TelegramBotListener


class TestTelegramBotListener:
    """Testes para o parser de comandos e segurança do Telegram Bot."""

    def test_is_authorized_when_chat_is_in_allowed_chats(self):
        bot = TelegramBotListener()
        with patch.object(config, "TELEGRAM_ALLOWED_CHATS", [123456, 987654]):
            assert bot._is_authorized(123456) is True
            assert bot._is_authorized(987654) is True
            assert bot._is_authorized(111111) is False

    def test_is_authorized_when_allowed_chats_is_empty(self):
        bot = TelegramBotListener()
        with patch.object(config, "TELEGRAM_ALLOWED_CHATS", []):
            assert bot._is_authorized(123456) is True

    @patch("commands.telegram_bot.TelegramBotListener._send_reply")
    def test_process_message_ignores_unauthorized_chat(self, mock_reply):
        bot = TelegramBotListener()
        with patch.object(config, "TELEGRAM_ALLOWED_CHATS", [123456]):
            msg = {
                "chat": {"id": 999999, "username": "hackerman"},
                "text": "/status"
            }
            bot._process_message(msg)
            
            # Deve enviar aviso de acesso negado
            mock_reply.assert_called_once()
            args, _ = mock_reply.call_args
            assert "Acesso Não Autorizado" in args[1]

    @patch("commands.telegram_bot.TelegramBotListener._send_reply")
    def test_process_message_ignores_non_command(self, mock_reply):
        bot = TelegramBotListener()
        with patch.object(config, "TELEGRAM_ALLOWED_CHATS", [123456]):
            msg = {
                "chat": {"id": 123456},
                "text": "Olá bot, tudo bem?"
            }
            bot._process_message(msg)
            mock_reply.assert_not_called()

    @patch("commands.telegram_bot.TelegramBotListener._handle_help")
    def test_process_message_routes_help_command(self, mock_help):
        bot = TelegramBotListener()
        with patch.object(config, "TELEGRAM_ALLOWED_CHATS", [123456]):
            msg = {
                "chat": {"id": 123456},
                "text": "/help"
            }
            bot._process_message(msg)
            mock_help.assert_called_once_with(123456)

    @patch("commands.telegram_bot.TelegramBotListener._handle_status")
    def test_process_message_routes_status_command(self, mock_status):
        bot = TelegramBotListener()
        with patch.object(config, "TELEGRAM_ALLOWED_CHATS", [123456]):
            msg = {
                "chat": {"id": 123456},
                "text": "/status"
            }
            bot._process_message(msg)
            mock_status.assert_called_once_with(123456)

    @patch("commands.telegram_bot.TelegramBotListener._handle_iniciar")
    def test_process_message_routes_iniciar_command(self, mock_iniciar):
        bot = TelegramBotListener()
        with patch.object(config, "TELEGRAM_ALLOWED_CHATS", [123456]):
            msg = {
                "chat": {"id": 123456},
                "text": "/iniciar"
            }
            bot._process_message(msg)
            mock_iniciar.assert_called_once_with(123456)
