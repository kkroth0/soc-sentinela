"""
core/notifications/__init__.py — Instância única do notificador Telegram.
"""
from core.notifications.telegram_notifier import TelegramNotifier

# Canal de saída único do projeto (Telegram). O nome antigo `global_dispatcher`
# vinha da época em que havia múltiplos canais (Teams) e foi removido.
telegram_dispatcher = TelegramNotifier()
