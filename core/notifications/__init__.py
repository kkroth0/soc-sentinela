import config
from core.notifications.dispatcher import NotificationDispatcher
from core.notifications.teams_notifier import TeamsNotifier
from core.notifications.telegram_notifier import TelegramNotifier

def build_dispatcher() -> NotificationDispatcher:
    notifiers = []
    if config.TEAMS_WEBHOOK_URL_CVE or config.TEAMS_WEBHOOK_URL_CTI:
        notifiers.append(TeamsNotifier())
    if config.TELEGRAM_BOT_TOKEN and (config.TELEGRAM_CHAT_ID_CVE or config.TELEGRAM_CHAT_ID_CTI):
        notifiers.append(TelegramNotifier())
    return NotificationDispatcher(notifiers=notifiers)

global_dispatcher = build_dispatcher()
