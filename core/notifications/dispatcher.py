"""
core/notifications/dispatcher.py — Orquestrador Assíncrono de Notificações.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable

from core.models import StandardCVEAlert, StandardCTINews
from core.notifications.base import BaseNotifier
from core.logger import get_logger

logger = get_logger("core.notifications.dispatcher")


class NotificationDispatcher:
    """
    Despachante concorrente.
    Garante que lentidão num canal (ex: Teams) não afete outro (ex: Telegram).
    """

    def __init__(self, notifiers: list[BaseNotifier]):
        self.notifiers = notifiers

    def dispatch_cve(self, alert: StandardCVEAlert) -> bool:
        """Dispara alerta de CVE para todos os notifiers registrados."""
        return self._dispatch(lambda n: n.send_cve_alert(alert))

    def dispatch_cti(self, news: StandardCTINews) -> bool:
        """Dispara alerta de CTI para todos os notifiers registrados."""
        return self._dispatch(lambda n: n.send_cti_news(news))

    def dispatch_report(self, stats: dict[str, Any], report_type: str) -> bool:
        """Dispara relatório para todos os notifiers registrados."""
        return self._dispatch(lambda n: n.send_report(stats, report_type))

    def _dispatch(self, task: Callable[[BaseNotifier], bool]) -> bool:
        if not self.notifiers:
            logger.warning("NotificationDispatcher sem notifiers configurados.")
            return False

        success_count = 0
        with ThreadPoolExecutor(max_workers=max(len(self.notifiers), 1)) as executor:
            future_to_notifier = {
                executor.submit(task, notifier): notifier 
                for notifier in self.notifiers
            }
            
            for future in as_completed(future_to_notifier):
                notifier = future_to_notifier[future]
                try:
                    if future.result():
                        success_count += 1
                except Exception as exc:
                    logger.error("Notifier '%s' gerou exceção: %s", notifier.name, exc)
                    
        return success_count > 0

