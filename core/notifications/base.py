"""
core/notifications/base.py — Interfaces do Padrão Adapter.
"""

from abc import ABC, abstractmethod
from typing import Any

from core.models import StandardCVEAlert, StandardCTINews


class BaseNotifier(ABC):
    """Interface abstrata para adaptadores de notificação."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Nome legível do canal."""
        pass

    @abstractmethod
    def send_cve_alert(self, alert: StandardCVEAlert) -> bool:
        """Dispara um alerta de CVE. Deve retornar True se chegar ao destino."""
        pass

    @abstractmethod
    def send_cti_news(self, news: StandardCTINews) -> bool:
        """Dispara alerta de CTI. Deve retornar True se chegar ao destino."""
        pass

    @abstractmethod
    def send_report(self, stats: dict[str, Any], report_type: str) -> bool:
        """Dispara relatório semanal ou mensal. report_type: 'weekly' ou 'monthly'."""
        pass
