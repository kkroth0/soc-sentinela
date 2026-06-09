"""
core/notifications/formatters — utilitários compartilhados de formatação.
"""

# Limite duro da Telegram Bot API para o campo `text` de sendMessage.
TELEGRAM_MAX_LEN: int = 4096


def clamp_telegram(msg: str, limit: int = TELEGRAM_MAX_LEN) -> str:
    """Garante que a mensagem caiba no limite da Telegram sem cortar tags HTML.

    Como os cartões são montados linha a linha (cada tag inline abre e fecha na
    mesma linha), cortar na última quebra de linha antes do limite preserva a
    marcação HTML válida.
    """
    if len(msg) <= limit:
        return msg
    suffix = "\n\n… <i>(mensagem truncada)</i>"
    budget = limit - len(suffix)
    cut = msg.rfind("\n", 0, budget)
    if cut == -1:
        cut = budget
    return msg[:cut].rstrip() + suffix
