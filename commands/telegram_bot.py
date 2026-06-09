"""
commands/telegram_bot.py — Escuta nativa de comandos via Telegram Bot API (Long Polling).
Comandos suportados: /start, /help, /status, /iniciar, /cti, /cves, /ativos, /recarregar
"""

import threading
import time
import requests
import html
from datetime import datetime, timezone
from typing import Any

import config
from core import storage, data_manager
from core.logger import get_logger
from core.clients.http_client import get_session
from cti import pipeline as cti_pipeline
from cve.aliases import reload_aliases
from cve.advisories import reload_advisories
from cti.scorer import reload_categories

logger = get_logger("commands.telegram_bot")

class TelegramBotListener:
    def __init__(self):
        self.running = False
        self.thread: threading.Thread | None = None
        self.offset = 0
        self.start_time = datetime.now(timezone.utc)
        self._pipeline_trigger_callback = None

    def set_pipeline_trigger(self, callback: Any) -> None:
        """Registra o callback de execução síncrona dos pipelines."""
        self._pipeline_trigger_callback = callback

    def start(self) -> None:
        """Inicia a escuta de comandos no Telegram em uma thread dedicada."""
        if self.running:
            logger.warning("Telegram Bot Listener já está rodando.")
            return
        
        self.running = True
        self.thread = threading.Thread(target=self._run_loop, name="telegram-bot-listener", daemon=True)
        self.thread.start()
        logger.info("Escuta de comandos do Telegram iniciada.")

    def stop(self) -> None:
        """Para a escuta de comandos."""
        if not self.running:
            return
        
        logger.info("Encerrando escuta de comandos do Telegram...")
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
            self.thread = None
        logger.info("Escuta de comandos do Telegram encerrada.")

    def _run_loop(self) -> None:
        session = get_session()
        url = f"https://api.telegram.org/bot{config.TELEGRAM_BOT_TOKEN}/getUpdates"
        
        # Limpa atualizações pendentes iniciais para evitar reprocessamento de comandos antigos
        try:
            resp = session.get(url, params={"timeout": 0, "limit": 10}, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("ok") and data.get("result"):
                    self.offset = data["result"][-1]["update_id"] + 1
                    logger.debug("Offset inicial do Telegram ajustado para %d", self.offset)
        except Exception as e:
            logger.debug("Não foi possível buscar atualizações iniciais: %s", e)

        while self.running:
            try:
                # Long polling: timeout de 20s
                params = {"offset": self.offset, "timeout": 20}
                resp = session.get(url, params=params, timeout=25)
                
                if resp.status_code != 200:
                    logger.error("Falha ao buscar updates do Telegram: HTTP %d", resp.status_code)
                    time.sleep(5)
                    continue

                updates = resp.json().get("result", [])
                for update in updates:
                    self.offset = update["update_id"] + 1
                    if "message" in update:
                        self._process_message(update["message"])
            except requests.exceptions.RequestException as e:
                # Erros normais de rede/timeout do long-polling
                logger.debug("Erro de rede ao buscar atualizações (long polling): %s", e)
                time.sleep(2)
            except Exception as e:
                logger.error("Erro inesperado no polling do Telegram: %s", e, exc_info=True)
                time.sleep(5)

    def _is_authorized(self, chat_id: int) -> bool:
        """Verifica se o chat_id está na lista de chats autorizados. Se vazia, autoriza por padrão."""
        if not config.TELEGRAM_ALLOWED_CHATS:
            return True
        return chat_id in config.TELEGRAM_ALLOWED_CHATS

    def _send_reply(self, chat_id: int, text: str) -> None:
        """Envia resposta para o chat."""
        from core.clients.telegram_client import send_message
        send_message(str(chat_id), text, parse_mode="HTML")

    def _process_message(self, message: dict[str, Any]) -> None:
        chat = message.get("chat", {})
        chat_id = chat.get("id")
        text = message.get("text", "").strip()

        if not chat_id or not text:
            return

        # Verifica autorização de acesso do chat/usuário
        if not self._is_authorized(chat_id):
            if text.startswith("/"):
                logger.warning("Tentativa de comando de chat não autorizado: %d (usuário: %s, comando: %s)", 
                               chat_id, chat.get("username", "desconhecido"), text)
                self._send_reply(chat_id, "🚫 <b>Acesso Não Autorizado</b>\nSeu ID de chat não está autorizado nas configurações deste bot.")
            return

        if not text.startswith("/"):
            return

        parts = text.split(maxsplit=1)
        command = parts[0].lower().split("@")[0] # Remove @nome_do_bot se houver

        logger.info("Comando recebido de chat %d: %s", chat_id, command)

        try:
            if command in ("/start", "/help"):
                self._handle_help(chat_id)
            elif command == "/status":
                self._handle_status(chat_id)
            elif command in ("/iniciar", "/run"):
                self._handle_iniciar(chat_id)
            elif command in ("/cti", "/latest"):
                self._handle_latest_cti(chat_id)
            elif command in ("/cves", "/cve"):
                self._handle_latest_cves(chat_id)
            elif command in ("/ativos", "/sync"):
                self._handle_sync_ativos(chat_id)
            elif command == "/recarregar":
                self._handle_recarregar(chat_id)
            else:
                self._send_reply(chat_id, f"❓ <b>Comando desconhecido:</b> {command}\nDigite /help para listar comandos.")
        except Exception as e:
            logger.error("Erro ao processar comando '%s': %s", command, e, exc_info=True)
            self._send_reply(chat_id, f"❌ <b>Erro interno ao processar comando:</b> {html.escape(str(e))}")

    def _handle_help(self, chat_id: int) -> None:
        msg = (
            "🤖 <b>SOC Sentinel — Assistente Threat Intelligence</b> 🛡️\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "Olá! Eu sou o assistente do SOC especializado em Cyber Threat Intelligence (CTI).\n\n"
            "<b>Comandos disponíveis:</b>\n"
            "🔹 `/status` — Uptime, configurações e estatísticas do sistema.\n"
            "🔹 `/iniciar` — Executa manualmente a varredura e análise de CTI.\n"
            "🔹 `/cti` ou `/latest` — Exibe as 10 últimas notícias CTI registradas.\n"
            "🔹 `/cves` — Exibe as 10 últimas CVEs priorizadas.\n"
            "🔹 `/ativos` — Recarrega o inventário local de ativos monitorados.\n"
            "🔹 `/recarregar` — Atualiza categorias CTI e aliases em memória.\n"
            "🔹 `/help` — Mostra esta lista de ajuda.\n\n"
            "<i>A coleta e análise automatizada de CTI continuam rodando em background periodicamente.</i>"
        )
        self._send_reply(chat_id, msg)

    def _handle_status(self, chat_id: int) -> None:
        uptime = self._get_uptime()
        
        # Consulta estatísticas do banco
        conn = storage.database.get_connection()
        try:
            total_news = conn.execute("SELECT COUNT(*) FROM sent_news").fetchone()[0]
            sent_news = conn.execute("SELECT COUNT(*) FROM sent_news WHERE status = 'SENT'").fetchone()[0]
            skipped_news = conn.execute("SELECT COUNT(*) FROM sent_news WHERE status = 'SKIPPED'").fetchone()[0]
            total_cves = conn.execute("SELECT COUNT(*) FROM sent_cves").fetchone()[0]
        except Exception as e:
            logger.error("Erro ao consultar stats do banco: %s", e)
            total_news = sent_news = skipped_news = total_cves = "?"

        msg = (
            "⚙️ <b>Status do Sistema</b>\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            f"🟢 <b>Bot:</b> Em execução\n"
            f"⏱️ <b>Tempo de Atividade:</b> {uptime}\n"
            f"🧠 <b>Modelo de IA:</b> {config.GROQ_MODEL}\n"
            f"⏱️ <b>Janela CTI:</b> {config.NEWS_TIME_WINDOW_MINUTES} min\n"
            f"🛡️ <b>Janela CVE:</b> {config.CVE_SCHEDULE_MINUTES} min\n\n"
            "📊 <b>Estatísticas da Base:</b>\n"
            f"• Total Notícias Analisadas: <b>{total_news}</b>\n"
            f"  └ 📬 Enviadas: <b>{sent_news}</b>\n"
            f"  └ ⏭️ Ignoradas: <b>{skipped_news}</b>\n"
            f"• CVEs Relacionadas / Salvas: <b>{total_cves}</b>"
        )
        self._send_reply(chat_id, msg)

    def _handle_iniciar(self, chat_id: int) -> None:
        if self._pipeline_trigger_callback:
            def run_async() -> None:
                self._send_reply(chat_id, "🔄 <b>Iniciando pipelines de coleta e análise manualmente...</b>")
                try:
                    self._pipeline_trigger_callback()
                    self._send_reply(chat_id, "✅ <b>Pipelines concluídos com sucesso!</b> Novos alertas foram encaminhados se identificados.")
                except Exception as e:
                    self._send_reply(chat_id, f"❌ <b>Erro na execução do pipeline:</b> {html.escape(str(e))}")

            threading.Thread(target=run_async, name="manual-telegram-trigger", daemon=True).start()
        else:
            self._send_reply(chat_id, "⚠️ Callback do pipeline não configurado no orquestrador.")

    def _handle_latest_cti(self, chat_id: int) -> None:
        news = storage.get_recent_news(limit=10)
        if not news:
            self._send_reply(chat_id, "📭 Nenhuma notícia CTI recente encontrada na base de dados.")
            return

        lines = ["📰 <b>Últimas Notícias CTI (Top 10)</b>", "━━━━━━━━━━━━━━━━━━━━━━"]
        for idx, item in enumerate(news, 1):
            title = html.escape(item.get("title", "Sem Título"))
            source = html.escape(item.get("source", "Desconhecido"))
            date = item.get("sent_at", "")[:16]
            lines.append(f"{idx}. <b>{title}</b>\n   └ Fonte: {source} | Data: {date}")
        
        self._send_reply(chat_id, "\n".join(lines))

    def _handle_latest_cves(self, chat_id: int) -> None:
        cves = storage.get_recent_cves(limit=10)
        if not cves:
            self._send_reply(chat_id, "📭 Nenhuma CVE recente registrada na base de dados.")
            return

        sev_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
        lines = ["🛡️ <b>Últimas CVEs (Top 10)</b>", "━━━━━━━━━━━━━━━━━━━━━━"]
        for idx, item in enumerate(cves, 1):
            cve_id = html.escape(str(item.get("cve_id", "?")))
            tag = str(item.get("risk_tag", "LOW"))
            emoji = sev_emoji.get(tag, "⚪")
            cvss = item.get("cvss_score")
            cvss_txt = f"CVSS {cvss}" if cvss is not None else "CVSS N/A"
            vendor = html.escape(str(item.get("vendor", "") or "—").upper())
            date = str(item.get("sent_at", ""))[:10]
            lines.append(f"{idx}. {emoji} <code>{cve_id}</code> ({cvss_txt} · {tag})\n   └ {vendor} | {date}")

        self._send_reply(chat_id, "\n".join(lines))

    def _handle_sync_ativos(self, chat_id: int) -> None:
        def sync_async() -> None:
            self._send_reply(chat_id, "🔄 <b>Recarregando inventário local de ativos...</b>")
            try:
                if data_manager.force_reload():
                    self._send_reply(chat_id, "✅ <b>Inventário recarregado!</b> Ativos atualizados a partir do arquivo local.")
                else:
                    self._send_reply(chat_id, "⚠️ <b>Arquivo de ativos não encontrado.</b> Verifique o caminho configurado em <code>ASSETS_CACHE_PATH</code>.")
            except Exception as e:
                self._send_reply(chat_id, f"❌ <b>Falha ao recarregar ativos:</b> {html.escape(str(e))}")

        threading.Thread(target=sync_async, name="telegram-assets-reload", daemon=True).start()

    def _handle_recarregar(self, chat_id: int) -> None:
        try:
            reload_aliases()
            reload_advisories()
            reload_categories()
            self._send_reply(chat_id, "✅ <b>Parâmetros (Aliases, Advisories e Categorias) recarregados com sucesso!</b>")
        except Exception as e:
            self._send_reply(chat_id, f"❌ <b>Erro ao recarregar parâmetros:</b> {html.escape(str(e))}")

    def _get_uptime(self) -> str:
        delta = datetime.now(timezone.utc) - self.start_time
        hours, remainder = divmod(int(delta.total_seconds()), 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{hours}h {minutes}m {seconds}s"

# Instância global do bot listener
telegram_bot = TelegramBotListener()
