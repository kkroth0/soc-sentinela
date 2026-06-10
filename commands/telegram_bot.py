"""
commands/telegram_bot.py — Escuta nativa de comandos via Telegram Bot API (Long Polling).
Comandos suportados: /start, /help, /status, /iniciar, /cti, /cves, /patchtuesday, /ativos, /recarregar
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
                    elif "callback_query" in update:
                        self._process_callback(update["callback_query"])
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
                self._send_reply(chat_id, "<b>ACCESS DENIED</b>\nThis chat is not authorized.")
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
                arg = parts[1].strip() if len(parts) > 1 else ""
                if command == "/cve" and arg:
                    self._handle_cve_lookup(chat_id, arg)
                else:
                    self._handle_latest_cves(chat_id)
            elif command == "/feeds":
                self._handle_feeds(chat_id)
            elif command == "/stats":
                arg = parts[1].strip() if len(parts) > 1 else ""
                self._handle_stats(chat_id, arg)
            elif command in ("/faq", "/ajuda"):
                self._handle_faq(chat_id)
            elif command in ("/ativos", "/sync"):
                self._handle_sync_ativos(chat_id)
            elif command == "/recarregar":
                self._handle_recarregar(chat_id)
            elif command in ("/patchtuesday", "/patch"):
                self._handle_patch_tuesday(chat_id)
            elif command in ("/idioma", "/language", "/lang"):
                self._handle_language(chat_id)
            else:
                self._send_reply(chat_id, f"<b>Unknown command:</b> {html.escape(command)}\nType /help for the command reference.")
        except Exception as e:
            logger.error("Erro ao processar comando '%s': %s", command, e, exc_info=True)
            self._send_reply(chat_id, f"<b>Internal error:</b> {html.escape(str(e))}")

    def _handle_help(self, chat_id: int) -> None:
        msg = (
            "<b>SOC SENTINEL COMMAND CENTER</b>\n"
            "<i>Threat Intelligence • Vulnerability Intelligence • Threat Monitoring</i>\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "<b>[ Intelligence ]</b>\n"
            "<pre>/cti          Latest CTI reports\n"
            "/iniciar      Run collection pipeline\n"
            "/stats        Metrics dashboard\n"
            "/feeds        Source health</pre>\n"
            "<b>[ Vulnerabilities ]</b>\n"
            "<pre>/cves         Prioritized CVE feed\n"
            "/cve &lt;id&gt;     Look up a specific CVE\n"
            "/patchtuesday Microsoft Patch Tuesday report</pre>\n"
            "<b>[ Platform ]</b>\n"
            "<pre>/status       Health and statistics\n"
            "/idioma       Set alert language\n"
            "/faq          How the platform works\n"
            "/recarregar   Reload configurations\n"
            "/ativos       Reload monitored assets\n"
            "/help         Command reference</pre>\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "Status: OPERATIONAL\n"
            "Collection Pipelines: ACTIVE\n"
            "Threat Monitoring: ACTIVE\n\n"
            f"<i>{config.SIGNATURE}</i>"
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
            "<b>SOC SENTINEL · SYSTEM STATUS</b>\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "<b>[ Runtime ]</b>\n"
            "<pre>"
            f"State       OPERATIONAL\n"
            f"Uptime      {uptime}\n"
            f"AI Model    {config.GROQ_MODEL}\n"
            f"CTI Window  {config.NEWS_TIME_WINDOW_MINUTES} min\n"
            f"CVE Window  {config.CVE_SCHEDULE_MINUTES} min"
            "</pre>\n"
            "<b>[ Database ]</b>\n"
            "<pre>"
            f"News Analyzed   {total_news}\n"
            f"  Sent          {sent_news}\n"
            f"  Skipped       {skipped_news}\n"
            f"CVEs Stored     {total_cves}"
            "</pre>\n"
            f"<i>{config.SIGNATURE}</i>"
        )
        self._send_reply(chat_id, msg)

    def _handle_iniciar(self, chat_id: int) -> None:
        if self._pipeline_trigger_callback:
            def run_async() -> None:
                self._send_reply(chat_id, "<b>Collection pipeline started</b> — running manually...")
                try:
                    self._pipeline_trigger_callback()
                    self._send_reply(chat_id, "<b>Pipeline complete.</b> New alerts dispatched if any were identified.")
                except Exception as e:
                    self._send_reply(chat_id, f"<b>Pipeline error:</b> {html.escape(str(e))}")

            threading.Thread(target=run_async, name="manual-telegram-trigger", daemon=True).start()
        else:
            self._send_reply(chat_id, "Pipeline trigger not configured in the orchestrator.")

    def _handle_latest_cti(self, chat_id: int) -> None:
        news = storage.get_recent_news(limit=10)
        if not news:
            self._send_reply(chat_id, "No recent CTI reports in the database.")
            return

        lines = ["<b>LATEST CTI REPORTS · TOP 10</b>", "━━━━━━━━━━━━━━━━━━━━━━━━"]
        for idx, item in enumerate(news, 1):
            title = html.escape(item.get("title", "Untitled"))
            source = html.escape(item.get("source", "Unknown"))
            date = item.get("sent_at", "")[:16]
            lines.append(f"{idx}. <b>{title}</b>\n    {source} | {date}")

        self._send_reply(chat_id, "\n".join(lines))

    def _handle_latest_cves(self, chat_id: int) -> None:
        cves = storage.get_recent_cves(limit=10)
        if not cves:
            self._send_reply(chat_id, "No recent CVEs in the database.")
            return

        sev_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
        lines = ["<b>PRIORITIZED CVE FEED · TOP 10</b>", "━━━━━━━━━━━━━━━━━━━━━━━━"]
        for idx, item in enumerate(cves, 1):
            cve_id = str(item.get("cve_id", "?"))
            cve_id_safe = html.escape(cve_id)
            tag = str(item.get("risk_tag", "LOW"))
            emoji = sev_emoji.get(tag, "⚪")
            cvss = item.get("cvss_score")
            cvss_txt = f"CVSS {cvss}" if cvss is not None else "CVSS N/A"
            vendor = str(item.get("vendor", "") or "").upper()
            product = str(item.get("product", "") or "").upper()
            date = str(item.get("sent_at", ""))[:10]
            nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

            # Linha 1: CVE como link clicável para a NVD + severidade
            lines.append(f'{idx}. {emoji} <a href="{nvd_url}">{cve_id_safe}</a> — {cvss_txt} · {tag}')
            # Linha 2: vendor/produto (se houver) + data
            meta = []
            if vendor:
                meta.append(html.escape(vendor))
            if product:
                meta.append(html.escape(product))
            meta.append(date)
            lines.append("    " + " · ".join(meta))

        self._send_reply(chat_id, "\n".join(lines))

    def _handle_sync_ativos(self, chat_id: int) -> None:
        def sync_async() -> None:
            self._send_reply(chat_id, "<b>Reloading monitored asset inventory...</b>")
            try:
                if data_manager.force_reload():
                    self._send_reply(chat_id, "<b>Inventory reloaded.</b> Assets updated from the local file.")
                else:
                    self._send_reply(chat_id, "<b>Asset file not found.</b> Check the <code>ASSETS_CACHE_PATH</code> setting.")
            except Exception as e:
                self._send_reply(chat_id, f"<b>Asset reload failed:</b> {html.escape(str(e))}")

        threading.Thread(target=sync_async, name="telegram-assets-reload", daemon=True).start()

    def _handle_patch_tuesday(self, chat_id: int) -> None:
        """Dispara manualmente o relatório de Patch Tuesday do mês atual."""
        def run_async() -> None:
            from cve import msrc_client
            from reports import patch_tuesday

            doc_id = msrc_client.get_patch_tuesday_doc_id()
            self._send_reply(
                chat_id,
                f"<b>Generating Patch Tuesday report ({html.escape(doc_id)})...</b>\n"
                "<i>Fetching the MSRC document and building attachments — this may take a few seconds.</i>",
            )
            try:
                # force=True: envio manual intencional (ignora guarda de duplicidade).
                # poll=False: se o documento do mês ainda não foi publicado, falha rápido.
                sent = patch_tuesday.run_patch_tuesday(force=True, poll=False)
                if sent:
                    self._send_reply(chat_id, "<b>Patch Tuesday report sent.</b>")
                else:
                    self._send_reply(
                        chat_id,
                        f"<b>Could not generate the report.</b>\n"
                        f"Document <code>{html.escape(doc_id)}</code> may not have been "
                        "published by Microsoft yet, or sending failed. Check the logs.",
                    )
            except Exception as e:
                self._send_reply(chat_id, f"<b>Patch Tuesday error:</b> {html.escape(str(e))}")

        threading.Thread(target=run_async, name="telegram-patch-tuesday", daemon=True).start()

    def _handle_recarregar(self, chat_id: int) -> None:
        try:
            reload_aliases()
            reload_advisories()
            reload_categories()
            self._send_reply(chat_id, "<b>Configurations reloaded</b> — feeds aliases, advisories and categories.")
        except Exception as e:
            self._send_reply(chat_id, f"<b>Reload error:</b> {html.escape(str(e))}")

    def _handle_language(self, chat_id: int) -> None:
        """Exibe o menu de seleção de idioma de saída dos alertas."""
        from core.clients.telegram_client import send_message
        current = str(storage.get_state("output_language", config.DEFAULT_OUTPUT_LANGUAGE)).lower()
        current_label = config.LANG_LABELS.get(current, current)
        text = (
            "<b>ALERT LANGUAGE</b>\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"Current: <b>{html.escape(current_label)}</b>\n\n"
            "Select the language for AI-generated alert content:"
        )
        keyboard = {"inline_keyboard": [[
            {"text": "Português", "callback_data": "setlang:pt"},
            {"text": "English", "callback_data": "setlang:en"},
        ]]}
        send_message(str(chat_id), text, parse_mode="HTML", reply_markup=keyboard)

    def _process_callback(self, cb: dict[str, Any]) -> None:
        """Trata cliques em teclados inline (ex.: seleção de idioma)."""
        from core.clients.telegram_client import answer_callback_query, send_message
        cb_id = cb.get("id", "")
        data = cb.get("data", "")
        chat_id = cb.get("message", {}).get("chat", {}).get("id")

        if not chat_id or not self._is_authorized(chat_id):
            answer_callback_query(cb_id, "Not authorized")
            return

        if data.startswith("setlang:"):
            lang = data.split(":", 1)[1]
            if lang in config.LANG_LABELS:
                storage.set_state("output_language", lang)
                label = config.LANG_LABELS[lang]
                logger.info("Idioma de saída alterado para '%s' por chat %s", lang, chat_id)
                answer_callback_query(cb_id, f"Language set: {label}")
                send_message(
                    str(chat_id),
                    f"<b>Alert language set to {html.escape(label)}.</b>\n"
                    "New alerts will be generated in this language.",
                    parse_mode="HTML",
                )
            else:
                answer_callback_query(cb_id, "Unknown language")
        elif data == "faq_menu":
            answer_callback_query(cb_id)
            self._handle_faq(chat_id)
        elif data.startswith("faq:"):
            answer_callback_query(cb_id)
            self._send_faq_topic(chat_id, data.split(":", 1)[1])
        elif data.startswith("stats:"):
            answer_callback_query(cb_id)
            try:
                days = int(data.split(":", 1)[1])
            except ValueError:
                days = 7
            self._handle_stats(chat_id, str(days))
        else:
            answer_callback_query(cb_id)

    def _handle_cve_lookup(self, chat_id: int, arg: str) -> None:
        """Consulta sob demanda de uma CVE específica (/cve CVE-YYYY-NNNN)."""
        import re
        m = re.search(r"CVE-\d{4}-\d{4,}", arg, re.IGNORECASE)
        if not m:
            self._send_reply(chat_id, "Invalid CVE id. Example: <code>/cve CVE-2021-44228</code>")
            return
        cve_id = m.group(0).upper()

        def run_async() -> None:
            self._send_reply(chat_id, f"<b>Looking up {cve_id}…</b>")
            try:
                from cve.pipeline import build_single_cve_alert
                from core.notifications.formatters.cve_formatter import build_cve_telegram_message
                alert = build_single_cve_alert(cve_id)
                if alert is None:
                    self._send_reply(chat_id, f"<b>{cve_id}</b> not found in the NVD.")
                    return
                self._send_reply(chat_id, build_cve_telegram_message(alert))
            except Exception as e:
                logger.error("Erro no lookup de CVE %s: %s", cve_id, e, exc_info=True)
                self._send_reply(chat_id, f"<b>Lookup error:</b> {html.escape(str(e))}")

        threading.Thread(target=run_async, name="cve-lookup", daemon=True).start()

    def _handle_feeds(self, chat_id: int) -> None:
        """Painel de saúde das fontes (/feeds)."""
        def run_async() -> None:
            try:
                from cti.rss_client import feed_health
                from core.notifications.formatters.report_formatter import build_feeds_telegram
                rows = feed_health()
                self._send_reply(chat_id, build_feeds_telegram(rows))
            except Exception as e:
                logger.error("Erro no /feeds: %s", e, exc_info=True)
                self._send_reply(chat_id, f"<b>Feed check error:</b> {html.escape(str(e))}")

        threading.Thread(target=run_async, name="feeds-health", daemon=True).start()

    def _handle_stats(self, chat_id: int, arg: str = "") -> None:
        """Painel de métricas (/stats) com botões 7/30 dias."""
        from datetime import timedelta
        from core.clients.telegram_client import send_message
        from core.notifications.formatters.report_formatter import build_stats_telegram

        days = 30 if ("30" in arg) else 7
        until = datetime.now(timezone.utc)
        since = until - timedelta(days=days)
        try:
            stats = storage.get_report_stats(since.isoformat(), until.isoformat())
        except Exception as e:
            logger.error("Erro no /stats: %s", e, exc_info=True)
            self._send_reply(chat_id, f"<b>Stats error:</b> {html.escape(str(e))}")
            return

        text = build_stats_telegram(stats, f"Last {days} days")
        keyboard = {"inline_keyboard": [[
            {"text": "7 days", "callback_data": "stats:7"},
            {"text": "30 days", "callback_data": "stats:30"},
        ]]}
        send_message(str(chat_id), text, parse_mode="HTML", reply_markup=keyboard)

    def _handle_faq(self, chat_id: int) -> None:
        """Menu inline do FAQ (/faq)."""
        from core.clients.telegram_client import send_message
        from commands.faq_content import FAQ
        text = (
            "<b>SOC SENTINEL · FAQ</b>\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "Select a topic:"
        )
        buttons = [[{"text": label, "callback_data": f"faq:{tid}"}] for tid, (label, _) in FAQ.items()]
        send_message(str(chat_id), text, parse_mode="HTML", reply_markup={"inline_keyboard": buttons})

    def _send_faq_topic(self, chat_id: int, topic_id: str) -> None:
        """Envia o corpo de um tópico do FAQ com botão de voltar."""
        from core.clients.telegram_client import send_message
        from commands.faq_content import FAQ
        entry = FAQ.get(topic_id)
        if not entry:
            return
        _, body = entry
        keyboard = {"inline_keyboard": [[{"text": "« Back", "callback_data": "faq_menu"}]]}
        send_message(str(chat_id), body, parse_mode="HTML", reply_markup=keyboard)

    def _get_uptime(self) -> str:
        delta = datetime.now(timezone.utc) - self.start_time
        hours, remainder = divmod(int(delta.total_seconds()), 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{hours}h {minutes}m {seconds}s"

# Instância global do bot listener
telegram_bot = TelegramBotListener()
