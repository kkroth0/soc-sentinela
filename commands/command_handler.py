"""
commands/command_handler.py — Servidor HTTP para comandos do Teams.
Endpoints: /ListeCVEs, /ListeCTI, /Status, /Iniciar, /health
"""

import io
import json
import csv
import threading
import hmac
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import config
from core import storage
from core.logger import get_logger

logger = get_logger("commands.command_handler")

_start_time: datetime = datetime.now(timezone.utc)
_pipeline_trigger_callback: Any = None


def set_pipeline_trigger(callback: Any) -> None:
    """Registra callback para trigger manual de pipelines."""
    global _pipeline_trigger_callback
    _pipeline_trigger_callback = callback


class CommandRequestHandler(BaseHTTPRequestHandler):
    """Handler para requisições de comandos do Teams."""

    def do_POST(self) -> None:
        """Processa requisições POST dos comandos."""
        path = self.path.rstrip("/")

        # 1. Autenticação (Opcional conforme solicitado, mas validada se houver Secret)
        if config.TEAMS_WEBHOOK_SECRET:
            auth = self.headers.get("Authorization", "")
            expected_auth = f"Bearer {config.TEAMS_WEBHOOK_SECRET}"
            if not hmac.compare_digest(auth, expected_auth):
                logger.warning("Tentativa de acesso não autorizado (Token inválido): %s", self.address_string())
                self._respond(401, {"error": "Unauthorized"})
                return
        else:
            # Log de auditoria para modo inseguro
            logger.debug("Comando recebido em modo INSEGURO (sem Secret): %s", path)

        # 2. Limite de segurança p/ Payload (DoS prevention)
        length = int(self.headers.get("Content-Length", 0))
        if length > 1 * 1024 * 1024:  # Max 1MB
            self._respond(413, {"error": "Payload too large"})
            return

        handlers = {
            "/ListeCVEs": self._handle_list_cves,
            "/ListeCTI": self._handle_list_cti,
            "/Status": self._handle_status,
            "/Iniciar": self._handle_iniciar,
            "/ExportarMes": self._handle_exportar_mes,
            "/AtualizarAtivos": self._handle_atualizar_ativos,
            "/Recarregar": self._handle_recarregar,
        }

        handler = handlers.get(path)
        if handler:
            handler()
        else:
            self._respond(404, {"error": f"Comando desconhecido: {path}"})

    def do_GET(self) -> None:
        """Health check endpoint."""
        if self.path.rstrip("/") == "/health":
            self._respond(200, {"status": "healthy", "uptime": self._get_uptime()})
        else:
            self._respond(404, {"error": "Not found"})

    def _handle_list_cves(self) -> None:
        """Lista as CVEs mais recentes enviadas."""
        cves = storage.get_recent_cves(limit=15)
        items = []
        for cve in cves:
            items.append({
                "cve_id": cve.get("cve_id"),
                "risk_tag": cve.get("risk_tag"),
                "cvss_score": cve.get("cvss_score"),
                "severity": cve.get("severity"),
                "sent_at": cve.get("sent_at"),
            })
        self._respond(200, {"cves": items, "count": len(items)})
        logger.info("Comando /ListeCVEs — %d resultados", len(items))

    def _handle_list_cti(self) -> None:
        """Lista as notícias mais recentes enviadas."""
        news = storage.get_recent_news(limit=15)
        items = []
        for article in news:
            items.append({
                "title": article.get("title"),
                "source": article.get("source"),
                "layer": article.get("layer"),
                "sent_at": article.get("sent_at"),
            })
        self._respond(200, {"news": items, "count": len(items)})
        logger.info("Comando /ListeCTI — %d resultados", len(items))

    def _handle_status(self) -> None:
        """Retorna status do bot."""
        uptime = self._get_uptime()
        self._respond(200, {
            "status": "running",
            "uptime": uptime,
            "time_window_cve": config.TIME_WINDOW_MINUTES,
            "time_window_cti": config.NEWS_TIME_WINDOW_MINUTES,
        })
        logger.info("Comando /Status executado")

    def _handle_iniciar(self) -> None:
        """Trigger manual dos pipelines."""
        if _pipeline_trigger_callback:
            threading.Thread(
                target=_pipeline_trigger_callback,
                name="manual-pipeline-trigger",
                daemon=True,
            ).start()
            self._respond(200, {"message": "Pipelines iniciados manualmente"})
            logger.info("Comando /Iniciar — pipelines triggerados")
        else:
            self._respond(503, {"error": "Pipeline trigger não configurado"})

    def _handle_exportar_mes(self) -> None:
        """Gera e retorna um CSV com todas as CVEs de um mês."""
        # Tenta pegar o mes do corpo (application/json) ou query param se houver
        year_month = datetime.now(timezone.utc).strftime("%Y-%m")
        try:
            length = int(self.headers.get("Content-Length", 0))
            if length > 0:
                body = json.loads(self.rfile.read(length))
                if "mes" in body:
                    year_month = body["mes"]
        except Exception:
            pass # Usa mês atual como padrão

        cves = storage.get_cves_for_month(year_month)
        
        # Monta CSV em memória
        output = io.StringIO()
        writer = csv.writer(output, delimiter=";", quoting=csv.QUOTE_MINIMAL)
        writer.writerow(["CVE ID", "Data Envio", "Vendor", "Product", "CVSS", "Risco", "Clientes Impactados"])
        
        for cve in cves:
            clients = ", ".join(json.loads(cve.get("impacted_clients", "[]")))
            writer.writerow([
                cve.get("cve_id"),
                cve.get("sent_at", "")[:10],
                cve.get("vendor", ""),
                cve.get("product", ""),
                cve.get("cvss_score", ""),
                cve.get("risk_tag", ""),
                clients
            ])
            
        csv_data = output.getvalue()
        
        # Envia como Download CSV
        self.send_response(200)
        self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header("Content-Disposition", f'attachment; filename="cves-{year_month}.csv"')
        self.end_headers()
        self.wfile.write(csv_data.encode("utf-8-sig")) # UTF-8 SIG p/ Excel
        logger.info("Comando /ExportarMes — Retornadas %d CVEs para %s", len(cves), year_month)

    def _handle_atualizar_ativos(self) -> None:
        """Sincroniza a planilha de ativos e responde imediatamente no background."""
        from core import data_manager

        def bg_sync() -> None:
            logger.info("Executando sincronização de ativos em background...")
            data_manager.sync_assets_from_cloud()

        threading.Thread(
            target=bg_sync,
            name="bg-asset-sync",
            daemon=True,
        ).start()

        self._respond(202, {"message": "Sincronização iniciada. Os dados serão atualizados em instantes."})
        logger.info("Comando /AtualizarAtivos executado")

    def _handle_recarregar(self) -> None:
        """Recarrega aliases e categorias CTI dinamicamente."""
        from cve.aliases import reload_aliases
        from cti.scorer import reload_categories
        
        try:
            reload_aliases()
            reload_categories()
            self._respond(200, {"message": "Parâmetros de inteligência recarregados com sucesso (Aliases e CTI Categories)."})
            logger.info("Comando /Recarregar — Aliases e Categorias CTI atualizados")
        except Exception as exc:
            logger.error("Erro ao recarregar parâmetros: %s", exc)
            self._respond(500, {"error": f"Falha ao recarregar: {exc}"})

    def _respond(self, status: int, body: dict) -> None:
        """Envia resposta JSON."""
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(body, ensure_ascii=False).encode("utf-8"))

    @staticmethod
    def _get_uptime() -> str:
        """Calcula uptime do bot."""
        delta = datetime.now(timezone.utc) - _start_time
        hours, remainder = divmod(int(delta.total_seconds()), 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{hours}h {minutes}m {seconds}s"

    def log_message(self, format: str, *args: Any) -> None:
        """Redireciona logs HTTP para o logger centralizado."""
        logger.debug(format, *args)


def start_server() -> HTTPServer:
    """Inicia o servidor HTTP de comandos em background."""
    server = HTTPServer(("0.0.0.0", config.COMMAND_PORT), CommandRequestHandler)
    thread = threading.Thread(
        target=server.serve_forever,
        name="command-server",
        daemon=True,
    )
    thread.start()
    logger.info("Servidor de comandos iniciado na porta %d", config.COMMAND_PORT)
    return server
