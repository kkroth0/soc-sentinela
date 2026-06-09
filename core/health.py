"""
core/health.py — Servidor HTTP mínimo de health check (liveness/readiness).

Consumido pelo Docker HEALTHCHECK e por plataformas como o DigitalOcean App
Platform. Responde em `/health` com 200 enquanto o loop principal estiver
batendo o heartbeat; 503 se o processo travar (heartbeat velho). Não expõe
nenhum dado sensível.
"""
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from core.logger import get_logger

logger = get_logger("core.health")

# Se o loop principal não bater por mais que isto, consideramos o bot travado.
_STALE_AFTER_S: int = 600

_start_time: float = time.time()
_heartbeat: dict[str, float] = {"ts": time.time()}


def beat() -> None:
    """Marca que o loop principal está vivo. Chamado periodicamente pelo bot."""
    _heartbeat["ts"] = time.time()


class _HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 (assinatura da stdlib)
        if self.path.rstrip("/") in ("/health", "/healthz", ""):
            age = time.time() - _heartbeat["ts"]
            healthy = age < _STALE_AFTER_S
            body = json.dumps({
                "status": "ok" if healthy else "stale",
                "uptime_s": int(time.time() - _start_time),
                "heartbeat_age_s": int(age),
            }).encode("utf-8")
            self.send_response(200 if healthy else 503)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *args, **kwargs) -> None:  # silencia logs de acesso
        return


def start_health_server(port: int) -> None:
    """Sobe o health server numa thread daemon (não bloqueia o bot)."""
    def _serve() -> None:
        try:
            server = ThreadingHTTPServer(("0.0.0.0", port), _HealthHandler)
            logger.info("Health server ouvindo em 0.0.0.0:%d/health", port)
            server.serve_forever()
        except Exception as exc:
            logger.error("Falha ao iniciar o health server na porta %d: %s", port, exc)

    threading.Thread(target=_serve, name="health-server", daemon=True).start()
