"""
bot.py — Orquestrador principal do SOC Sentinel.
Agenda e inicializa pipelines CVE/CTI e relatórios via APScheduler.
"""

import signal
import sys
import time

from apscheduler.schedulers.blocking import BlockingScheduler

import config
from commands import command_handler
from core import storage, data_manager
from core.logger import get_logger
from cve import pipeline as cve_pipeline
from cti import pipeline as cti_pipeline
from reports import reporter

logger = get_logger("bot")


def _run_all_pipelines() -> None:
    """Executa ambos os pipelines (usado pelo trigger manual)."""
    cve_pipeline.run()
    cti_pipeline.run()


def main() -> None:
    """Ponto de entrada do SOC Sentinel."""
    banner = r"""
    ███████╗ ██████╗  ██████╗ 
    ██╔════╝██╔═══██╗██╔════╝ 
    ███████╗██║   ██║██║      
    ╚════██║██║   ██║██║      
    ███████║╚██████╔╝╚██████╗ 
    ╚══════╝ ╚═════╝  ╚═════╝ 
        
        🛡️  Security Operations Center – Monitoring & Automation
        
        Version: 1.0.0 | Status: Active Monitoring
        © 2026 @kkroth0 - Matheus Andrade

══════════════════════════════════════════════════════════════════════
✓ Sistema iniciado e pronto para monitoramento
══════════════════════════════════════════════════════════════════════
    """
    for line in banner.splitlines():
        if line.strip():
            logger.info(line)

    # ── 0. Graceful shutdown (Mover para o início para capturar Ctrl+C cedo) ──
    def _shutdown(signum: int = 0, frame: object = None) -> None:
        import os
        from core.clients import http_client
        logger.info("Iniciando encerramento seguro do SOC Sentinel...")
        try:
            scheduler.shutdown(wait=False)
        except Exception:
            pass
        
        # Garante fechamento de recursos
        storage.close_db()
        http_client.close_session()
        
        logger.info("Bot finalizado. Até logo! 🛡️")
        os._exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)
    if hasattr(signal, 'SIGBREAK'): # Suporte específico para Windows
        signal.signal(signal.SIGBREAK, _shutdown)

    # ── 1. Validar Configurações ──────────────────────────────────────
    try:
        config.validate_config()
    except Exception as exc:
        logger.error(str(exc))
        sys.exit(1)

    # ── 2. Inicializar banco de dados ─────────────────────────────────
    storage.init_db()

    # ── 3. Iniciar servidor de comandos ───────────────────────────────
    command_handler.set_pipeline_trigger(_run_all_pipelines)
    command_handler.start_server()

    # ── 4. Configurar scheduler ───────────────────────────────────────
    scheduler = BlockingScheduler(timezone="UTC")

    scheduler.add_job(cve_pipeline.run, "interval", minutes=config.TIME_WINDOW_MINUTES, id="cve_pipeline", name="Pipeline CVE", max_instances=1, coalesce=True)
    scheduler.add_job(cti_pipeline.run, "interval", minutes=config.NEWS_TIME_WINDOW_MINUTES, id="cti_pipeline", name="Pipeline CTI", max_instances=1, coalesce=True)
    scheduler.add_job(reporter.run_weekly_report, "cron", day_of_week="mon", hour=8, minute=0, id="weekly_report", name="Relatório Semanal", max_instances=1)
    scheduler.add_job(reporter.run_monthly_report, "cron", day=1, hour=8, minute=0, id="monthly_report", name="Relatório Mensal", max_instances=1)
    scheduler.add_job(data_manager.sync_assets_from_cloud, "interval", hours=12, id="sync_assets", name="Sincronização de Ativos", max_instances=1, coalesce=True)

    # ── 5. Execução inicial imediata ──────────────────────────────────
    logger.info("Executando inicialização do ambiente...")
    try:
        data_manager.sync_assets_from_cloud()
        cve_pipeline.run()
        cti_pipeline.run()
    except Exception as exc:
        logger.error("Falha na carga inicial: %s", exc)

    # ── 6. Iniciar scheduler (blocking) ───────────────────────────────
    logger.info("Scheduler iniciado — SOC Sentinel operacional ✅")
    try:
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        _shutdown()


if __name__ == "__main__":
    main()
