"""
bot.py — Orquestrador principal do SOC Sentinel.
Agenda e inicializa o pipeline CTI e relatórios via APScheduler.
"""

import signal
import sys
import time
from datetime import datetime, timezone

from apscheduler.schedulers.background import BackgroundScheduler

import config
from commands.telegram_bot import telegram_bot
from core import storage, data_manager
from core.logger import get_logger
from cti import pipeline as cti_pipeline
from cve import pipeline as cve_pipeline
from reports import reporter
from reports import patch_tuesday

logger = get_logger("bot")


def _run_all_pipelines() -> None:
    """Executa os pipelines CTI e CVE (usado pelo trigger manual /iniciar)."""
    cti_pipeline.run()
    try:
        cve_pipeline.run()
    except Exception as exc:
        logger.error("Falha ao executar o pipeline CVE no trigger manual: %s", exc)


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

        ----------------------------------------------------------------------
        Sistema iniciado e pronto para monitoramento
        ----------------------------------------------------------------------
    """
    logger.info(banner)

    # ── 0. Graceful shutdown (Mover para o início para capturar Ctrl+C cedo) ──
    def _shutdown(signum: int = 0, frame: object = None) -> None:
        from core.clients import http_client
        logger.info("Iniciando encerramento seguro do SOC Sentinel...")
        try:
            scheduler.shutdown(wait=False)
        except Exception as exc:
            logger.debug("Scheduler já encerrado ou erro no shutdown: %s", exc)
        
        try:
            telegram_bot.stop()
        except Exception as exc:
            logger.debug("Erro ao parar Telegram Bot: %s", exc)
        
        # Garante fechamento de recursos
        storage.close_db()
        http_client.close_session()
        
        logger.info("Bot finalizado. Até logo! 🛡️")
        sys.exit(0)

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

    # ── 2.1 Health server (Docker HEALTHCHECK / DO App Platform) ──────
    from core import health
    health.start_health_server(config.HEALTH_PORT)

    # ── 3. Iniciar bot do Telegram ────────────────────────────────────
    telegram_bot.set_pipeline_trigger(_run_all_pipelines)
    telegram_bot.start()

    # ── 4. Configurar scheduler ───────────────────────────────────────
    scheduler = BackgroundScheduler(timezone="UTC")
    
    now = datetime.now(timezone.utc)


    scheduler.add_job(cti_pipeline.run, "interval", minutes=config.NEWS_TIME_WINDOW_MINUTES, next_run_time=now, id="cti_pipeline", name="Pipeline CTI", max_instances=1, coalesce=True)
    scheduler.add_job(cve_pipeline.run, "interval", minutes=config.CVE_SCHEDULE_MINUTES, next_run_time=now, id="cve_pipeline", name="Pipeline CVE", max_instances=1, coalesce=True)
    scheduler.add_job(reporter.run_weekly_report, "cron", day_of_week="mon", hour=8, minute=0, id="weekly_report", name="Relatório Semanal", max_instances=1)
    scheduler.add_job(reporter.run_monthly_report, "cron", day=1, hour=8, minute=0, id="monthly_report", name="Relatório Mensal", max_instances=1)

    # Patch Tuesday: 2ª terça do mês (único dia 8–14 que cai numa terça).
    # Dispara logo após a publicação MSRC (~17-18h UTC); o coletor faz poll
    # caso o documento ainda não esteja no ar.
    if config.PATCH_TUESDAY_ENABLED:
        scheduler.add_job(
            patch_tuesday.run_patch_tuesday, "cron",
            day="8-14", day_of_week="tue",
            hour=config.PATCH_TUESDAY_HOUR, minute=config.PATCH_TUESDAY_MINUTE,
            id="patch_tuesday", name="Relatório Patch Tuesday", max_instances=1, coalesce=True,
        )

    # ── 5. Carga inicial do inventário local de ativos ────────────────
    logger.info("Carregando inventário local de ativos antes dos pipelines...")
    try:
        if not data_manager.force_reload():
            logger.warning("Inventário de ativos não encontrado em %s — CVE matching ficará vazio até o arquivo existir.", config.ASSETS_CACHE_PATH)
    except Exception as exc:
        logger.error("Falha na carga inicial de ativos: %s", exc)

    # ── 6. Iniciar scheduler (background) ─────────────────────────────
    logger.info("Scheduler iniciado — Pipeline CTI despachado ✅")
    scheduler.start()
    
    try:
        while True:
            health.beat()  # mantém o heartbeat do health check vivo
            time.sleep(1)
    except (KeyboardInterrupt, SystemExit):
        _shutdown()


if __name__ == "__main__":
    main()
