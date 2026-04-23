"""
bot.py — Orquestrador principal do SOC Sentinel.
Agenda e inicializa pipelines CVE/CTI e relatórios via APScheduler.
"""

import signal
import sys

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

    # ── 1. Inicializar banco de dados ─────────────────────────────────
    storage.init_db()

    # ── 2. Iniciar servidor de comandos ───────────────────────────────
    command_handler.set_pipeline_trigger(_run_all_pipelines)
    command_handler.start_server()
    logger.info("Servidor de comandos ativo na porta %d", config.COMMAND_PORT)

    # ── 3. Configurar scheduler ───────────────────────────────────────
    scheduler = BlockingScheduler(timezone="UTC")

    # Pipeline CVE — a cada TIME_WINDOW_MINUTES
    scheduler.add_job(
        cve_pipeline.run,
        "interval",
        minutes=config.TIME_WINDOW_MINUTES,
        id="cve_pipeline",
        name="Pipeline CVE",
        max_instances=1,
        coalesce=True,
    )
    logger.info("Pipeline CVE agendado: a cada %d minutos", config.TIME_WINDOW_MINUTES)

    # Pipeline CTI — a cada NEWS_TIME_WINDOW_MINUTES
    scheduler.add_job(
        cti_pipeline.run,
        "interval",
        minutes=config.NEWS_TIME_WINDOW_MINUTES,
        id="cti_pipeline",
        name="Pipeline CTI",
        max_instances=1,
        coalesce=True,
    )
    logger.info("Pipeline CTI agendado: a cada %d minutos", config.NEWS_TIME_WINDOW_MINUTES)

    # Relatório semanal — toda segunda-feira às 08:00 UTC
    scheduler.add_job(
        reporter.run_weekly_report,
        "cron",
        day_of_week="mon",
        hour=8,
        minute=0,
        id="weekly_report",
        name="Relatório Semanal",
        max_instances=1,
    )
    logger.info("Relatório semanal agendado: segunda-feira 08:00 UTC")

    # Relatório mensal — dia 1 de cada mês às 08:00 UTC
    scheduler.add_job(
        reporter.run_monthly_report,
        "cron",
        day=1,
        hour=8,
        minute=0,
        id="monthly_report",
        name="Relatório Mensal",
        max_instances=1,
    )
    logger.info("Relatório mensal agendado: dia 1 às 08:00 UTC")

    # Sincronização de Ativos (Planilha na Nuvem) — a cada 12 horas
    scheduler.add_job(
        data_manager.sync_assets_from_cloud,
        "interval",
        hours=12,
        id="sync_assets",
        name="Sincronização de Ativos",
        max_instances=1,
        coalesce=True,
    )
    logger.info("Sincronização de ativos agendada: a cada 12 horas")

    # ── 4. Graceful shutdown ──────────────────────────────────────────
    def _shutdown(signum: int, frame: object) -> None:
        logger.info("Sinal %d recebido — encerrando gracefully...", signum)
        storage.close_db()
        scheduler.shutdown(wait=False)
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    # ── 5. Execução inicial imediata ──────────────────────────────────
    logger.info("Executando inicialização do ambiente...")
    try:
        # Sincroniza arquivos ANTES de rodar pipelines
        data_manager.sync_assets_from_cloud()
        logger.info("Rodando pipelines iniciais...")
        _run_all_pipelines()
    except Exception as exc:
        logger.error("Falha na execução inicial: %s", exc)

    # ── 6. Iniciar scheduler (blocking) ───────────────────────────────
    logger.info("Scheduler iniciado — SOC Sentinel operacional ✅")
    try:
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        logger.info("SOC Sentinel encerrado.")


if __name__ == "__main__":
    main()
