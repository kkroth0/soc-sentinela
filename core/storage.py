"""
core/storage.py — SQLite com tabelas separadas por pipeline.
Tabelas: sent_cves, sent_news, weekly_summary.
Bug fix #3: Lock em memória para prevenir race condition no processamento de CVEs.
"""

import json
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any

import config
from core.logger import get_logger

logger = get_logger("core.storage")

_db_lock = threading.Lock()
_processing_cves: set[str] = set()
_processing_lock = threading.Lock()

_connection: sqlite3.Connection | None = None


def _get_connection() -> sqlite3.Connection:
    """Retorna uma conexão persistente protegida pelo _db_lock."""
    global _connection
    if _connection is None:
        _connection = sqlite3.connect(config.BOT_DB_PATH, timeout=10, check_same_thread=False)
        _connection.row_factory = sqlite3.Row
        _connection.execute("PRAGMA journal_mode=WAL")
    return _connection


def close_db() -> None:
    """Encerra a conexão persistente."""
    global _connection
    with _db_lock:
        if _connection:
            _connection.close()
            _connection = None


def init_db() -> None:
    """Cria as tabelas se não existirem."""
    with _db_lock:
        conn = _get_connection()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS sent_cves (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id          TEXT    NOT NULL UNIQUE,
                cvss_score      REAL,
                severity        TEXT,
                risk_tag        TEXT,
                vendor          TEXT DEFAULT '',
                product         TEXT DEFAULT '',
                impacted_clients TEXT   DEFAULT '[]',
                sent_at         TEXT,
                payload_json    TEXT
            );

            CREATE TABLE IF NOT EXISTS sent_news (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                article_url TEXT    NOT NULL UNIQUE,
                title       TEXT,
                source      TEXT,
                layer       INTEGER,
                sent_at     TEXT,
                status      TEXT DEFAULT 'SENT'
            );

            CREATE TABLE IF NOT EXISTS weekly_summary (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                period_key     TEXT,
                cve_count      INTEGER,
                news_count     INTEGER,
                critical_count INTEGER,
                high_count     INTEGER,
                created_at     TEXT
            );

            CREATE TABLE IF NOT EXISTS monthly_summary (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                period_key     TEXT    NOT NULL UNIQUE,
                cve_count      INTEGER,
                news_count     INTEGER,
                critical_count INTEGER,
                high_count     INTEGER,
                medium_count   INTEGER,
                low_count      INTEGER,
                avg_cvss       REAL,
                top_vendors    TEXT DEFAULT '[]',
                top_products   TEXT DEFAULT '[]',
                top_clients    TEXT DEFAULT '[]',
                created_at     TEXT
            );
        """)
        logger.info("Banco de dados inicializado em %s", config.BOT_DB_PATH)
        
        try:
            conn.execute("ALTER TABLE sent_cves ADD COLUMN vendor TEXT DEFAULT ''")
            conn.execute("ALTER TABLE sent_cves ADD COLUMN product TEXT DEFAULT ''")
        except sqlite3.OperationalError:
            pass # Colunas já existem

        try:
            conn.execute("ALTER TABLE sent_news ADD COLUMN status TEXT DEFAULT 'SENT'")
        except sqlite3.OperationalError:
            pass


# ─── CVE deduplication ────────────────────────────────────────────────

def acquire_cve_lock(cve_id: str) -> bool:
    """
    Tenta adquirir lock de processamento para uma CVE.
    Bug fix #3: Previne race condition entre ciclos de processamento.
    Retorna True se adquiriu (CVE não está em processamento), False caso contrário.
    """
    with _processing_lock:
        if cve_id in _processing_cves:
            return False
        _processing_cves.add(cve_id)
        return True


def release_cve_lock(cve_id: str) -> None:
    """Libera lock de processamento de uma CVE."""
    with _processing_lock:
        _processing_cves.discard(cve_id)


def is_cve_sent(cve_id: str) -> bool:
    """Verifica se a CVE já foi enviada ao Teams."""
    with _db_lock:
        conn = _get_connection()
        try:
            row = conn.execute(
                "SELECT 1 FROM sent_cves WHERE cve_id = ?", (cve_id,)
            ).fetchone()
            return row is not None
        except Exception as exc:
            logger.error("Erro no SQLite (is_cve_sent): %s", exc)
            return False


def save_cve(cve: dict[str, Any]) -> None:
    """Grava CVE enviada no banco. impacted_clients é sempre JSON array."""
    now = datetime.now(timezone.utc).isoformat()
    clients_json = json.dumps(cve.get("impacted_clients", []))
    payload_json = json.dumps(cve.get("payload"), default=str) if cve.get("payload") else None

    with _db_lock:
        conn = _get_connection()
        try:
            conn.execute(
                """INSERT OR IGNORE INTO sent_cves
                   (cve_id, cvss_score, severity, risk_tag, vendor, product, impacted_clients, sent_at, payload_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    cve["cve_id"],
                    cve.get("cvss_score"),
                    cve.get("severity"),
                    cve.get("risk_tag"),
                    str(cve.get("vendor", "")).strip().lower(),
                    str(cve.get("product", "")).strip().lower(),
                    clients_json,
                    now,
                    payload_json,
                ),
            )
            conn.commit()
            logger.info("CVE %s gravada no banco", cve["cve_id"])
        except Exception as exc:
            logger.error("Erro ao gravar CVE no banco: %s", exc)


# ─── News deduplication ───────────────────────────────────────────────

def is_news_sent(article_url: str) -> bool:
    """Verifica se a notícia já foi enviada ao Teams."""
    with _db_lock:
        conn = _get_connection()
        try:
            row = conn.execute(
                "SELECT 1 FROM sent_news WHERE article_url = ?", (article_url,)
            ).fetchone()
            return row is not None
        except Exception as exc:
            logger.error("Erro no SQLite (is_news_sent): %s", exc)
            return False


def save_news(article: dict[str, Any], status: str = "SENT") -> None:
    """Grava notícia no banco com status (SENT ou SKIPPED)."""
    now = datetime.now(timezone.utc).isoformat()
    with _db_lock:
        conn = _get_connection()
        try:
            conn.execute(
                """INSERT OR IGNORE INTO sent_news
                   (article_url, title, source, layer, sent_at, status)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    article["url"],
                    article.get("title"),
                    article.get("source"),
                    article.get("layer"),
                    now,
                    status,
                ),
            )
            conn.commit()
            if status == "SENT":
                logger.info("Notícia gravada: %s", article.get("title", article["url"]))
        except Exception as exc:
            logger.error("Erro ao gravar notícia no banco: %s", exc)


# ─── Weekly summary ───────────────────────────────────────────────────

def save_weekly_summary(
    period_key: str,
    cve_count: int,
    news_count: int,
    critical_count: int,
    high_count: int,
) -> None:
    """Grava resumo semanal."""
    now = datetime.now(timezone.utc).isoformat()
    with _db_lock:
        conn = _get_connection()
        try:
            conn.execute(
                """INSERT INTO weekly_summary
                   (period_key, cve_count, news_count, critical_count, high_count, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (period_key, cve_count, news_count, critical_count, high_count, now),
            )
            conn.commit()
            logger.info("Resumo semanal %s gravado", period_key)
        except Exception as exc:
            logger.error("Erro ao gravar resumo semanal no banco: %s", exc)


# ─── Query helpers (para commands e reports) ──────────────────────────

def get_recent_cves(limit: int = 10) -> list[dict[str, Any]]:
    """Retorna as CVEs mais recentes enviadas."""
    with _db_lock:
        conn = _get_connection()
        try:
            rows = conn.execute(
                "SELECT * FROM sent_cves ORDER BY sent_at DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(row) for row in rows]
        except Exception as exc:
            logger.error("Erro no SQLite (get_recent_cves): %s", exc)
            return []


def get_cves_for_month(year_month: str) -> list[dict[str, Any]]:
    """Retorna todas as CVEs enviadas em um mês específico (Formato YYYY-MM)."""
    with _db_lock:
        conn = _get_connection()
        try:
            rows = conn.execute(
                "SELECT * FROM sent_cves WHERE sent_at LIKE ? ORDER BY sent_at DESC", 
                (f"{year_month}%",)
            ).fetchall()
            return [dict(row) for row in rows]
        except Exception as exc:
            logger.error("Erro no SQLite (get_cves_for_month): %s", exc)
            return []


def get_recent_news(limit: int = 10) -> list[dict[str, Any]]:
    """Retorna as notícias mais recentes enviadas (status SENT)."""
    with _db_lock:
        conn = _get_connection()
        try:
            rows = conn.execute(
                "SELECT * FROM sent_news WHERE status = 'SENT' ORDER BY sent_at DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(row) for row in rows]
        except Exception as exc:
            logger.error("Erro no SQLite (get_recent_news): %s", exc)
            return []


def get_cve_stats(since: str, until: str = "") -> dict[str, int]:
    """Retorna contagens de CVEs por risk_tag em um período."""
    with _db_lock:
        conn = _get_connection()
        try:
            if until:
                rows = conn.execute(
                    """SELECT risk_tag, COUNT(*) as cnt
                       FROM sent_cves WHERE sent_at >= ? AND sent_at <= ?
                       GROUP BY risk_tag""",
                    (since, until),
                ).fetchall()
            else:
                rows = conn.execute(
                    """SELECT risk_tag, COUNT(*) as cnt
                       FROM sent_cves WHERE sent_at >= ?
                       GROUP BY risk_tag""",
                    (since,),
                ).fetchall()
            return {row["risk_tag"]: row["cnt"] for row in rows}
        except Exception as exc:
            logger.error("Erro no SQLite (get_cve_stats): %s", exc)
            return {}


def get_news_count(since: str, until: str = "") -> int:
    """Retorna total de notícias enviadas em um período."""
    with _db_lock:
        conn = _get_connection()
        try:
            if until:
                row = conn.execute(
                    "SELECT COUNT(*) as cnt FROM sent_news WHERE sent_at >= ? AND sent_at <= ? AND status = 'SENT'",
                    (since, until),
                ).fetchone()
            else:
                row = conn.execute(
                    "SELECT COUNT(*) as cnt FROM sent_news WHERE sent_at >= ? AND status = 'SENT'", (since,)
                ).fetchone()
            return row["cnt"] if row else 0
        except Exception as exc:
            logger.error("Erro no SQLite (get_news_count): %s", exc)
            return 0


# ─── Analytical queries (Reports) ───────────────────────────────────────

def get_cves_by_vendor(since: str, until: str) -> list[dict[str, Any]]:
    """Top vendors por quantidade de CVEs, com breakdown por risco."""
    with _db_lock:
        conn = _get_connection()
        try:
            rows = conn.execute(
                """SELECT vendor,
                          COUNT(*) as total,
                          SUM(CASE WHEN risk_tag = 'CRITICAL' THEN 1 ELSE 0 END) as critical,
                          SUM(CASE WHEN risk_tag = 'HIGH' THEN 1 ELSE 0 END) as high,
                          ROUND(AVG(cvss_score), 1) as avg_cvss
                   FROM sent_cves
                   WHERE sent_at >= ? AND sent_at <= ? AND vendor != ''
                   GROUP BY vendor
                   ORDER BY total DESC
                   LIMIT 5""",
                (since, until),
            ).fetchall()
            return [dict(row) for row in rows]
        except Exception as exc:
            logger.error("Erro no SQLite (get_cves_by_vendor): %s", exc)
            return []


def get_cves_by_product(since: str, until: str) -> list[dict[str, Any]]:
    """Top produtos por quantidade de CVEs."""
    with _db_lock:
        conn = _get_connection()
        try:
            rows = conn.execute(
                """SELECT product, vendor,
                          COUNT(*) as total,
                          ROUND(AVG(cvss_score), 1) as avg_cvss
                   FROM sent_cves
                   WHERE sent_at >= ? AND sent_at <= ? AND product != ''
                   GROUP BY product
                   ORDER BY total DESC
                   LIMIT 5""",
                (since, until),
            ).fetchall()
            return [dict(row) for row in rows]
        except Exception as exc:
            logger.error("Erro no SQLite (get_cves_by_product): %s", exc)
            return []


def get_most_impacted_clients(since: str, until: str) -> list[dict[str, Any]]:
    """Top clientes mais impactados. Parseia JSON de impacted_clients."""
    with _db_lock:
        conn = _get_connection()
        try:
            rows = conn.execute(
                "SELECT impacted_clients FROM sent_cves WHERE sent_at >= ? AND sent_at <= ?",
                (since, until),
            ).fetchall()

            client_counts: dict[str, int] = {}
            for row in rows:
                clients = json.loads(row["impacted_clients"] or "[]")
                for client in clients:
                    client_counts[client] = client_counts.get(client, 0) + 1

            sorted_clients = sorted(client_counts.items(), key=lambda x: x[1], reverse=True)[:5]
            return [{"client": c, "count": n} for c, n in sorted_clients]
        except Exception as exc:
            logger.error("Erro no SQLite (get_most_impacted_clients): %s", exc)
            return []


def get_news_by_source(since: str, until: str) -> list[dict[str, Any]]:
    """Top fontes de notícias CTI."""
    with _db_lock:
        conn = _get_connection()
        try:
            rows = conn.execute(
                """SELECT source, layer, COUNT(*) as total
                   FROM sent_news
                   WHERE sent_at >= ? AND sent_at <= ? AND status = 'SENT'
                   GROUP BY source
                   ORDER BY total DESC
                   LIMIT 5""",
                (since, until),
            ).fetchall()
            return [dict(row) for row in rows]
        except Exception as exc:
            logger.error("Erro no SQLite (get_news_by_source): %s", exc)
            return []


def get_avg_cvss(since: str, until: str) -> float:
    """Retorna CVSS médio das CVEs em um período."""
    with _db_lock:
        conn = _get_connection()
        try:
            row = conn.execute(
                "SELECT ROUND(AVG(cvss_score), 1) as avg FROM sent_cves WHERE sent_at >= ? AND sent_at <= ? AND cvss_score IS NOT NULL",
                (since, until),
            ).fetchone()
            return float(row["avg"]) if row and row["avg"] else 0.0
        except Exception as exc:
            logger.error("Erro no SQLite (get_avg_cvss): %s", exc)
            return 0.0


def save_monthly_summary(stats: dict[str, Any]) -> None:
    """Grava resumo mensal com dados analíticos completos."""
    now = datetime.now(timezone.utc).isoformat()
    with _db_lock:
        conn = _get_connection()
        try:
            conn.execute(
                """INSERT OR REPLACE INTO monthly_summary
                   (period_key, cve_count, news_count, critical_count, high_count,
                    medium_count, low_count, avg_cvss, top_vendors, top_products, top_clients, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    stats.get("period", ""),
                    stats.get("cve_count", 0),
                    stats.get("news_count", 0),
                    stats.get("risk_breakdown", {}).get("CRITICAL", 0),
                    stats.get("risk_breakdown", {}).get("HIGH", 0),
                    stats.get("risk_breakdown", {}).get("MEDIUM", 0),
                    stats.get("risk_breakdown", {}).get("LOW", 0),
                    stats.get("avg_cvss", 0.0),
                    json.dumps(stats.get("top_vendors", []), default=str),
                    json.dumps(stats.get("top_products", []), default=str),
                    json.dumps(stats.get("top_clients", []), default=str),
                    now,
                ),
            )
            conn.commit()
            logger.info("Resumo mensal %s gravado", stats.get("period"))
        except Exception as exc:
            logger.error("Erro ao gravar resumo mensal: %s", exc)
