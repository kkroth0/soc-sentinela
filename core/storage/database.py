"""
core/storage/database.py — Gerenciamento de conexão e schema SQLite.
"""
import sqlite3
import threading
import config
from core.logger import get_logger

logger = get_logger("core.storage.db")

_db_lock = threading.Lock()
_connection: sqlite3.Connection | None = None

def get_connection() -> sqlite3.Connection:
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
        conn = get_connection()
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

            CREATE TABLE IF NOT EXISTS system_state (
                key   TEXT PRIMARY KEY,
                value TEXT,
                updated_at TEXT
            );
        """)
        logger.info("Banco de dados inicializado em %s", config.BOT_DB_PATH)
        
        # Migrations simplificadas
        try:
            conn.execute("ALTER TABLE sent_cves ADD COLUMN vendor TEXT DEFAULT ''")
            conn.execute("ALTER TABLE sent_cves ADD COLUMN product TEXT DEFAULT ''")
        except sqlite3.OperationalError: pass

        try:
            conn.execute("ALTER TABLE sent_news ADD COLUMN status TEXT DEFAULT 'SENT'")
        except sqlite3.OperationalError: pass
