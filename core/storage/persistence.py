"""
core/storage/persistence.py — Lógica de CRUD, Deduplicação e Locks.
"""
import json
import threading
import re
from datetime import datetime, timezone, timedelta
from typing import Any

from core.logger import get_logger
from core.storage.database import get_connection, _db_lock
from core.utils.dates import now_iso

logger = get_logger("core.storage.persistence")

_processing_cves: set[str] = set()
_processing_news: set[str] = set()
_processing_lock = threading.Lock()

def acquire_cve_lock(cve_id: str) -> bool:
    with _processing_lock:
        if cve_id in _processing_cves: return False
        _processing_cves.add(cve_id)
        return True

def release_cve_lock(cve_id: str) -> None:
    with _processing_lock: _processing_cves.discard(cve_id)

def is_cve_sent(cve_id: str) -> bool:
    with _db_lock:
        conn = get_connection()
        row = conn.execute("SELECT 1 FROM sent_cves WHERE cve_id = ?", (cve_id,)).fetchone()
        return row is not None

def save_cve(cve: dict[str, Any]) -> None:
    now = now_iso()
    clients_json = json.dumps(cve.get("impacted_clients", []))
    payload_json = json.dumps(cve.get("payload"), default=str) if cve.get("payload") else None
    with _db_lock:
        conn = get_connection()
        try:
            with conn:
                conn.execute(
                    """INSERT OR IGNORE INTO sent_cves
                       (cve_id, cvss_score, severity, risk_tag, vendor, product, impacted_clients, sent_at, payload_json)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (cve["cve_id"], cve.get("cvss_score"), cve.get("severity"), cve.get("risk_tag"),
                     str(cve.get("vendor", "")).strip().lower(), str(cve.get("product", "")).strip().lower(),
                     clients_json, now, payload_json)
                )
        except Exception as exc:
            logger.error("Erro ao gravar CVE: %s", exc)

def acquire_news_lock(url: str) -> bool:
    with _processing_lock:
        if url in _processing_news: return False
        _processing_news.add(url)
        return True

def release_news_lock(url: str) -> None:
    with _processing_lock: _processing_news.discard(url)

def _normalize_url(url: str) -> str:
    if not url: return ""
    url = re.sub(r'^https?://', '', url)
    url = re.sub(r'^www\.', '', url)
    return url.rstrip('/').lower()

def is_news_sent(article_url: str) -> bool:
    norm_url = _normalize_url(article_url)
    with _db_lock:
        conn = get_connection()
        row = conn.execute("SELECT 1 FROM sent_news WHERE article_url = ?", (norm_url,)).fetchone()
        return row is not None

def save_news(article: dict[str, Any], status: str = "SENT") -> None:
    norm_url = _normalize_url(article.get("url", ""))
    now = now_iso()
    with _db_lock:
        conn = get_connection()
        try:
            with conn:
                conn.execute(
                    "INSERT OR IGNORE INTO sent_news (article_url, title, source, layer, sent_at, status) VALUES (?, ?, ?, ?, ?, ?)",
                    (norm_url, article.get("title"), article.get("source"), article.get("layer"), now, status)
                )
        except Exception as exc:
            logger.error("Erro ao gravar notícia: %s", exc)

def save_weekly_summary(period_key: str, cve_count: int, news_count: int, critical_count: int, high_count: int) -> None:
    now = now_iso()
    with _db_lock:
        conn = get_connection()
        try:
            with conn:
                conn.execute(
                    "INSERT OR REPLACE INTO weekly_summary (period_key, cve_count, news_count, critical_count, high_count, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (period_key, cve_count, news_count, critical_count, high_count, now)
                )
        except Exception as exc:
            logger.error("Erro ao gravar resumo semanal: %s", exc)

def save_monthly_summary(stats: dict[str, Any]) -> None:
    now = now_iso()
    with _db_lock:
        conn = get_connection()
        try:
            with conn:
                conn.execute(
                    """INSERT OR REPLACE INTO monthly_summary
                       (period_key, cve_count, news_count, critical_count, high_count,
                        medium_count, low_count, avg_cvss, top_vendors, top_products, top_clients, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (stats.get("period", ""), stats.get("cve_count", 0), stats.get("news_count", 0),
                     stats.get("risk_breakdown", {}).get("CRITICAL", 0), stats.get("risk_breakdown", {}).get("HIGH", 0),
                     stats.get("risk_breakdown", {}).get("MEDIUM", 0), stats.get("risk_breakdown", {}).get("LOW", 0),
                     stats.get("avg_cvss", 0.0), json.dumps(stats.get("top_vendors", []), default=str),
                     json.dumps(stats.get("top_products", []), default=str), json.dumps(stats.get("top_clients", []), default=str), now)
                )
        except Exception as exc:
            logger.error("Erro ao gravar resumo mensal: %s", exc)

def get_state(key: str, default: Any = None) -> Any:
    with _db_lock:
        conn = get_connection()
        row = conn.execute("SELECT value FROM system_state WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default

def set_state(key: str, value: Any) -> None:
    now = now_iso()
    with _db_lock:
        conn = get_connection()
        try:
            with conn:
                conn.execute("INSERT OR REPLACE INTO system_state (key, value, updated_at) VALUES (?, ?, ?)", (key, str(value), now))
        except Exception as exc:
            logger.error("Erro ao gravar estado: %s", exc)

def cleanup_old_data(days: int = 365) -> int:
    cutoff_date = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    deleted_count = 0
    with _db_lock:
        conn = get_connection()
        try:
            with conn:
                deleted_count += conn.execute("DELETE FROM sent_cves WHERE sent_at < ?", (cutoff_date,)).rowcount
                deleted_count += conn.execute("DELETE FROM sent_news WHERE sent_at < ?", (cutoff_date,)).rowcount
            return deleted_count
        except Exception as exc:
            logger.error("Erro na faxina: %s", exc)
            return 0


def get_report_stats(since: str, until: str) -> dict[str, Any]:
    """Coleta estatísticas agregadas para relatórios."""
    stats = {
        "total_cves": 0, "total_news": 0, "avg_cvss": 0.0,
        "risk_distribution": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "LOG_ONLY": 0},
        "top_vendors": [], "top_products": [], "top_clients": [], "top_sources": []
    }
    with _db_lock:
        conn = get_connection()
        try:
            # 1. CVEs e Risk Distribution
            rows = conn.execute(
                "SELECT risk_tag, COUNT(*), AVG(cvss_score) FROM sent_cves WHERE sent_at BETWEEN ? AND ? GROUP BY risk_tag",
                (since, until)
            ).fetchall()
            
            total_cvss_sum = 0.0
            for tag, count, avg_cvss in rows:
                if tag in stats["risk_distribution"]:
                    stats["risk_distribution"][tag] = count
                stats["total_cves"] += count
                total_cvss_sum += (avg_cvss or 0.0) * count
            
            if stats["total_cves"] > 0:
                stats["avg_cvss"] = round(total_cvss_sum / stats["total_cves"], 2)

            # 2. News
            stats["total_news"] = conn.execute(
                "SELECT COUNT(*) FROM sent_news WHERE sent_at BETWEEN ? AND ? AND status = 'SENT'",
                (since, until)
            ).fetchone()[0]

            # 3. Top Lists (Vendors, Products, Sources)
            stats["top_vendors"] = conn.execute(
                "SELECT vendor, COUNT(*) as c FROM sent_cves WHERE sent_at BETWEEN ? AND ? GROUP BY vendor ORDER BY c DESC LIMIT 5",
                (since, until)
            ).fetchall()
            
            stats["top_sources"] = conn.execute(
                "SELECT source, COUNT(*) as c FROM sent_news WHERE sent_at BETWEEN ? AND ? AND status = 'SENT' GROUP BY source ORDER BY c DESC LIMIT 5",
                (since, until)
            ).fetchall()
            
            return stats
        except Exception as exc:
            logger.error("Erro ao coletar stats de relatório: %s", exc)
            return stats
