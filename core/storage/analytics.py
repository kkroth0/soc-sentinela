"""
core/storage/analytics.py — Consultas complexas e estatísticas para relatórios.
Otimizado para baixo consumo de memória (Memory-Safe).
"""
import json
from typing import Any
from core.logger import get_logger
from core.storage.database import get_connection, _db_lock

logger = get_logger("core.storage.analytics")

def get_report_stats(since: str, until: str) -> dict[str, Any]:
    """Calcula estatísticas de desempenho para relatórios."""
    with _db_lock:
        conn = get_connection()
        try:
            # Query agregada única para eficiência
            cve_res = conn.execute(
                """SELECT COUNT(*) as total, ROUND(AVG(cvss_score), 1) as avg_cvss,
                          SUM(CASE WHEN risk_tag = 'CRITICAL' THEN 1 ELSE 0 END) as critical,
                          SUM(CASE WHEN risk_tag = 'HIGH' THEN 1 ELSE 0 END) as high,
                          SUM(CASE WHEN risk_tag = 'MEDIUM' THEN 1 ELSE 0 END) as medium,
                          SUM(CASE WHEN risk_tag = 'LOW' THEN 1 ELSE 0 END) as low
                   FROM sent_cves WHERE sent_at >= ? AND sent_at < ?""", (since, until)
            ).fetchone()

            news_res = conn.execute("SELECT COUNT(*) as total FROM sent_news WHERE sent_at >= ? AND sent_at < ?", (since, until)).fetchone()
            
            vendors = conn.execute(
                "SELECT vendor, COUNT(*) as total FROM sent_cves WHERE sent_at >= ? AND sent_at < ? AND vendor != '' GROUP BY vendor ORDER BY total DESC LIMIT 5", (since, until)
            ).fetchall()

            products = conn.execute(
                "SELECT product, vendor, COUNT(*) as total FROM sent_cves WHERE sent_at >= ? AND sent_at < ? AND product != '' GROUP BY product ORDER BY total DESC LIMIT 5", (since, until)
            ).fetchall()

            client_rows = conn.execute("SELECT impacted_clients FROM sent_cves WHERE sent_at >= ? AND sent_at < ?", (since, until)).fetchall()
            client_counts = {}
            for r in client_rows:
                for c in json.loads(r["impacted_clients"] or "[]"):
                    client_counts[c] = client_counts.get(c, 0) + 1
            top_clients = [{"client": c, "count": n} for c, n in sorted(client_counts.items(), key=lambda x: x[1], reverse=True)[:5]]

            news_sources = conn.execute(
                "SELECT source, COUNT(*) as total FROM sent_news WHERE sent_at >= ? AND sent_at < ? AND source != '' GROUP BY source ORDER BY total DESC LIMIT 5", (since, until)
            ).fetchall()

            return {
                "total_cves": cve_res["total"] or 0, "avg_cvss": cve_res["avg_cvss"] or 0.0, "total_news": news_res["total"] or 0,
                "risk_distribution": {"CRITICAL": cve_res["critical"] or 0, "HIGH": cve_res["high"] or 0, "MEDIUM": cve_res["medium"] or 0, "LOW": cve_res["low"] or 0},
                "top_vendors": [dict(r) for r in vendors], "top_products": [dict(r) for r in products], "top_clients": top_clients,
                "top_sources": [dict(r) for r in news_sources]
            }
        except Exception as exc:
            logger.error("Erro analítico: %s", exc)
            return {"total_cves": 0, "avg_cvss": 0.0, "total_news": 0, "risk_distribution": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}, "top_vendors": [], "top_products": [], "top_clients": []}

def get_recent_cves(limit: int = 15) -> list[dict[str, Any]]:
    """Retorna CVEs recentes (apenas metadados, sem payload_json para poupar RAM)."""
    with _db_lock:
        conn = get_connection()
        # OTIMIZAÇÃO: Nunca selecione payload_json em listagens
        rows = conn.execute(
            "SELECT cve_id, cvss_score, severity, risk_tag, vendor, product, sent_at FROM sent_cves ORDER BY sent_at DESC LIMIT ?", 
            (limit,)
        ).fetchall()
        return [dict(row) for row in rows]

def get_recent_news(limit: int = 15) -> list[dict[str, Any]]:
    """Retorna notícias recentes sentidas."""
    with _db_lock:
        conn = get_connection()
        rows = conn.execute(
            "SELECT title, source, layer, sent_at FROM sent_news WHERE status = 'SENT' ORDER BY sent_at DESC LIMIT ?", 
            (limit,)
        ).fetchall()
        return [dict(row) for row in rows]

def get_cves_for_month(year_month: str) -> list[dict[str, Any]]:
    """Busca todas as CVEs enviadas em um mês específico (YYYY-MM)."""
    with _db_lock:
        conn = get_connection()
        # Busca por prefixo na string ISO8601 (ex: '2023-10%')
        rows = conn.execute(
            """SELECT cve_id, sent_at, vendor, product, cvss_score, risk_tag, impacted_clients 
               FROM sent_cves WHERE sent_at LIKE ? ORDER BY sent_at ASC""", 
            (f"{year_month}%",)
        ).fetchall()
        return [dict(row) for row in rows]
