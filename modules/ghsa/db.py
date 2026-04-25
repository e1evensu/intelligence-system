import sqlite3
import os
import json
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))
from config import DB_PATH

def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def init_db():
    conn = get_conn()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS advisories (
        ghsa_id TEXT PRIMARY KEY,
        cve_id TEXT,
        summary TEXT,
        severity TEXT,
        published_at TEXT,
        repo TEXT,
        stars INTEGER DEFAULT 0,
        cvss_score REAL DEFAULT 0,
        vuln_type TEXT,
        affected TEXT,
        exploit_difficulty TEXT,
        urgency TEXT,
        summary_cn TEXT,
        action TEXT,
        analyzed_at TEXT,
        created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS daily_reports (
        date TEXT PRIMARY KEY,
        total_fetched INTEGER DEFAULT 0,
        total_filtered INTEGER DEFAULT 0,
        urgent_count INTEGER DEFAULT 0,
        high_count INTEGER DEFAULT 0,
        watch_count INTEGER DEFAULT 0,
        html_path TEXT,
        oss_url TEXT,
        created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_advisories_published ON advisories(published_at);
    CREATE INDEX IF NOT EXISTS idx_advisories_urgency ON advisories(urgency);
    """)
    conn.commit()

    # --- 迁移：添加新字段 ---
    new_columns = [
        ('description', 'TEXT'),
        ('raw_references', 'TEXT'),
        ('ecosystem', 'TEXT'),
        ('package_name', 'TEXT'),
        ('patched_version', 'TEXT'),
        ('language', 'TEXT'),
        ('sink_source', 'TEXT'),
        ('poc', 'TEXT'),
        ('fix_detail', 'TEXT'),
        ('business_context', 'TEXT'),
    ]
    cur = conn.cursor()
    cur.execute("PRAGMA table_info(advisories)")
    existing = {row[1] for row in cur.fetchall()}
    for col_name, col_type in new_columns:
        if col_name not in existing:
            conn.execute(f"ALTER TABLE advisories ADD COLUMN {col_name} {col_type}")
            print(f"[db] Migrated: added column {col_name}")
    conn.commit()
    conn.close()

def advisory_exists(ghsa_id: str) -> bool:
    conn = get_conn()
    row = conn.execute("SELECT 1 FROM advisories WHERE ghsa_id=?", (ghsa_id,)).fetchone()
    conn.close()
    return row is not None

def save_advisory(data: dict):
    conn = get_conn()
    # Serialize complex fields to JSON strings
    raw_refs = data.get('raw_references', '')
    if isinstance(raw_refs, (list, dict)):
        raw_refs = json.dumps(raw_refs, ensure_ascii=False)

    sink_source = data.get('sink_source', '')
    if isinstance(sink_source, (list, dict)):
        sink_source = json.dumps(sink_source, ensure_ascii=False)

    poc = data.get('poc', '')
    if isinstance(poc, (list, dict)):
        poc = json.dumps(poc, ensure_ascii=False)

    fix_detail = data.get('fix_detail', '')
    if isinstance(fix_detail, (list, dict)):
        fix_detail = json.dumps(fix_detail, ensure_ascii=False)

    conn.execute("""
        INSERT OR REPLACE INTO advisories 
        (ghsa_id, cve_id, summary, severity, published_at, repo, stars, cvss_score,
         vuln_type, affected, exploit_difficulty, urgency, summary_cn, action,
         description, raw_references, ecosystem, package_name, patched_version,
         language, sink_source, poc, fix_detail, business_context)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        data.get('ghsa_id'), data.get('cve_id'), data.get('summary'),
        data.get('severity'), data.get('published_at'), data.get('repo'),
        data.get('stars', 0), data.get('cvss_score', 0),
        data.get('vuln_type'), data.get('affected'), data.get('exploit_difficulty'),
        data.get('urgency'), data.get('summary_cn'), data.get('action'),
        # New fields
        data.get('description', ''),
        raw_refs,
        data.get('ecosystem', ''),
        data.get('package_name', ''),
        data.get('patched_version', ''),
        data.get('language', ''),
        sink_source,
        poc,
        fix_detail,
        data.get('business_context', ''),
    ))
    conn.commit()
    conn.close()

def save_daily_report(date: str, total_fetched: int, total_filtered: int,
                      urgent: int, high: int, watch: int, html_path: str, oss_url: str = ''):
    conn = get_conn()
    conn.execute("""
        INSERT OR REPLACE INTO daily_reports 
        (date, total_fetched, total_filtered, urgent_count, high_count, watch_count, html_path, oss_url)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (date, total_fetched, total_filtered, urgent, high, watch, html_path, oss_url))
    conn.commit()
    conn.close()

def get_recent_stats(days: int = 7) -> list:
    conn = get_conn()
    rows = conn.execute("""
        SELECT date, total_filtered, urgent_count, high_count, watch_count 
        FROM daily_reports 
        ORDER BY date DESC LIMIT ?
    """, (days,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]
