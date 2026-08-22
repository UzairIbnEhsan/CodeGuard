import json
import sqlite3
import os
from pathlib import Path

# ============================================================
# FIX: Use /tmp for Vercel (writable directory)
# ============================================================

# Check if running on Vercel
IS_VERCEL = os.environ.get('VERCEL', False)

if IS_VERCEL:
    # Vercel uses /tmp as writable directory
    DB_PATH = Path("/tmp") / "codeguard.db"
else:
    # Local development
    DB_PATH = Path(__file__).resolve().parents[2] / "codeguard.db"

# ============================================================
# REST OF THE CODE (unchanged)
# ============================================================

def get_connection():
    """Create and return a database connection"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Create the scans table if it doesn't exist"""
    conn = get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            score INTEGER NOT NULL,
            findings TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

def save_scan(filename, score, findings):
    """Save scan results to database"""
    conn = get_connection()
    findings_json = json.dumps(findings)
    cursor = conn.execute(
        "INSERT INTO scans (filename, score, findings) VALUES (?, ?, ?)",
        (filename, score, findings_json)
    )
    conn.commit()
    scan_id = cursor.lastrowid
    conn.close()
    return scan_id

def get_recent_scans(limit=10):
    """Get most recent scans"""
    conn = get_connection()
    rows = conn.execute(
        "SELECT id, filename, score, created_at FROM scans ORDER BY id DESC LIMIT ?",
        (limit,)
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_scan_by_id(scan_id):
    """Get a specific scan by ID"""
    conn = get_connection()
    row = conn.execute(
        "SELECT id, filename, score, findings, created_at FROM scans WHERE id = ?",
        (scan_id,)
    ).fetchone()
    conn.close()
    
    if row:
        result = dict(row)
        result['findings'] = json.loads(result['findings'])
        return result
    return None

def delete_scan(scan_id):
    """Delete a scan by ID"""
    conn = get_connection()
    cursor = conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    conn.commit()
    deleted = cursor.rowcount > 0
    conn.close()
    return deleted

def get_scan_statistics():
    """Get statistics about all scans"""
    conn = get_connection()
    cursor = conn.execute("""
        SELECT 
            COUNT(*) as total_scans,
            AVG(score) as average_score,
            MIN(score) as lowest_score,
            MAX(score) as highest_score
        FROM scans
    """)
    row = cursor.fetchone()
    conn.close()
    
    stats = dict(row)
    if stats['average_score']:
        stats['average_score'] = round(stats['average_score'], 2)
    return stats