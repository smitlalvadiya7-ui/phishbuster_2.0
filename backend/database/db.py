import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "scans.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            verdict TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            reasons TEXT NOT NULL,
            ai_explanation TEXT,
            scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

def save_scan(url, verdict, risk_score, reasons, ai_explanation):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        INSERT INTO scans (url, verdict, risk_score, reasons, ai_explanation)
        VALUES (?, ?, ?, ?, ?)
    """, (url, verdict, risk_score, str(reasons), ai_explanation))
    conn.commit()
    conn.close()

def get_history(limit=20):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        SELECT url, verdict, risk_score, reasons, ai_explanation, scanned_at
        FROM scans ORDER BY scanned_at DESC LIMIT ?
    """, (limit,))
    rows = c.fetchall()
    conn.close()
    return [
        {
            "url": r[0],
            "verdict": r[1],
            "risk_score": r[2],
            "reasons": r[3],
            "ai_explanation": r[4],
            "scanned_at": r[5]
        }
        for r in rows
    ]
