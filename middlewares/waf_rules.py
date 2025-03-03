import re
import sqlite3
from flask import request, abort

DB_PATH = 'waf_rules.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS waf_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pattern TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_db()

def get_waf_rules():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT pattern FROM waf_rules")
    rows = c.fetchall()
    conn.close()
    return [row[0] for row in rows]

def waf_rules():
    rules = get_waf_rules()
    for rule in rules:
        if re.search(rule, request.path, re.IGNORECASE):
            abort(403, description="Blocked by WAF rule")

def update_waf_rules(new_rules):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM waf_rules")
    for pattern in new_rules:
        c.execute("INSERT INTO waf_rules (pattern) VALUES (?)", (pattern,))
    conn.commit()
    conn.close()
    print("WAF rules updated:", new_rules)

