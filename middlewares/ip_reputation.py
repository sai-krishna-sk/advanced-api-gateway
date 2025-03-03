import time
import sqlite3
import logging
from flask import request, abort
from middlewares.threat_detection import detect_vulnerabilities  # Import threat detection

DB_PATH = "ip_reputation.db"

# Initialize the database
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS ip_reputation (
            ip TEXT PRIMARY KEY,
            request_count INTEGER DEFAULT 0,
            last_request_time REAL,
            reputation_score INTEGER DEFAULT 100,
            is_banned INTEGER DEFAULT 0  -- 0 = Not banned, 1 = Banned
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# Function to check if an IP is banned
def is_ip_banned(ip):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT is_banned FROM ip_reputation WHERE ip = ?", (ip,))
    row = c.fetchone()
    conn.close()
    return row and row[0] == 1  # Return True if banned

# Function to update IP reputation based on request count
def update_ip_reputation(ip):
    current_time = time.time()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Fetch existing IP data
    c.execute("SELECT request_count, last_request_time, reputation_score FROM ip_reputation WHERE ip = ?", (ip,))
    row = c.fetchone()

    if row:
        request_count, last_time, reputation_score = row

        # Reset count if last request was over an hour ago
        if current_time - last_time > 3600:
            request_count = 0
            reputation_score = 100  # Reset reputation

        # Increase request count
        request_count += 1

        # Reduce reputation score for excessive requests
        if request_count > 100:
            reputation_score = max(reputation_score - 10, 0)
        elif request_count > 50:
            reputation_score = max(reputation_score - 5, 0)

        # Update the record in the database
        c.execute(
            "UPDATE ip_reputation SET request_count = ?, last_request_time = ?, reputation_score = ? WHERE ip = ?",
            (request_count, current_time, reputation_score, ip)
        )
    else:
        # First-time IP entry
        request_count = 1
        reputation_score = 100
        c.execute(
            "INSERT INTO ip_reputation (ip, request_count, last_request_time, reputation_score, is_banned) VALUES (?, ?, ?, ?, 0)",
            (ip, request_count, current_time, reputation_score)
        )

    conn.commit()
    conn.close()
    return reputation_score

# Function to check and update IP reputation based on threat detection
def ip_reputation():
    ip = request.remote_addr

    # Check if the IP is already banned
    if is_ip_banned(ip):
        abort(403, description="Your IP is permanently banned due to malicious activity.")

    # First update reputation based on request count
    reputation_score = update_ip_reputation(ip)

    # Check for malicious activity using threat detection
    is_malicious = False
    try:
        url = request.url  # Get the requested URL
        detect_vulnerabilities(url)  # This may abort the request if a threat is detected
    except Exception as e:
        logging.error(f"Threat detection error for IP {ip}: {str(e)}")
        is_malicious = True  # Assume a threat was detected if an exception is raised

    # If malicious activity is detected, reduce the reputation score by 20 points
    if is_malicious:
        reputation_score = max(reputation_score - 15, 0)
        # Update the new reputation score in the database
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("UPDATE ip_reputation SET reputation_score = ? WHERE ip = ?", (reputation_score, ip))
        conn.commit()
        conn.close()

    # If reputation drops below 10, permanently ban the IP
    if reputation_score < 50:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("UPDATE ip_reputation SET is_banned = 1 WHERE ip = ?", (ip,))
        conn.commit()
        conn.close()
        abort(403, description="Your IP has been permanently banned due to repeated malicious activity.")

    # Attach the reputation score to the request for use by other middlewares
    request.ip_reputation_score = reputation_score

    # Logging for debugging and monitoring
    logging.info(f"IP {ip} - Reputation Score: {reputation_score}")
    if reputation_score < 50:
        logging.warning(f"⚠️ WARNING: IP {ip} has a low reputation score ({reputation_score}). Possible malicious activity!")

