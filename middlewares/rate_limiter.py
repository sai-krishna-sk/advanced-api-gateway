from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask import jsonify
import time
import sqlite3

# Initialize rate limiter with the correct key_func
limiter = Limiter(key_func=get_remote_address)

# Database path
DB_PATH = "blocked_ips.db"

# Function to get a new database connection
def get_db_connection():
    return sqlite3.connect(DB_PATH, check_same_thread=False)

# Create the database table (run once)
conn = get_db_connection()
cursor = conn.cursor()
cursor.execute("""
    CREATE TABLE IF NOT EXISTS blocked_ips (
        ip TEXT PRIMARY KEY,
        request_count INTEGER DEFAULT 0,
        is_blocked INTEGER DEFAULT 0,
        blocked_at INTEGER,
        last_request_at INTEGER DEFAULT 0
    )
""")
conn.commit()
conn.close()

# Function to check if an IP is blocked
def is_ip_blocked(ip):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT is_blocked, blocked_at FROM blocked_ips WHERE ip = ?", (ip,))
    result = cursor.fetchone()
    conn.close()

    if result:
        is_blocked, blocked_at = result
        if is_blocked == 1:
            if blocked_at and (int(time.time()) - blocked_at) >= 1800:
                unblock_ip_automatically(ip)
                return False  # Now the IP is unblocked, so return False
            return False  # Otherwise, it's still blocked
    return False  # Not blocked

# Function to unblock an IP after 30 minutes
def unblock_ip_automatically(ip):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE blocked_ips SET request_count = 0, is_blocked = 0, blocked_at = NULL WHERE ip = ?", (ip,))
    conn.commit()
    conn.close()

# Function to ensure an IP exists in the database
def ensure_ip_exists(ip):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT OR IGNORE INTO blocked_ips (ip, request_count, is_blocked, last_request_at) 
        VALUES (?, 0, 0, ?)
    """, (ip, int(time.time())))
    conn.commit()
    conn.close()

# Function to get the current request count and last request time for an IP
def get_ip_data(ip):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT request_count, last_request_at FROM blocked_ips WHERE ip = ?", (ip,))
    result = cursor.fetchone()
    conn.close()
    return result if result else (0, 0)

# Function to update request count and timestamp
def update_request_data(ip, reset=False):
    conn = get_db_connection()
    cursor = conn.cursor()
    if reset:
        cursor.execute("UPDATE blocked_ips SET request_count = 1, last_request_at = ? WHERE ip = ?", (int(time.time()), ip))
    else:
        cursor.execute("UPDATE blocked_ips SET request_count = request_count + 1, last_request_at = ? WHERE ip = ?", (int(time.time()), ip))
    conn.commit()
    conn.close()

# Function to block an IP
def block_ip(ip):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE blocked_ips SET is_blocked = 1, blocked_at = ? WHERE ip = ?", (int(time.time()), ip))
    conn.commit()
    conn.close()

# Middleware to check for blacklisted IPs
def check_blocked_ips():
    ip = get_remote_address()
    ensure_ip_exists(ip)  # Ensure the IP is added to the database if it's new

    if is_ip_blocked(ip):
        return jsonify({"error": "Too many requests. You are permanently blocked."}), 429

    request_count, last_request_time = get_ip_data(ip)
    current_time = int(time.time())

    # If the last request was more than 1 minute ago, reset the request count
    if current_time - last_request_time > 60:
        update_request_data(ip, reset=True)
    else:
        update_request_data(ip)

    # Get the updated request count after updating
    request_count, _ = get_ip_data(ip)

    # If the request count exceeds 20, block the IP
    if request_count > 20:
        block_ip(ip)
        return jsonify({"error": "Too many requests. You are now permanently blocked."}), 429

