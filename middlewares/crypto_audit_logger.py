import hashlib
import json
import logging
from flask import request
from datetime import datetime

# Configure Logger for Cryptographic Audit Logs
audit_logger = logging.getLogger("crypto_audit")
audit_logger.setLevel(logging.INFO)

if audit_logger.hasHandlers():
    audit_logger.handlers.clear()

file_handler = logging.FileHandler("crypto_audit.log")
file_handler.setFormatter(logging.Formatter('[%(asctime)s] AUDIT - %(message)s'))
audit_logger.addHandler(file_handler)

def crypto_audit_logger():
    """Logs requests with independent cryptographic hashing."""
    log_entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "method": request.method,
        "path": request.path,
        "headers": {k: v for k, v in request.headers.items()},
        "body": request.get_json(silent=True) or request.form.to_dict() or {},
    }

    # Convert log entry to a JSON string and compute independent hash
    log_string = json.dumps(log_entry, sort_keys=True)
    request_hash = hashlib.sha256(log_string.encode('utf-8')).hexdigest()

    # Store log with its hash
    audit_logger.info(f"🔐 Audit Log [{request_hash}]: {log_string}")

