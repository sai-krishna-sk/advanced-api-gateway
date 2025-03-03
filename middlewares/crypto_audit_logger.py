import hashlib
import json
from flask import request
from datetime import datetime

previous_hash = ""

def crypto_audit_logger():
    global previous_hash
    log_entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "method": request.method,
        "path": request.path,
        "body": request.get_data(as_text=True)
    }
    log_string = json.dumps(log_entry, sort_keys=True)
    combined = previous_hash + log_string
    current_hash = hashlib.sha256(combined.encode('utf-8')).hexdigest()
    previous_hash = current_hash
    print(f"Audit Log [{current_hash}]: {log_string}")

