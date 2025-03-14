import hashlib
import json
import re

AUDIT_LOG_FILE = "crypto_audit.log"
SERVER_LOG_FILE = "server.log"

# Function to extract requests from server.log
def extract_requests_from_server_log():
    with open(SERVER_LOG_FILE, "r") as f:
        logs = f.readlines()
    
    requests = []
    current_request = {}
    
    for line in logs:
        if "🔹 Request: " in line:
            method, path = line.split(": ")[1].strip().split(" ")
            current_request = {"method": method, "path": path}
        elif "🔹 Headers: " in line:
            headers_str = line.split("Headers: ")[1].strip()
            current_request["headers"] = eval(headers_str)  # Convert string to dictionary
        elif "🔹 Body: " in line:
            try:
                body_text = line.split("Body: ")[1].strip()
                # Remove or escape any control characters
                body_text = re.sub(r'[\x00-\x1F\x7F]', '', body_text)
                current_request["body"] = json.loads(body_text)
            except json.JSONDecodeError as e:
                print(f"Warning: Could not parse JSON body: {e}")
                current_request["body"] = {"error": "Could not parse body"}
        elif "🔐 Audit Log [" in line:
            match = re.search(r"\[([a-f0-9]{64})\]", line)
            if match:
                current_request["audit_hash"] = match.group(1)
                requests.append(current_request)
                current_request = {}
    
    return requests

# Function to extract audit logs
def extract_audit_hashes():
    with open(AUDIT_LOG_FILE, "r") as f:
        logs = f.readlines()
    
    audit_entries = {}
    for line in logs:
        match = re.search(r"\[([a-f0-9]{64})\]: (.*)", line)
        if match:
            hash_value = match.group(1)
            audit_data = json.loads(match.group(2).strip())
            audit_entries[hash_value] = audit_data
    
    return audit_entries

# Function to compute independent hash
def compute_hash(audit_data):
    audit_json = json.dumps(audit_data, sort_keys=True)
    return hashlib.sha256(audit_json.encode()).hexdigest()

# Function to verify logs
def verify_logs():
    server_requests = extract_requests_from_server_log()
    audit_logs = extract_audit_hashes()
    
    tampered = False
    for request in server_requests:
        expected_hash = request["audit_hash"]
        constructed_audit = {
            "method": request["method"],
            "path": request["path"],
            "headers": request["headers"],
            "body": request["body"],
        }
        
        # Ensure we use the correct timestamp for consistency
        if expected_hash in audit_logs:
            constructed_audit["timestamp"] = audit_logs[expected_hash]["timestamp"]
        
        calculated_hash = compute_hash(constructed_audit)
        
        if expected_hash != calculated_hash:
            print(f"❌ Tampering Detected for {request['method']} {request['path']}!")
            print(f"   Expected: {expected_hash}")
            print(f"   Found:    {calculated_hash}")
            tampered = True
        else:
            print(f"✅ Verified: {request['method']} {request['path']} - Hash matches.")
    
    if not tampered:
        print("✅ All audit logs are intact!")

if __name__ == "__main__":
    verify_logs()
