from flask import request, abort
import re

# Define patterns for multiple vulnerabilities
patterns = {
    "xss": [
        r"(?i)<script.*?>", r"(?i)on\w+\s*=", r"(?i)javascript:", r"(?i)vbscript:",
        r"(?i)data:text/html", r"(?i)document\.cookie", r"(?i)document\.write",
        r"(?i)alert\(", r"(?i)prompt\(", r"(?i)eval\(", r"(?i)innerHTML", r"(?i)outerHTML"
    ],
    "sql_injection": [
        r"(?i)union\s+select", r"(?i)or\s+1=1", r"(?i)drop\s+table", r"(?i)insert\s+into",
        r"(?i)update\s+.*set", r"(?i)delete\s+from", r"(?i)benchmark\((.*?)\)",
        r"(?i)sleep\((\d+)\)", r"(?i)load_file\(", r"(?i)outfile", r"(?i)information_schema"
    ],
    "cmd_injection": [
        r"(?i);--", r"(?i)&\s*rm\s", r"(?i)&\s*del\s", r"(?i)&\s*format\s",
        r"(?i)&\s*shutdown\s", r"(?i)&\s*reboot\s", r"(?i)system\(", r"(?i)exec\s+",
        r"(?i)os\.system", r"(?i)subprocess\.Popen"
    ],
    "path_traversal": [
        r"(?i)\.\./", r"(?i)/etc/passwd", r"(?i)/proc/self/environ", r"(?i)C:\\Windows",
        r"(?i)C:\\boot.ini", r"(?i)\\..\\", r"(?i)/var/log", r"(?i)/root/.ssh"
    ],
    "rce": [
        r"(?i)import\s+os", r"(?i)import\s+subprocess", r"(?i)import\s+pickle",
        r"(?i)import\s+eval", r"(?i)eval\(", r"(?i)exec\(", r"(?i)pickle\.loads",
        r"(?i)marshal\.loads"
    ],
    "sensitive_data": [
        r"(?i)Set-Cookie:", r"(?i)api_key=", r"(?i)password=",
        r"(?i)secret_key=", r"(?i)access_token=", r"(?i)private_key=", r"(?i)session_id="
    ],  # Removed "Authorization:" to allow legitimate API authentication
    "ssrf": [
        r"(?i)http://169\.254\.169\.254", r"(?i)http://metadata\.google\.internal",
        r"(?i)http://localhost", r"(?i)http://127\.0\.0\.1", r"(?i)file://", r"(?i)ftp://"
    ],
    "xxe": [
        r"(?i)<!DOCTYPE", r"(?i)SYSTEM", r"(?i)ENTITY", r"(?i)file://", r"(?i)public"
    ],
    "ldap_injection": [
        r"(?i)\*\|", r"(?i)&\|", r"(?i)\(objectClass=.*\)", r"(?i)\(userPassword=.*\)",
        r"(?i)\(cn=.*\)", r"(?i)\(uid=.*\)"
    ],
    "ssti": [
        r"(?i){{.*?}}", r"(?i){%.*?%}", r"(?i)\$\{.*?}", r"(?i)eval\(", r"(?i)exec\("
    ],
    "open_redirect": [
    r"(?i)\bhttps?://[^/]+@",  # Allow standard URLs, block `@`-based redirects
    r"(?i)\bhttps?://[^/]+\.example\.com@",  # Block `example.com@`
    r"(?i)\bhttps?:\/\/[^\/]+\/\/"  # More strict double-slash check
    ]

}

# Compile regex patterns for efficiency
compiled_patterns = {key: [re.compile(p) for p in value] for key, value in patterns.items()}

def detect_vulnerabilities(url: str = None):
    """
    Scans request data, headers, and optionally a URL for security threats.

    - Checks raw request data
    - Scans headers (excluding 'Authorization')
    - If a URL is provided, includes it in the scan
    - Aborts the request with a `403 Forbidden` if any threat is detected
    """
    payload = request.get_data(as_text=True)
    headers = {k: v for k, v in request.headers.items() if k.lower() != "authorization"}  # Ignore Authorization header

    # Combine all input sources for scanning
    full_request_data = payload + str(headers)
    if url:
        full_request_data += url  # Include URL in scan if provided

    detected_vulnerabilities = []
    for category, pattern_list in compiled_patterns.items():
        for pattern in pattern_list:
            if pattern.search(full_request_data):
                detected_vulnerabilities.append(category)
                break  # Stop checking more patterns if a category is found

    if detected_vulnerabilities:
        abort(403, description=f"Security Threat Detected: {', '.join(detected_vulnerabilities)}")

