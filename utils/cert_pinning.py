import hashlib

def verify_certificate(cert_bytes, expected_fingerprint):
    # Calculate the SHA-256 fingerprint of the certificate bytes
    fingerprint = hashlib.sha256(cert_bytes).hexdigest()
    return fingerprint == expected_fingerprint

