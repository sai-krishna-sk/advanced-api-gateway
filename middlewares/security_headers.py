from flask import request

def security_headers(response):
    """
    Adds security headers dynamically based on the request type and potential vulnerabilities.
    """
    # Essential security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = "geolocation=(), microphone=(), camera=()"

    # Enforce HTTPS for better security
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'

    # Only allow execution from the same origin for better protection
    response.headers['Content-Security-Policy'] = "default-src 'self'"

    # Apply additional security if sensitive requests are made
    if request.method in ['POST', 'PUT', 'DELETE']:
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'

    return response

