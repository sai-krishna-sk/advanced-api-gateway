import os
import jwt
from flask import request, abort

def jwt_oauth_validator():
    # Skip token validation for OPTIONS requests
    if request.method == "OPTIONS":
        return

    # Allow public endpoints: /auth/ (login and register), /, and /favicon.ico
    if (request.path.startswith('/auth/') or 
        request.path == '/' or 
        request.path == '/favicon.ico'):
        return

    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header.split(" ")[1]
        try:
            decoded = jwt.decode(token, os.getenv("JWT_SECRET", "default_secret_key"), algorithms=["HS256"])
            request.user = decoded
        except jwt.InvalidTokenError:
            abort(401, description="Invalid token")
    else:
        abort(401, description="No token provided")

