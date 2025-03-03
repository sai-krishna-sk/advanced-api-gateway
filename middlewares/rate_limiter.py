from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Limit to 100 requests per minute per IP
limiter = Limiter(key_func=get_remote_address, default_limits=["100 per minute"])

