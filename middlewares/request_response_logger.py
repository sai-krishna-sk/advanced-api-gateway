import logging
from flask import request

logger = logging.getLogger()  # Use global logger

# ✅ Dual Logging (Console + server.log)
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

# File Handler (Writes to server.log)
file_handler = logging.FileHandler("server.log")
file_handler.setFormatter(logging.Formatter('[%(asctime)s] %(levelname)s - %(message)s'))
logger.addHandler(file_handler)

# Console Handler (Displays logs on screen)
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter('[%(asctime)s] %(levelname)s - %(message)s'))
logger.addHandler(console_handler)


def log_request():
    """
    Logs incoming requests including method, path, headers, and body.
    """
    logger.info(f"🔹 Request: {request.method} {request.path}")
    logger.info(f"🔹 Headers: {dict(request.headers)}")
    logger.info(f"🔹 Body: {request.get_data(as_text=True)}")

def log_response(response):
    """
    Logs outgoing responses including status and body.
    """
    logger.info(f"🔸 Response Status: {response.status}")
    logger.info(f"🔸 Response Body: {response.get_data(as_text=True)}")
    return response  # Ensure response is returned for further processing

