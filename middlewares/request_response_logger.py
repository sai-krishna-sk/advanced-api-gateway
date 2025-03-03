from flask import request

def log_request():
    print(f"Request: {request.method} {request.path} - Body: {request.get_data(as_text=True)}")

def log_response(response):
    print(f"Response: {response.get_data(as_text=True)}")
    return response

