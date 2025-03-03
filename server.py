import os
import ssl
import logging
from dotenv import load_dotenv
from flask import Flask, jsonify, request, redirect, url_for
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from models import db, bcrypt, User

# Import security middlewares
from middlewares.request_response_logger import log_request, log_response
from middlewares.threat_detection import detect_vulnerabilities
from middlewares.crypto_audit_logger import crypto_audit_logger
from middlewares.ip_reputation import ip_reputation  # Ensure this function is defined as ip_reputation in ip_reputation.py
from middlewares.jwt_oauth_validator import jwt_oauth_validator
from middlewares.ml_anomaly_detection import ml_anomaly_detection
from middlewares.security_headers import security_headers
from middlewares.waf_rules import waf_rules
from middlewares.rate_limiter import limiter

# Load environment variables
load_dotenv()

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Configure database using an environment variable
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL", "sqlite:///app.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv("JWT_SECRET", "supersecret")  # Change in production

# Initialize extensions
db.init_app(app)
bcrypt.init_app(app)
jwt = JWTManager(app)
limiter.init_app(app)  # Register rate limiter

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# Global before_request middleware with error handling
@app.before_request
def run_middlewares():
    try:
        # Log incoming request and perform audit logging
        log_request()
        crypto_audit_logger()
        waf_rules()
        
        # Run IP reputation first to update the score, even if threat detection later aborts the request
        ip_reputation()
        
        # Then perform threat detection on the URL (this may abort if vulnerabilities are detected)
        detect_vulnerabilities(request.url)
        
        # Continue with JWT validation and anomaly detection
        jwt_oauth_validator()
        ml_anomaly_detection()
    except Exception as e:
        logging.error(f"Middleware error: {str(e)}")
        return jsonify({"error": f"Middleware error: {str(e)}"}), 500

# Global after_request middleware for response logging and security headers
@app.after_request
def apply_security_headers(response):
    response = security_headers(response)
    response = log_response(response)
    return response

# User Registration Endpoint
@app.route('/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({"error": "User already exists"}), 400
    new_user = User(username=username)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User registered successfully"}), 201

# User Login Endpoint (Returns JWT Token)
@app.route('/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400
    user = User.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
        return jsonify({"error": "Invalid username or password"}), 401
    access_token = create_access_token(identity=username)
    return jsonify({"access_token": access_token}), 200

# Redirect root to login page
@app.route('/')
def home():
    return redirect(url_for('login'))

# Secure API Route (Requires JWT Authentication)
@app.route('/api/echo', methods=['GET'])
@jwt_required()
def echo():
    current_user = get_jwt_identity()
    url_param = request.args.get('url')
    if not url_param:
        return jsonify({"error": "Missing URL parameter"}), 400
    logging.debug(f"Received URL: {url_param}")
    
    # Optionally, you can perform additional threat detection on the URL parameter.
    if detect_vulnerabilities(url_param):
        return jsonify({"error": "Potential threat detected in URL"}), 403

    return jsonify({"user": current_user, "requested_url": url_param}), 200

# Initialize Database (create all tables)
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    port = int(os.getenv("PORT", 8443))
    
    # SSL Configuration with security enhancements
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile='certs/server.crt', keyfile='certs/server.key')
    context.load_verify_locations(cafile='certs/ca.crt')
    if os.getenv("ENV") == "production":
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
    else:
        context.verify_mode = ssl.CERT_NONE

    app.run(host='0.0.0.0', port=port, ssl_context=context, threaded=True)

