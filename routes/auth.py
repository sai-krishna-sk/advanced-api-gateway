from flask import Blueprint, request, jsonify
import jwt, os, datetime, traceback
from models import User, db
from uuid import uuid4

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json(force=True)
        username = data.get("username")
        password = data.get("password")
        if not username or not password:
            return jsonify({"error": "Username and password are required"}), 400
        
        # Check if user already exists
        if User.query.filter_by(username=username).first():
            return jsonify({"error": "User already exists"}), 400
        
        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        return jsonify({"message": "User registered successfully"}), 201
    except Exception as e:
        print("Register error:", e)
        traceback.print_exc()
        return jsonify({"error": "Internal Server Error"}), 500

@auth_bp.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json(force=True)
        username = data.get("username")
        password = data.get("password")
        if not username or not password:
            return jsonify({"error": "Username and password are required"}), 400
        
        # Retrieve user from the database
        user = User.query.filter_by(username=username).first()
        if user is None or not user.check_password(password):
            return jsonify({"error": "Invalid username or password"}), 401
        
        secret = os.getenv("JWT_SECRET", "default_secret_key")
        token = jwt.encode({
            "user_id": user.id,
            "username": user.username,
            "jti": str(uuid4()),  # Unique token identifier
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }, secret, algorithm="HS256")
        if isinstance(token, bytes):
            token = token.decode('utf-8')
        return jsonify({"token": token})
    except Exception as e:
        print("Login error:", e)
        traceback.print_exc()
        return jsonify({"error": "Internal Server Error"}), 500
