import os
import jwt
from datetime import datetime, timedelta
from flask import current_app

def generate_jwt_token(user_id, username, role):
    """
    Generates a JWT token for the authenticated user.
    """
    try:
        secret_key = current_app.config.get('SECRET_KEY') if current_app else os.environ.get('SECRET_KEY', 'replace_with_a_very_secure_string_9018230')
        payload = {
            'exp': datetime.utcnow() + timedelta(hours=12),  # Token valid for 12 hours
            'iat': datetime.utcnow(),
            'sub': user_id,
            'username': username,
            'role': role
        }
        return jwt.encode(payload, secret_key, algorithm='HS256')
    except Exception as e:
        print(f"JWT Token Generation error: {e}")
        return None

def decode_jwt_token(token):
    """
    Decodes a JWT token and returns the payload dictionary.
    Returns None if signature is expired or token is invalid.
    """
    try:
        secret_key = current_app.config.get('SECRET_KEY') if current_app else os.environ.get('SECRET_KEY', 'replace_with_a_very_secure_string_9018230')
        payload = jwt.decode(token, secret_key, algorithms=['HS256'])
        return {
            'user_id': payload.get('sub'),
            'username': payload.get('username'),
            'role': payload.get('role')
        }
    except jwt.ExpiredSignatureError:
        print("JWT token expired.")
        return None
    except jwt.InvalidTokenError:
        print("JWT token invalid.")
        return None
    except Exception as e:
        print(f"JWT decode error: {e}")
        return None
