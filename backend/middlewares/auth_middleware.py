import secrets
from functools import wraps
from flask import request, session, jsonify, redirect, url_for, abort, current_app

def login_required(f):
    """Decorator ensuring that user session exists."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            # If API request or JSON expected, return json error
            if request.path.startswith('/api/') or request.headers.get('Accept') == 'application/json':
                return jsonify({'success': False, 'message': 'Authentication required. Please login.'}), 401
            return redirect(url_for('auth.login_view'))
        return f(*args, **kwargs)
    return decorated_function

def roles_required(*roles):
    """Decorator limiting routes access to specific roles (e.g., Admin, Analyst, Viewer)."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                if request.path.startswith('/api/') or request.headers.get('Accept') == 'application/json':
                    return jsonify({'success': False, 'message': 'Authentication required.'}), 401
                return redirect(url_for('auth.login_view'))
                
            user_role = session.get('role')
            if user_role not in roles:
                if request.path.startswith('/api/') or request.headers.get('Accept') == 'application/json':
                    return jsonify({'success': False, 'message': f"Access forbidden. Requires roles: {', '.join(roles)}."}), 403
                return abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def generate_csrf_token():
    """Generates a secure random CSRF token if one is not present in session."""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

def csrf_protect(f):
    """Decorator enforcing matching session CSRF token header/payload verification on POST/PUT/DELETE write actions."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Exclude safe read methods
        if request.method in ('GET', 'HEAD', 'OPTIONS', 'TRACE'):
            return f(*args, **kwargs)

        # Allow write actions during tests or if request is authenticated via JWT Bearer token.
        auth_header = request.headers.get('Authorization')
        if current_app.config.get('TESTING') or (auth_header and auth_header.startswith('Bearer ')):
            return f(*args, **kwargs)

            
        token = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token')
        session_token = session.get('csrf_token')
        
        if not session_token or not token or not secrets.compare_digest(session_token, token):
            return jsonify({'success': False, 'message': 'Invalid or missing CSRF token security parameter.'}), 400
            
        return f(*args, **kwargs)
    return decorated_function
