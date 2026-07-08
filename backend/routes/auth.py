from flask import Blueprint, render_template, session, redirect, url_for
from backend.controllers.auth_controller import AuthController
from backend.middlewares.auth_middleware import csrf_protect, generate_csrf_token
from backend.middlewares.rate_limiter import limit_requests

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET'])
def login_view():
    """Renders the HTML login page."""
    if 'user_id' in session:
        return redirect(url_for('dashboard.dashboard_view'))
    # Ensure CSRF token is active
    generate_csrf_token()
    return render_template('login.html')

@auth_bp.route('/api/auth/login', methods=['POST'])
@limit_requests(limit=5, period=60) # Protect from brute-force login guessing
def login_api():
    """Handles authentication JSON endpoint."""
    return AuthController.login()

@auth_bp.route('/api/auth/logout', methods=['POST'])
@csrf_protect
def logout_api():
    """Logs out and clears session."""
    return AuthController.logout()

@auth_bp.route('/api/auth/profile', methods=['GET'])
def profile_api():
    """Fetches user information."""
    return AuthController.get_current_user()
