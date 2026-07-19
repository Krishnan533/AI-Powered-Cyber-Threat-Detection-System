from flask import Blueprint, render_template, session, redirect, url_for
from backend.controllers.auth_controller import AuthController
from backend.controllers.user_controller import UserController
from backend.middlewares.auth_middleware import csrf_protect, generate_csrf_token
from backend.middlewares.rate_limiter import limit_requests

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/', methods=['GET'])
@auth_bp.route('/landing', methods=['GET'])
def landing_view():
    """Renders the HTML landing page with 3D threat globe."""
    generate_csrf_token()
    return render_template('landing.html', is_logged_in=('user_id' in session))

@auth_bp.route('/login', methods=['GET'])
def login_view():
    """Renders the HTML login page."""
    if 'user_id' in session:
        return redirect(url_for('dashboard.dashboard_view'))
    # Ensure CSRF token is active
    generate_csrf_token()
    return render_template('login.html')

@auth_bp.route('/register', methods=['GET'])
def register_view():
    """Renders the HTML registration page."""
    if 'user_id' in session:
        return redirect(url_for('dashboard.dashboard_view'))
    generate_csrf_token()
    return render_template('register.html')

@auth_bp.route('/forgot-password', methods=['GET'])
def forgot_password_view():
    """Renders the HTML forgot password page."""
    if 'user_id' in session:
        return redirect(url_for('dashboard.dashboard_view'))
    generate_csrf_token()
    return render_template('forgot_password.html')

@auth_bp.route('/api/auth/login', methods=['POST'])
@limit_requests(limit=5, period=60) # Protect from brute-force login guessing
def login_api():
    """Handles authentication JSON endpoint."""
    return AuthController.login()

@auth_bp.route('/api/auth/register', methods=['POST'])
@limit_requests(limit=5, period=60)
def register_api():
    """Handles user self-registration."""
    return UserController.create_user()

@auth_bp.route('/api/auth/forgot-password', methods=['POST'])
@limit_requests(limit=5, period=60)
def forgot_password_api():
    """Triggers password reset token generation."""
    return AuthController.forgot_password()

@auth_bp.route('/api/auth/reset-password', methods=['POST'])
@limit_requests(limit=5, period=60)
def reset_password_api():
    """Resets password using token."""
    return AuthController.reset_password()

@auth_bp.route('/api/auth/verify-email', methods=['GET', 'POST'])
def verify_email_api():
    """Verifies email address with token."""
    return AuthController.verify_email()

@auth_bp.route('/logout', methods=['GET'])
def logout_view():
    """Logs out user and redirects to login view."""
    AuthController.logout()
    return redirect(url_for('auth.login_view'))

@auth_bp.route('/api/auth/logout', methods=['POST'])
@csrf_protect
def logout_api():
    """Logs out and clears session."""
    return AuthController.logout()


@auth_bp.route('/api/auth/profile', methods=['GET'])
def profile_api():
    """Fetches user information."""
    return AuthController.get_current_user()

