from flask import Blueprint, render_template, session
from backend.controllers.settings_controller import SettingsController
from backend.middlewares.auth_middleware import login_required, roles_required, csrf_protect

settings_bp = Blueprint('settings', __name__)

@settings_bp.route('/settings', methods=['GET'])
@login_required
@roles_required('Admin', 'Analyst')
def settings_view():
    """Renders the HTML Settings management page."""
    return render_template('settings.html', username=session.get('username'), role=session.get('role'))

@settings_bp.route('/api/settings', methods=['GET'])
@login_required
@roles_required('Admin', 'Analyst')
def get_settings_api():
    """Endpoint exposing global configurations."""
    return SettingsController.get_settings()

@settings_bp.route('/api/settings', methods=['POST'])
@login_required
@roles_required('Admin', 'Analyst')
@csrf_protect
def update_settings_api():
    """Endpoint updating global configuration attributes."""
    return SettingsController.update_settings()
