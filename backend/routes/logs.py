from flask import Blueprint, render_template, session
from backend.controllers.log_controller import LogController
from backend.middlewares.auth_middleware import login_required, roles_required

logs_bp = Blueprint('logs', __name__)

@logs_bp.route('/logs', methods=['GET'])
@login_required
@roles_required('Admin', 'Analyst')
def logs_view():
    """Renders the HTML Audit Logs and System diagnostics page."""
    return render_template('logs.html', username=session.get('username'), role=session.get('role'))

@logs_bp.route('/api/logs/audit', methods=['GET'])
@login_required
@roles_required('Admin', 'Analyst')
def audit_logs_api():
    """Fetches paginated audit logs."""
    return LogController.get_audit_logs()

@logs_bp.route('/api/logs/system', methods=['GET'])
@login_required
@roles_required('Admin')
def system_logs_api():
    """Fetches paginated diagnostics level logs."""
    return LogController.get_system_logs()
