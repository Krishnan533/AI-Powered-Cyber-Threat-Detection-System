from flask import Blueprint, render_template, session
from backend.controllers.threat_controller import ThreatController
from backend.middlewares.auth_middleware import login_required, roles_required, csrf_protect

threats_bp = Blueprint('threats', __name__)

@threats_bp.route('/threats', methods=['GET'])
@login_required
def threats_view():
    """Renders the HTML threats browser interface."""
    return render_template('threats.html', username=session.get('username'), role=session.get('role'))

@threats_bp.route('/api/threats', methods=['GET'])
@login_required
def get_threats_api():
    """Fetches paginated threats."""
    return ThreatController.get_threats()

@threats_bp.route('/api/threats/<int:threat_id>/status', methods=['POST'])
@login_required
@roles_required('Admin', 'Analyst')
@csrf_protect
def update_status_api(threat_id):
    """Updates status for a specific threat log."""
    return ThreatController.update_status(threat_id)

@threats_bp.route('/api/threats/export', methods=['GET'])
@login_required
def export_report_api():
    """Triggers CSV/PDF document generation of current logs."""
    return ThreatController.export_report()
