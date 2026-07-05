from flask import Blueprint, render_template, session
from backend.controllers.blocked_ip_controller import BlockedIPController
from backend.middlewares.auth_middleware import login_required, roles_required, csrf_protect

blocked_ips_bp = Blueprint('blocked_ips', __name__)

@blocked_ips_bp.route('/blocked-ips', methods=['GET'])
@login_required
def blocked_ips_view():
    """Renders the HTML Firewall Blocks interface."""
    return render_template('blocked_ips.html', username=session.get('username'), role=session.get('role'))

@blocked_ips_bp.route('/api/blocked-ips', methods=['GET'])
@login_required
def get_blocked_ips_api():
    """Fetches blocked IP logs."""
    return BlockedIPController.get_blocked_ips()

@blocked_ips_bp.route('/api/blocked-ips', methods=['POST'])
@login_required
@roles_required('Admin', 'Analyst')
@csrf_protect
def add_blocked_ip_api():
    """Creates a new IP block rule."""
    return BlockedIPController.block_ip()

@blocked_ips_bp.route('/api/blocked-ips/<int:ip_id>', methods=['DELETE'])
@login_required
@roles_required('Admin')
@csrf_protect
def unblock_ip_api(ip_id):
    """Deletes an IP block rule."""
    return BlockedIPController.unblock_ip(ip_id)
