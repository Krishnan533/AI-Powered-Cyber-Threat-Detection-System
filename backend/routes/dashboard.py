from flask import Blueprint, render_template, session, redirect, url_for
from backend.controllers.dashboard_controller import DashboardController
from backend.middlewares.auth_middleware import login_required, roles_required, csrf_protect

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/', methods=['GET'])
@dashboard_bp.route('/dashboard', methods=['GET'])
@login_required
def dashboard_view():
    """Renders the HTML Dashboard application."""
    return render_template('dashboard.html', username=session.get('username'), role=session.get('role'))

@dashboard_bp.route('/api/dashboard/stats', methods=['GET'])
@login_required
def stats_api():
    """Endpoint exposing general counts and stats."""
    return DashboardController.get_stats()

@dashboard_bp.route('/api/dashboard/timeline', methods=['GET'])
@login_required
def timeline_api():
    """Endpoint exposing hourly threat/packet density mappings."""
    return DashboardController.get_timeline()

@dashboard_bp.route('/api/dashboard/top-ips', methods=['GET'])
@login_required
def top_ips_api():
    """Endpoint exposing top destination/source IP counts."""
    return DashboardController.get_top_ips()

@dashboard_bp.route('/api/dashboard/live-feed', methods=['GET'])
@login_required
def live_feed_api():
    """Endpoint exposing 10 most recent packets and active threats."""
    return DashboardController.get_live_feed()

@dashboard_bp.route('/api/dashboard/retrain', methods=['POST'])
@login_required
@roles_required('Admin')
@csrf_protect
def retrain_api():
    """Spawns an asynchronous train.py command context to retrain the anomaly model."""
    return DashboardController.retrain_model()
