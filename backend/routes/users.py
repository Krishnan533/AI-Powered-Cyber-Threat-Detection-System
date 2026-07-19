from flask import Blueprint, render_template, session
from backend.controllers.user_controller import UserController
from backend.middlewares.auth_middleware import login_required, roles_required, csrf_protect

users_bp = Blueprint('users', __name__)

@users_bp.route('/users', methods=['GET'])
@login_required
@roles_required('Admin')
def users_view():
    """Renders the HTML User Management console."""
    return render_template('users.html', username=session.get('username'), role=session.get('role'))

@users_bp.route('/api/users', methods=['GET'])
@login_required
@roles_required('Admin')
def get_users_api():
    """Endpoint listing registered accounts."""
    return UserController.get_users()

@users_bp.route('/api/users', methods=['POST'])
@login_required
@roles_required('Admin')
@csrf_protect
def add_user_api():
    """Endpoint allowing administrative account provisioning."""
    return UserController.create_user()

@users_bp.route('/api/users/<int:user_id>', methods=['PUT'])
@login_required
@roles_required('Admin')
@csrf_protect
def update_user_api(user_id):
    """Endpoint allowing account authorization updates."""
    return UserController.update_user_role(user_id)

@users_bp.route('/api/users/<int:user_id>', methods=['DELETE'])
@login_required
@roles_required('Admin')
@csrf_protect
def delete_user_api(user_id):
    """Endpoint allowing account deprovisioning."""
    return UserController.delete_user(user_id)
