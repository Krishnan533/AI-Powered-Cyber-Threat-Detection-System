from flask import request, jsonify, session
from backend.models.user import User
from backend.extensions import db
from backend.utils.helpers import log_audit, log_system
from backend.utils.validators import is_valid_username, sanitize_string

class UserController:
    """Handles CRUD operations for user account administration (Admin role only) and User Registration."""

    @staticmethod
    def get_users():
        """Lists all registered users in the database."""
        try:
            users = User.query.order_by(User.id.asc()).all()
            return jsonify([u.to_dict() for u in users]), 200
        except Exception as e:
            log_system('ERROR', f"Failed to list users: {e}")
            return jsonify({'error': 'Failed to fetch users.'}), 500

    @staticmethod
    def create_user():
        """Registers a new user account (used by Admin or self-registration)."""
        try:
            data = request.get_json() or {}
            username = sanitize_string(data.get('username', '')).strip()
            password = data.get('password', '')
            role = data.get('role', 'Viewer').strip() # Default role is Viewer

            if not username or not password:
                return jsonify({'success': False, 'message': 'Username and password are required.'}), 400

            if not is_valid_username(username):
                return jsonify({'success': False, 'message': 'Invalid username format.'}), 400

            if role not in ('Admin', 'Analyst', 'Viewer'):
                return jsonify({'success': False, 'message': 'Invalid role choice.'}), 400

            # Expose registration endpoint. If self-registering, role MUST be Viewer
            # unless admin is logged in and creating a user.
            current_user_role = session.get('role')
            if current_user_role != 'Admin' and role != 'Viewer':
                role = 'Viewer'

            # Check if username exists
            existing = User.query.filter_by(username=username).first()
            if existing:
                return jsonify({'success': False, 'message': 'Username is already taken.'}), 400

            user = User(
                username=username,
                role=role
            )
            user.set_password(password)
            db.session.add(user)
            db.session.commit()

            operator = session.get('username', 'Anonymous')
            log_audit(
                action="USER_CREATED",
                user_id=session.get('user_id'),
                details=f"User {username} created with role {role} by {operator}."
            )
            log_system('INFO', f"User {username} created successfully with role {role}.")

            return jsonify({
                'success': True,
                'message': f"User account '{username}' created successfully.",
                'user': user.to_dict()
            }), 201

        except Exception as e:
            db.session.rollback()
            log_system('ERROR', f"User creation failed: {e}")
            return jsonify({'success': False, 'message': f"Failed to create user: {e}"}), 500

    @staticmethod
    def update_user_role(user_id):
        """Updates the authorization level/role of a user."""
        try:
            data = request.get_json() or {}
            role = data.get('role', '').strip()
            admin_username = session.get('username', 'System')

            if role not in ('Admin', 'Analyst', 'Viewer'):
                return jsonify({'success': False, 'message': 'Invalid role specified.'}), 400

            user = db.session.get(User, user_id)
            if not user:
                return jsonify({'success': False, 'message': 'User not found.'}), 404

            # Prevent Admin from changing their own role to avoid lockout
            if session.get('user_id') == user.id and role != 'Admin':
                return jsonify({'success': False, 'message': 'Cannot modify your own administrator role to avoid lockout.'}), 400

            old_role = user.role
            user.role = role
            db.session.commit()

            log_audit(
                action="USER_ROLE_UPDATED",
                user_id=session.get('user_id'),
                details=f"Admin {admin_username} updated role of user {user.username} from {old_role} to {role}."
            )
            log_system('INFO', f"User {user.username} role updated from {old_role} to {role} by {admin_username}.")

            return jsonify({
                'success': True,
                'message': f"Role of user '{user.username}' updated to {role}.",
                'user': user.to_dict()
            }), 200

        except Exception as e:
            db.session.rollback()
            log_system('ERROR', f"User role update failed: {e}")
            return jsonify({'success': False, 'message': f"Database commit failed: {e}"}), 500

    @staticmethod
    def delete_user(user_id):
        """Deletes a user account from the system."""
        try:
            admin_username = session.get('username', 'System')

            user = db.session.get(User, user_id)
            if not user:
                return jsonify({'success': False, 'message': 'User account not found.'}), 404

            # Prevent self-deletion
            if session.get('user_id') == user.id:
                return jsonify({'success': False, 'message': 'Cannot delete your own active administrator account.'}), 400

            username = user.username
            db.session.delete(user)
            db.session.commit()

            log_audit(
                action="USER_DELETED",
                user_id=session.get('user_id'),
                details=f"Admin {admin_username} deleted user account: {username}."
            )
            log_system('INFO', f"User account {username} deleted by {admin_username}.")

            return jsonify({
                'success': True,
                'message': f"User account '{username}' deleted successfully."
            }), 200

        except Exception as e:
            db.session.rollback()
            log_system('ERROR', f"User deletion failed: {e}")
            return jsonify({'success': False, 'message': f"Database commit failed: {e}"}), 500
