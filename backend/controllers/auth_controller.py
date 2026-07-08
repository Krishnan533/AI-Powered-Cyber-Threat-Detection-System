from flask import request, session, jsonify, redirect, url_for, flash
from backend.models.user import User
from backend.utils.helpers import log_audit, log_system
from backend.utils.validators import is_valid_username, sanitize_string

class AuthController:
    """Handles authentication actions: user login, logout, and session audits."""
    
    @staticmethod
    def login():
        """Handles user session authentication."""
        data = request.get_json() or {}
        username = sanitize_string(data.get('username', ''))
        password = data.get('password', '')

        if not username or not password:
            return jsonify({'success': False, 'message': 'Username and password are required.'}), 400

        if not is_valid_username(username):
            return jsonify({'success': False, 'message': 'Invalid username format.'}), 400

        try:
            # Query user
            user = User.query.filter_by(username=username).first()
            
            # Verify user and password
            if user and user.check_password(password):
                # Establish session
                session.clear()
                session['user_id'] = user.id
                session['username'] = user.username
                session['role'] = user.role
                session.permanent = True
                
                # Audit log success
                log_audit(
                    action="USER_LOGIN_SUCCESS",
                    user_id=user.id,
                    ip_address=request.remote_addr,
                    details=f"User {username} successfully authenticated as {user.role}."
                )
                
                return jsonify({
                    'success': True,
                    'message': 'Login successful.',
                    'user': user.to_dict()
                }), 200
                
            # Audit log failure
            log_audit(
                action="USER_LOGIN_FAILURE",
                ip_address=request.remote_addr,
                details=f"Failed login attempt for username: {username}."
            )
            return jsonify({'success': False, 'message': 'Invalid username or password.'}), 401
            
        except Exception as e:
            log_system('ERROR', f"Authentication crash: {e}")
            return jsonify({'success': False, 'message': 'Internal authentication server error.'}), 500

    @staticmethod
    def logout():
        """Clears user session and logs audit."""
        username = session.get('username')
        user_id = session.get('user_id')
        
        if user_id:
            log_audit(
                action="USER_LOGOUT",
                user_id=user_id,
                ip_address=request.remote_addr,
                details=f"User {username} logged out."
            )
            
        session.clear()
        return jsonify({'success': True, 'message': 'Logged out successfully.'}), 200

    @staticmethod
    def get_current_user():
        """Retrieves session profile data."""
        if 'user_id' not in session:
            return jsonify({'authenticated': False}), 401
            
        user = db.session.get(User, session['user_id'])
        if not user:
            session.clear()
            return jsonify({'authenticated': False}), 401
            
        return jsonify({
            'authenticated': True,
            'user': user.to_dict()
        }), 200
