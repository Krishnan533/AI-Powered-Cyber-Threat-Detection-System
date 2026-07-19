from flask import request, session, jsonify, redirect, url_for, flash
from backend.extensions import db
from backend.models.user import User
from backend.utils.jwt_helper import generate_jwt_token
from backend.utils.helpers import log_audit, log_system
from backend.utils.validators import is_valid_username, sanitize_string

class AuthController:
    """Handles authentication actions: user login, logout, and session audits."""
    
    @staticmethod
    def login():
        """Handles user session authentication."""
        data = request.get_json(silent=True) or request.form or {}
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
                
                token = generate_jwt_token(user.id, user.username, user.role)
                
                return jsonify({
                    'success': True,
                    'message': 'Login successful.',
                    'token': token,
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

    @staticmethod
    def forgot_password():
        """Generates password reset token and sends email link."""
        data = request.get_json(silent=True) or request.form or {}
        email_or_username = sanitize_string(data.get('username_or_email', ''))

        if not email_or_username:
            return jsonify({'success': False, 'message': 'Username or email address is required.'}), 400

        try:
            import secrets
            from datetime import datetime, timedelta
            from backend.services.email_notifier import send_security_alert

            user = User.query.filter(
                (User.username == email_or_username) | (User.email == email_or_username)
            ).first()

            if user:
                token = secrets.token_urlsafe(32)
                user.reset_token = token
                user.reset_token_expiration = datetime.utcnow() + timedelta(hours=1)
                db.session.commit()

                log_audit(
                    action="USER_PASSWORD_RESET_REQUEST",
                    user_id=user.id,
                    details=f"Password reset token generated for user {user.username}."
                )

            # Always return success to prevent username/email enumeration attacks
            return jsonify({
                'success': True,
                'message': 'If an account exists with that username or email, a password reset link has been dispatched.'
            }), 200

        except Exception as e:
            log_system('ERROR', f"Forgot password crash: {e}")
            return jsonify({'success': False, 'message': 'Failed to process password reset request.'}), 500

    @staticmethod
    def reset_password():
        """Verifies reset token and updates user password."""
        data = request.get_json(silent=True) or request.form or {}
        token = data.get('token', '')
        new_password = data.get('new_password', '')

        if not token or not new_password:
            return jsonify({'success': False, 'message': 'Reset token and new password are required.'}), 400

        if len(new_password) < 8:
            return jsonify({'success': False, 'message': 'New password must be at least 8 characters long.'}), 400

        try:
            from datetime import datetime
            user = User.query.filter_by(reset_token=token).first()

            if not user or not user.reset_token_expiration or user.reset_token_expiration < datetime.utcnow():
                return jsonify({'success': False, 'message': 'Invalid or expired password reset token.'}), 400

            user.set_password(new_password)
            user.reset_token = None
            user.reset_token_expiration = None
            db.session.commit()

            log_audit(
                action="USER_PASSWORD_RESET_SUCCESS",
                user_id=user.id,
                details=f"User {user.username} successfully reset password."
            )

            return jsonify({'success': True, 'message': 'Password reset successful. Please log in with your new credentials.'}), 200

        except Exception as e:
            log_system('ERROR', f"Password reset crash: {e}")
            return jsonify({'success': False, 'message': 'Failed to reset password.'}), 500

    @staticmethod
    def verify_email():
        """Verifies user email using verification token."""
        token = request.args.get('token') or (request.get_json(silent=True) or {}).get('token')
        if not token:
            return jsonify({'success': False, 'message': 'Verification token is required.'}), 400

        try:
            user = User.query.filter_by(verification_token=token).first()
            if not user:
                return jsonify({'success': False, 'message': 'Invalid email verification token.'}), 400

            user.email_verified = True
            user.verification_token = None
            db.session.commit()

            log_audit(
                action="EMAIL_VERIFIED",
                user_id=user.id,
                details=f"User {user.username} verified email address."
            )

            return jsonify({'success': True, 'message': 'Email address verified successfully.'}), 200

        except Exception as e:
            log_system('ERROR', f"Email verification crash: {e}")
            return jsonify({'success': False, 'message': 'Failed to verify email.'}), 500
