from datetime import datetime, timedelta
from flask import request, jsonify, session
from backend.models.blocked_ip import BlockedIP
from backend.extensions import db
from backend.utils.helpers import log_audit, log_system
from backend.utils.validators import is_valid_ip, sanitize_string

class BlockedIPController:
    """Handles CRUD actions for blacklisted firewall IPs."""

    @staticmethod
    def get_blocked_ips():
        """Lists currently blocked IPs in the database."""
        try:
            page = request.args.get('page', 1, type=int)
            per_page = request.args.get('limit', 10, type=int)
            search = request.args.get('search', '', type=str).strip()

            query = BlockedIP.query

            if search:
                query = query.filter(BlockedIP.ip_address.like(f"%{search}%") | BlockedIP.reason.like(f"%{search}%"))

            # Order by blocked_at desc
            query = query.order_by(BlockedIP.blocked_at.desc())

            pagination = query.paginate(page=page, per_page=per_page, error_out=False)
            items = [b.to_dict() for b in pagination.items]

            return jsonify({
                'blocked_ips': items,
                'total': pagination.total,
                'pages': pagination.pages,
                'current_page': pagination.page
            }), 200

        except Exception as e:
            log_system('ERROR', f"Blocked IP query crash: {e}")
            return jsonify({'error': 'Failed to query firewall block database.'}), 500

    @staticmethod
    def block_ip():
        """Manually creates a new IP firewall block."""
        try:
            data = request.get_json() or {}
            ip = sanitize_string(data.get('ip_address', '')).strip()
            reason = sanitize_string(data.get('reason', 'Manual administrative lock')).strip()
            duration = data.get('duration_hours') # hours, can be None for permanent block
            
            user_id = session.get('user_id')
            username = session.get('username', 'System')

            if not ip:
                return jsonify({'success': False, 'message': 'IP Address is required.'}), 400

            if not is_valid_ip(ip):
                return jsonify({'success': False, 'message': 'Invalid IP address formatting.'}), 400

            # Check if already blocked
            existing = BlockedIP.query.filter_by(ip_address=ip).first()
            if existing:
                # Update block if existing is expired
                if existing.is_expired():
                    db.session.delete(existing)
                    db.session.commit()
                else:
                    return jsonify({'success': False, 'message': 'IP Address is already blocked.'}), 400

            # Calculate expiration
            expires_at = None
            if duration:
                try:
                    hrs = float(duration)
                    if hrs <= 0:
                        return jsonify({'success': False, 'message': 'Duration hours must be positive.'}), 400
                    expires_at = datetime.utcnow() + timedelta(hours=hrs)
                except ValueError:
                    return jsonify({'success': False, 'message': 'Invalid duration format.'}), 400

            block = BlockedIP(
                ip_address=ip,
                reason=reason,
                blocked_at=datetime.utcnow(),
                expires_at=expires_at,
                blocked_by=username
            )
            db.session.add(block)
            db.session.commit()

            log_audit(
                action="IP_MANUAL_BLOCKED",
                user_id=user_id,
                ip_address=ip,
                details=f"User {username} blocked IP {ip}. Reason: {reason}. Expiration: {expires_at or 'Permanent'}"
            )
            log_system('INFO', f"IP {ip} manually blocked by {username}.")

            return jsonify({
                'success': True,
                'message': 'IP Address blocked successfully.',
                'blocked_ip': block.to_dict()
            }), 201

        except Exception as e:
            db.session.rollback()
            log_system('ERROR', f"Failed to manually block IP: {e}")
            return jsonify({'success': False, 'message': f"Database commit failed: {e}"}), 500

    @staticmethod
    def unblock_ip(ip_id):
        """Removes a blocked IP entry from the database."""
        try:
            user_id = session.get('user_id')
            username = session.get('username', 'System')

            block = BlockedIP.query.get(ip_id)
            if not block:
                return jsonify({'success': False, 'message': 'Blocked IP entry not found.'}), 404

            ip = block.ip_address
            db.session.delete(block)
            db.session.commit()

            log_audit(
                action="IP_MANUAL_UNBLOCKED",
                user_id=user_id,
                ip_address=ip,
                details=f"User {username} unblocked IP {ip}."
            )
            log_system('INFO', f"IP {ip} unblocked by {username}.")

            return jsonify({
                'success': True,
                'message': f"IP Address {ip} unblocked successfully."
            }), 200

        except Exception as e:
            db.session.rollback()
            log_system('ERROR', f"Failed to unblock IP: {e}")
            return jsonify({'success': False, 'message': f"Database commit failed: {e}"}), 500
