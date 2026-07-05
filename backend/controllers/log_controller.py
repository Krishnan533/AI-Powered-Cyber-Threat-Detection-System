from flask import request, jsonify
from backend.models.audit_log import AuditLog
from backend.models.system_log import SystemLog
from backend.utils.helpers import log_system

class LogController:
    """Handles log telemetry retrieval for administrative audit auditing."""

    @staticmethod
    def get_audit_logs():
        """Lists user and daemon audit actions (paginated, sorted, searchable)."""
        try:
            page = request.args.get('page', 1, type=int)
            per_page = request.args.get('limit', 15, type=int)
            search = request.args.get('search', '', type=str).strip()
            action = request.args.get('action', '', type=str).strip()

            query = AuditLog.query

            if search:
                query = query.filter(
                    (AuditLog.details.like(f"%{search}%")) |
                    (AuditLog.ip_address.like(f"%{search}%"))
                )
            if action:
                query = query.filter_by(action=action)

            # Sorted by timestamp desc
            query = query.order_by(AuditLog.timestamp.desc())

            pagination = query.paginate(page=page, per_page=per_page, error_out=False)
            items = [log.to_dict() for log in pagination.items]

            # Fetch distinct action types for search dropdown filters
            distinct_actions = [row[0] for row in AuditLog.query.with_entities(AuditLog.action).distinct().all()]

            return jsonify({
                'audit_logs': items,
                'actions': distinct_actions,
                'total': pagination.total,
                'pages': pagination.pages,
                'current_page': pagination.page
            }), 200

        except Exception as e:
            log_system('ERROR', f"Audit logs query failure: {e}")
            return jsonify({'error': 'Failed to query system audit logs.'}), 500

    @staticmethod
    def get_system_logs():
        """Lists internal diagnostics and error logs (paginated, sorted, filterable by log level)."""
        try:
            page = request.args.get('page', 1, type=int)
            per_page = request.args.get('limit', 15, type=int)
            level = request.args.get('level', '', type=str).upper().strip()
            search = request.args.get('search', '', type=str).strip()

            query = SystemLog.query

            if level:
                query = query.filter_by(level=level)
            if search:
                query = query.filter(SystemLog.message.like(f"%{search}%"))

            # Sorted by timestamp desc
            query = query.order_by(SystemLog.timestamp.desc())

            pagination = query.paginate(page=page, per_page=per_page, error_out=False)
            items = [log.to_dict() for log in pagination.items]

            return jsonify({
                'system_logs': items,
                'total': pagination.total,
                'pages': pagination.pages,
                'current_page': pagination.page
            }), 200

        except Exception as e:
            log_system('ERROR', f"System logs query failure: {e}")
            return jsonify({'error': 'Failed to query internal diagnostics logs.'}), 500
