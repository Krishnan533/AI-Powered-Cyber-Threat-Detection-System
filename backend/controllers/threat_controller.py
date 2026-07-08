from flask import request, jsonify, make_response, session
from backend.models.threat import Threat
from backend.models.blocked_ip import BlockedIP
from backend.extensions import db
from backend.utils.helpers import log_audit, log_system, generate_csv_report, generate_pdf_report
from backend.utils.validators import is_valid_ip

class ThreatController:
    """Manages Threat log searching, status modifications, and report exporting."""

    @staticmethod
    def get_threats():
        """Fetches a paginated, filtered, and searched list of threat alerts."""
        try:
            # Query parameters
            page = request.args.get('page', 1, type=int)
            per_page = request.args.get('limit', 10, type=int)
            search = request.args.get('search', '', type=str).strip()
            severity = request.args.get('severity', '', type=str).strip()
            status = request.args.get('status', '', type=str).strip()

            query = Threat.query

            # Text filters
            if search:
                query = query.filter(
                    (Threat.source_ip.like(f"%{search}%")) |
                    (Threat.destination_ip.like(f"%{search}%")) |
                    (Threat.type.like(f"%{search}%")) |
                    (Threat.description.like(f"%{search}%"))
                )

            # Categorical filters
            if severity:
                query = query.filter_by(severity_level=severity)
            if status:
                query = query.filter_by(status=status)

            # Order by timestamp desc
            query = query.order_by(Threat.timestamp.desc())

            # Perform pagination
            pagination = query.paginate(page=page, per_page=per_page, error_out=False)
            items = [t.to_dict() for t in pagination.items]

            return jsonify({
                'threats': items,
                'total': pagination.total,
                'pages': pagination.pages,
                'current_page': pagination.page
            }), 200

        except Exception as e:
            log_system('ERROR', f"Threat list retrieval crash: {e}")
            return jsonify({'error': 'Failed to query threat database records.'}), 500

    @staticmethod
    def update_status(threat_id):
        """Updates the monitoring status of an alert (e.g. Active, Resolved, False Positive)."""
        try:
            data = request.get_json() or {}
            new_status = data.get('status', '').strip()
            user_id = session.get('user_id')
            username = session.get('username', 'System')

            if new_status not in ('Active', 'Resolved', 'False Positive'):
                return jsonify({'success': False, 'message': 'Invalid status choice.'}), 400

            threat = db.session.get(Threat, threat_id)
            if not threat:
                return jsonify({'success': False, 'message': 'Threat alert record not found.'}), 404

            old_status = threat.status
            threat.status = new_status
            
            # If resolved/false positive, check if we should unblock the IP if it was blocked
            if new_status in ('Resolved', 'False Positive') and old_status == 'Active':
                # Check if this IP is blocked
                blocked = BlockedIP.query.filter_by(ip_address=threat.source_ip).first()
                if blocked:
                    db.session.delete(blocked)
                    log_audit(
                        action="IP_AUTO_UNBLOCKED",
                        user_id=user_id,
                        ip_address=threat.source_ip,
                        details=f"IP auto unblocked because threat ID {threat.id} was marked as {new_status}."
                    )
            
            db.session.commit()
            
            log_audit(
                action="THREAT_STATUS_UPDATE",
                user_id=user_id,
                details=f"User {username} updated threat ID {threat_id} status from {old_status} to {new_status}."
            )
            log_system('INFO', f"Threat {threat_id} updated to status {new_status} by {username}.")

            return jsonify({
                'success': True,
                'message': 'Threat status updated successfully.',
                'threat': threat.to_dict()
            }), 200

        except Exception as e:
            db.session.rollback()
            log_system('ERROR', f"Threat status update failed: {e}")
            return jsonify({'success': False, 'message': f"Database commit failed: {e}"}), 500

    @staticmethod
    def export_report():
        """Generates downloadable summary reports in CSV or PDF formats."""
        try:
            format_type = request.args.get('format', 'csv').lower().strip()
            severity = request.args.get('severity', '').strip()
            status = request.args.get('status', '').strip()

            query = Threat.query
            if severity:
                query = query.filter_by(severity_level=severity)
            if status:
                query = query.filter_by(status=status)
            threats = query.order_by(Threat.timestamp.desc()).all()

            headers = ["ID", "Type", "Source IP", "Destination IP", "Severity Score", "Severity Level", "Timestamp", "Status", "AI Detected"]
            
            rows = []
            for t in threats:
                rows.append([
                    t.id,
                    t.type,
                    t.source_ip,
                    t.destination_ip or "N/A",
                    t.severity_score,
                    t.severity_level,
                    t.timestamp.strftime('%Y-%m-%d %H:%M:%S') if t.timestamp else "",
                    t.status,
                    "Yes" if t.ai_detected else "No"
                ])

            if format_type == 'pdf':
                pdf_binary = generate_pdf_report("Security Cyber Threat Intelligence Report", headers, rows)
                response = make_response(pdf_binary)
                response.headers['Content-Type'] = 'application/pdf'
                response.headers['Content-Disposition'] = 'attachment; filename=threat_report.pdf'
                return response
                
            # Default to CSV
            csv_str = generate_csv_report(headers, rows)
            response = make_response(csv_str)
            response.headers['Content-Type'] = 'text/csv'
            response.headers['Content-Disposition'] = 'attachment; filename=threat_report.csv'
            return response

        except Exception as e:
            log_system('ERROR', f"Threat log export crashed: {e}")
            return make_response(jsonify({'error': 'Failed to compile report binary.'}), 500)
