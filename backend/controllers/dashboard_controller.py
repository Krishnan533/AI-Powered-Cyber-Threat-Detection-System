import os
import subprocess
from datetime import datetime, timedelta
from flask import jsonify, request, current_app, session
from sqlalchemy import func
from backend.extensions import db
from backend.models import Packet, Threat, BlockedIP, User
from backend.utils.helpers import log_system, log_audit

class DashboardController:
    """Handles statistics computation and data telemetry for the main dashboard interface."""

    @staticmethod
    def get_stats():
        """Computes summary statistics and threat distribution counts."""
        try:
            # Time thresholds
            now = datetime.utcnow()
            one_hour_ago = now - timedelta(hours=1)
            one_day_ago = now - timedelta(days=1)

            # Core volume aggregations
            total_packets = Packet.query.count()
            packets_last_hour = Packet.query.filter(Packet.timestamp >= one_hour_ago).count()
            
            total_threats = Threat.query.count()
            active_threats = Threat.query.filter_by(status='Active').count()
            resolved_threats = Threat.query.filter_by(status='Resolved').count()
            
            total_blocked = BlockedIP.query.filter(
                (BlockedIP.expires_at == None) | (BlockedIP.expires_at > now)
            ).count()

            # Protocol distributions
            proto_counts = db.session.query(
                Packet.protocol, func.count(Packet.id)
            ).group_by(Packet.protocol).all()
            protocols = {r[0]: r[1] for r in proto_counts}

            # Severity distributions
            severity_counts = db.session.query(
                Threat.severity_level, func.count(Threat.id)
            ).filter(Threat.status == 'Active').group_by(Threat.severity_level).all()
            severities = {r[0]: r[1] for r in severity_counts}
            
            # AI anomaly counter
            ai_threats = Threat.query.filter_by(ai_detected=True).count()

            # Default empty buckets for clean client rendering
            for level in ['Low', 'Medium', 'High', 'Critical']:
                if level not in severities:
                    severities[level] = 0

            return jsonify({
                'packets': {
                    'total': total_packets,
                    'last_hour': packets_last_hour,
                    'protocols': protocols
                },
                'threats': {
                    'total': total_threats,
                    'active': active_threats,
                    'resolved': resolved_threats,
                    'severities': severities,
                    'ai_anomalies': ai_threats
                },
                'blocked_ips': {
                    'active_count': total_blocked
                }
            }), 200

        except Exception as e:
            log_system('ERROR', f"Dashboard stats query crash: {e}")
            return jsonify({'error': 'Failed to compile telemetry statistics.'}), 500

    @staticmethod
    def get_timeline():
        """Aggregates packet counts and threat occurrences in 5-minute bins for the past 6 hours."""
        try:
            now = datetime.utcnow()
            six_hours_ago = now - timedelta(hours=6)

            packet_rows = Packet.query.filter(Packet.timestamp >= six_hours_ago).all()
            threat_rows = Threat.query.filter(Threat.timestamp >= six_hours_ago).all()

            # Seed 5-minute intervals to ensure no gaps in chart
            timeline = {}
            temp_time = six_hours_ago.replace(second=0, microsecond=0)
            step = timedelta(minutes=5)
            while temp_time <= now:
                label = temp_time.strftime('%Y-%m-%d %H:%M')
                timeline[label] = {'timestamp': label, 'packets': 0, 'threats': 0}
                temp_time += step

            def bucket_label(timestamp):
                if not timestamp:
                    return None
                rounded_minute = (timestamp.minute // 5) * 5
                rounded = timestamp.replace(minute=rounded_minute, second=0, microsecond=0)
                return rounded.strftime('%Y-%m-%d %H:%M')

            for packet in packet_rows:
                label = bucket_label(packet.timestamp)
                if label and label in timeline:
                    timeline[label]['packets'] += 1

            for threat in threat_rows:
                label = bucket_label(threat.timestamp)
                if label and label in timeline:
                    timeline[label]['threats'] += 1

            sorted_timeline = sorted(timeline.values(), key=lambda x: x['timestamp'])
            return jsonify(sorted_timeline), 200

        except Exception as e:
            log_system('ERROR', f"Timeline aggregation crash: {e}")
            return jsonify({'error': 'Failed to compile timeline chart statistics.'}), 500

    @staticmethod
    def get_top_ips():
        """Compiles top source and destination IP counts."""
        try:
            top_sources = db.session.query(
                Packet.src_ip, func.count(Packet.id)
            ).group_by(Packet.src_ip).order_by(func.count(Packet.id).desc()).limit(5).all()

            top_destinations = db.session.query(
                Packet.dst_ip, func.count(Packet.id)
            ).group_by(Packet.dst_ip).order_by(func.count(Packet.id).desc()).limit(5).all()

            return jsonify({
                'sources': [{'ip': r[0], 'count': r[1]} for r in top_sources],
                'destinations': [{'ip': r[0], 'count': r[1]} for r in top_destinations]
            }), 200
            
        except Exception as e:
            log_system('ERROR', f"Top IP compilation crash: {e}")
            return jsonify({'error': 'Failed to compile TOP IP statistics.'}), 500

    @staticmethod
    def get_live_feed():
        """Fetches the 10 most recent packets and 10 most recent active threats for dashboard grids."""
        try:
            recent_packets = Packet.query.order_by(Packet.timestamp.desc()).limit(10).all()
            recent_threats = Threat.query.filter_by(status='Active').order_by(Threat.timestamp.desc()).limit(10).all()
            
            return jsonify({
                'packets': [p.to_dict() for p in recent_packets],
                'threats': [t.to_dict() for t in recent_threats]
            }), 200
        except Exception as e:
            log_system('ERROR', f"Dashboard live feed query crash: {e}")
            return jsonify({'error': 'Failed to compile dashboard feeds.'}), 500

    @staticmethod
    def retrain_model():
        """Triggers a background execution of the model training script."""
        try:
            user_id = session.get('user_id')
            username = session.get('username', 'System')
            
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            script_path = os.path.join(base_dir, "ai_model", "train.py")
            
            # Execute subprocess to train the Isolation Forest model asynchronously
            process = subprocess.Popen(
                [current_app.config.get('PYTHON_EXECUTABLE', 'python'), script_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            log_audit(
                action="AI_MODEL_RETRAIN",
                user_id=user_id,
                details=f"User {username} manually triggered AI Isolation Forest model retraining."
            )
            log_system('INFO', "AI model training task spawned successfully via user request.")
            
            return jsonify({'success': True, 'message': 'Model training task scheduled in background.'}), 202
            
        except Exception as e:
            log_system('ERROR', f"Model retraining command dispatch failed: {e}")
            return jsonify({'success': False, 'message': f"Failed to dispatch model training command: {e}"}), 500

