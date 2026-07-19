import os
import sys

# Ensure root workspace directory is in sys.path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from flask import Flask, render_template, session, jsonify, request
from dotenv import load_dotenv

load_dotenv()


from backend.config.settings import config_by_name
from backend.extensions import db, mail
from backend.routes import register_blueprints
from backend.services.email_notifier import EmailNotifier
from backend.services.threat_detector import ThreatDetector
from packet_capture.sniffer import NetworkSniffer
from backend.utils.helpers import log_system
from backend.models.user import User

# Global instances for background daemons
sniffer_instance = None
threat_detector_instance = None

def create_app(config_name=None, config_overrides=None):
    """Flask Application Factory."""
    app = Flask(__name__, 
                template_folder='templates',
                static_folder='static')
    
    # Load configuration
    if not config_name:
        config_name = os.environ.get('FLASK_ENV', 'development')
    app.config.from_object(config_by_name[config_name])

    if config_overrides:
        app.config.from_mapping(config_overrides)
    
    # Store python execution path for dynamic model retraining subprocesses
    app.config['PYTHON_EXECUTABLE'] = sys.executable

    # Ensure instance directory exists for SQLite fallbacks or temporary files
    try:
        os.makedirs(app.instance_path, exist_ok=True)
    except Exception:
        pass

    # Initialize extensions
    db.init_app(app)

    mail.init_app(app)
    
    # Register routes blueprints
    register_blueprints(app)

    # Inject CSRF token to templates contexts
    @app.context_processor
    def inject_csrf():
        from backend.middlewares.auth_middleware import generate_csrf_token
        return dict(csrf_token=generate_csrf_token())


    # Global Error Handlers
    @app.errorhandler(401)
    def unauthorized(e):
        return render_template('login.html'), 401

    @app.errorhandler(403)
    def forbidden(e):
        return render_template('base.html', error="403 Forbidden - Access Denied"), 403

    @app.errorhandler(404)
    def page_not_found(e):
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Resource not found'}), 404
        return render_template('base.html', error="404 Not Found"), 404

    @app.errorhandler(500)
    def server_error(e):
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Internal server error'}), 500
        return render_template('base.html', error="500 Internal Server Error"), 500

    @app.before_request
    def check_jwt_token():
        """Extracts JWT token from Authorization header and sets up session context for APIs."""
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            from backend.utils.jwt_helper import decode_jwt_token
            token = auth_header.split(" ")[1]
            user_data = decode_jwt_token(token)
            if user_data:
                session['user_id'] = user_data.get('user_id')
                session['username'] = user_data.get('username')
                session['role'] = user_data.get('role')

    def seed_and_load_settings(app):
        from backend.models.system_setting import SystemSetting
        
        default_settings = {
            'MAIL_SERVER': os.environ.get('MAIL_SERVER', 'localhost'),
            'MAIL_PORT': os.environ.get('MAIL_PORT', '1025'),
            'MAIL_USE_TLS': os.environ.get('MAIL_USE_TLS', 'False'),
            'MAIL_USE_SSL': os.environ.get('MAIL_USE_SSL', 'False'),
            'MAIL_USERNAME': os.environ.get('MAIL_USERNAME', ''),
            'MAIL_PASSWORD': os.environ.get('MAIL_PASSWORD', ''),
            'MAIL_DEFAULT_SENDER': os.environ.get('MAIL_DEFAULT_SENDER', 'threat-alerts@example.com'),
            'ADMIN_EMAIL': os.environ.get('ADMIN_EMAIL', 'admin-alerts@example.com'),
            'SNIFFER_INTERFACE': os.environ.get('SNIFFER_INTERFACE', ''),
            'SNIFFER_SIMULATION': os.environ.get('SNIFFER_SIMULATION', 'TRUE'),
            'SNIFFER_SIMULATION_INTERVAL': os.environ.get('SNIFFER_SIMULATION_INTERVAL', '0.5'),
            'DDOS_THRESHOLD': '100',
            'PORTSCAN_THRESHOLD': '15',
            'BRUTEFORCE_THRESHOLD': '10',
            'SEND_EMAIL_NOTIFICATIONS': os.environ.get('SEND_EMAIL_NOTIFICATIONS', 'TRUE')
        }
        
        try:
            db_settings = SystemSetting.query.all()
            db_keys = {s.key for s in db_settings}
            
            for k, v in default_settings.items():
                if k not in db_keys:
                    setting = SystemSetting(key=k, value=str(v))
                    db.session.add(setting)
            db.session.commit()
            
            # Load all into app.config
            all_settings = SystemSetting.query.all()
            for s in all_settings:
                if s.key in ('MAIL_PORT', 'DDOS_THRESHOLD', 'PORTSCAN_THRESHOLD', 'BRUTEFORCE_THRESHOLD'):
                    try:
                        app.config[s.key] = int(s.value)
                    except ValueError:
                        app.config[s.key] = s.value
                elif s.key in ('MAIL_USE_TLS', 'MAIL_USE_SSL', 'SNIFFER_SIMULATION', 'SEND_EMAIL_NOTIFICATIONS'):
                    app.config[s.key] = s.value.lower() in ('true', '1', 't')
                elif s.key == 'SNIFFER_SIMULATION_INTERVAL':
                    try:
                        app.config[s.key] = float(s.value)
                    except ValueError:
                        app.config[s.key] = 0.5
                else:
                    app.config[s.key] = s.value
        except Exception as e:
            print(f"Failed to seed and load settings from database: {e}")

    def init_db_and_seed():
        try:
            with app.app_context():
                db.create_all()
                # Migrate missing columns for existing database instances safely without breaking transactions
                try:
                    from sqlalchemy import inspect, text
                    inspector = inspect(db.engine)
                    if 'users' in inspector.get_table_names():
                        existing_cols = {c['name'] for c in inspector.get_columns('users')}
                        with db.engine.begin() as conn:
                            if 'email' not in existing_cols:
                                conn.execute(text("ALTER TABLE users ADD COLUMN email VARCHAR(120)"))
                            if 'email_verified' not in existing_cols:
                                conn.execute(text("ALTER TABLE users ADD COLUMN email_verified BOOLEAN DEFAULT FALSE"))
                            if 'verification_token' not in existing_cols:
                                conn.execute(text("ALTER TABLE users ADD COLUMN verification_token VARCHAR(100)"))
                            if 'reset_token' not in existing_cols:
                                conn.execute(text("ALTER TABLE users ADD COLUMN reset_token VARCHAR(100)"))
                            if 'reset_token_expiration' not in existing_cols:
                                conn.execute(text("ALTER TABLE users ADD COLUMN reset_token_expiration TIMESTAMP"))
                except Exception as e:
                    print(f"Column migration check note: {e}")


                seed_and_load_settings(app)
                if not app.config.get('TESTING'):
                    admin_username = app.config.get('DEFAULT_ADMIN_USERNAME', 'admin')
                    admin_user = User.query.filter_by(username=admin_username).first()
                    if not admin_user:
                        admin = User(
                            username=admin_username,
                            role='Admin'
                        )
                        admin.set_password(app.config.get('DEFAULT_ADMIN_PASSWORD', 'AdminPass123!'))
                        db.session.add(admin)

                    if User.query.count() == 1 and admin_user:
                        analyst = User(
                            username=app.config.get('DEFAULT_ANALYST_USERNAME', 'analyst'),
                            role='Analyst'
                        )
                        analyst.set_password(app.config.get('DEFAULT_ANALYST_PASSWORD', 'AnalystPass456!'))
                        viewer = User(
                            username=app.config.get('DEFAULT_VIEWER_USERNAME', 'viewer'),
                            role='Viewer'
                        )
                        viewer.set_password(app.config.get('DEFAULT_VIEWER_PASSWORD', 'ViewerPass789!'))
                        db.session.add_all([analyst, viewer])

                    db.session.commit()
                    log_system('INFO', 'Database initialized and default user accounts verified.')

                    # Seed sample database packets, threats, and blocked_ips if empty
                    from backend.models.packet import Packet
                    from backend.models.threat import Threat
                    from backend.models.blocked_ip import BlockedIP
                    from datetime import datetime, timedelta

                    if Packet.query.count() == 0:
                        p1 = Packet(src_ip='192.168.1.15', dst_ip='192.168.1.254', src_port=53210, dst_port=80, protocol='TCP', packet_size=64, flags='S', payload_preview='GET / HTTP/1.1', timestamp=datetime.utcnow() - timedelta(minutes=10))
                        p2 = Packet(src_ip='192.168.1.15', dst_ip='192.168.1.254', src_port=53210, dst_port=80, protocol='TCP', packet_size=1200, flags='A', payload_preview='HTTP/1.1 200 OK', timestamp=datetime.utcnow() - timedelta(minutes=9))
                        p3 = Packet(src_ip='10.0.0.5', dst_ip='192.168.1.50', src_port=58732, dst_port=22, protocol='TCP', packet_size=78, flags='S', payload_preview='SSH-2.0-OpenSSH_8.2p1', timestamp=datetime.utcnow() - timedelta(minutes=8))
                        p4 = Packet(src_ip='192.168.1.100', dst_ip='8.8.8.8', src_port=49152, dst_port=53, protocol='UDP', packet_size=52, payload_preview='Standard query A google.com', timestamp=datetime.utcnow() - timedelta(minutes=7))
                        p5 = Packet(src_ip='203.0.113.12', dst_ip='192.168.1.50', src_port=44321, dst_port=80, protocol='TCP', packet_size=40, flags='R', timestamp=datetime.utcnow() - timedelta(minutes=6))
                        db.session.add_all([p1, p2, p3, p4, p5])
                        db.session.commit()

                    if Threat.query.count() == 0:
                        t1 = Threat(type='Port Scan', source_ip='203.0.113.45', destination_ip='192.168.1.50', severity_score=8.2, severity_level='High', status='Active', description='Source IP scanned 45 unique destination ports in 1.2 seconds.', ai_detected=False, timestamp=datetime.utcnow() - timedelta(minutes=5))
                        t2 = Threat(type='DDoS', source_ip='198.51.100.12', destination_ip='192.168.1.50', severity_score=9.5, severity_level='Critical', status='Active', description='DDoS volumetric alert: 4500 packets/sec detected from isolated IP source.', ai_detected=False, timestamp=datetime.utcnow() - timedelta(minutes=4))
                        t3 = Threat(type='AI Anomaly', source_ip='192.168.1.111', destination_ip='10.0.0.10', severity_score=6.5, severity_level='Medium', status='Active', description='Isolation Forest anomaly detected: unusual payload size to UDP ports.', ai_detected=True, timestamp=datetime.utcnow() - timedelta(minutes=3))
                        t4 = Threat(type='Brute Force', source_ip='198.51.100.99', destination_ip='192.168.1.50', severity_score=7.8, severity_level='High', status='Resolved', description='Multiple failed login attempts on port 22 (SSH). IP automatically resolved via lock.', ai_detected=False, timestamp=datetime.utcnow() - timedelta(minutes=2))
                        db.session.add_all([t1, t2, t3, t4])
                        db.session.commit()

                    if BlockedIP.query.count() == 0:
                        b1 = BlockedIP(ip_address='203.0.113.45', reason='Port scanning detected on interface eth0', expires_at=datetime.utcnow() + timedelta(hours=24), blocked_by='System', blocked_at=datetime.utcnow() - timedelta(minutes=5))
                        b2 = BlockedIP(ip_address='198.51.100.12', reason='DDoS flood source mitigation rule', expires_at=datetime.utcnow() + timedelta(hours=2), blocked_by='admin', blocked_at=datetime.utcnow() - timedelta(minutes=4))
                        db.session.add_all([b1, b2])
                        db.session.commit()
        except Exception as e:
            print(f"Database initialization/seeding note: {e}")

    # Immediately ensure DB schema and default admin exist
    init_db_and_seed()

    # Hook packet sniffer daemon thread startup on first request
    @app.before_request
    def initialize_system():
        """Executed once before the very first request to start background sniffer daemon."""
        if getattr(app, '_system_initialized', False):
            return
        if os.environ.get('WERKZEUG_RUN_MAIN') != 'true' and app.debug and not app.config.get('TESTING'):
            return

        global sniffer_instance, threat_detector_instance
        
        if sniffer_instance is None:
            # Instantiate defensive threat capture pipeline (skip live capture in tests)
            email_notifier = EmailNotifier(app)
            threat_detector_instance = ThreatDetector(app, email_notifier)
            
            sim_mode = app.config.get('SNIFFER_SIMULATION', True)
            if not app.config.get('TESTING'):
                iface = app.config.get('SNIFFER_INTERFACE') or os.environ.get('SNIFFER_INTERFACE')
                interval = float(app.config.get('SNIFFER_SIMULATION_INTERVAL', 0.5))
                
                sniffer_instance = NetworkSniffer(
                    app=app, 
                    threat_detector=threat_detector_instance,
                    interface=iface,
                    simulation=sim_mode,
                    simulation_interval=interval
                )
                sniffer_instance.start()
            else:
                print("NetworkSniffer startup skipped because TESTING mode is enabled.")

            with app.app_context():
                log_system('INFO', f"Flask Web Application Initialized. Background Sniffer Daemon launched. Simulation: {sim_mode}")

        app._system_initialized = True

    return app

# Main execution entrypoint
if __name__ == '__main__':
    app = create_app()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
