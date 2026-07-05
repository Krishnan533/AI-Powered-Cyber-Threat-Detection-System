import os
import sys
from flask import Flask, render_template, session, jsonify
from dotenv import load_dotenv

load_dotenv()

from backend.config.settings import config_by_name
from backend.extensions import db, mail
from backend.routes import register_blueprints
from backend.services.email_notifier import EmailNotifier
from backend.services.threat_detector import ThreatDetector
from packet_capture.sniffer import NetworkSniffer
from backend.utils.helpers import log_system

# Global instances for background daemons
sniffer_instance = None
threat_detector_instance = None

def create_app(config_name=None):
    """Flask Application Factory."""
    app = Flask(__name__, 
                template_folder='templates',
                static_folder='static')
    
    # Load configuration
    if not config_name:
        config_name = os.environ.get('FLASK_ENV', 'development')
    app.config.from_object(config_by_name[config_name])
    
    # Store python execution path for dynamic model retraining subprocesses
    app.config['PYTHON_EXECUTABLE'] = sys.executable

    # Initialize extensions
    db.init_app(app)
    mail.init_app(app)
    
    # Register routes blueprints
    register_blueprints(app)

    # Inject CSRF token to templates contexts
    @app.context_processor
    def inject_csrf():
        return dict(csrf_token=session.get('csrf_token', ''))

    # Global Error Handlers
    @app.errorhandler(401)
    def unauthorized(e):
        return render_template('login.html'), 401

    @app.errorhandler(403)
    def forbidden(e):
        return render_template('base.html', error="403 Forbidden - Access Denied"), 403

    @app.errorhandler(404)
    def page_not_found(e):
        # API return
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Resource not found'}), 404
        return render_template('base.html', error="404 Not Found"), 404

    @app.errorhandler(500)
    def server_error(e):
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Internal server error'}), 500
        return render_template('base.html', error="500 Internal Server Error"), 500

    # Hook database initialization and packet sniffer daemon thread startup
    @app.before_all_requests
    def initialize_system():
        """Executed once before the very first request to start background sniffer and setup DB."""
        # Ensure we only start this once (even with Werkzeug reloader enabled)
        if os.environ.get('WERKZEUG_RUN_MAIN') != 'true' and app.debug:
            # We are in the parent reloader process, wait for the actual worker process to spin up sniffer
            return
            
        global sniffer_instance, threat_detector_instance
        
        if sniffer_instance is None:
            # 1. Initialize Tables if they do not exist (useful for SQLite / automatic deployments)
            try:
                db.create_all()
                print("SQLAlchemy: Database tables created/verified.")
            except Exception as e:
                print(f"SQLAlchemy Database verification failed: {e}")

            # 2. Instantiate and launch the defensive threat capture pipeline
            email_notifier = EmailNotifier(app)
            threat_detector_instance = ThreatDetector(app, email_notifier)
            
            # Read variables
            iface = os.environ.get('SNIFFER_INTERFACE')
            sim_mode = os.environ.get('SNIFFER_SIMULATION', 'TRUE').lower() in ('true', '1', 't')
            interval = float(os.environ.get('SNIFFER_SIMULATION_INTERVAL', 0.5))
            
            sniffer_instance = NetworkSniffer(
                app=app, 
                threat_detector=threat_detector_instance,
                interface=iface,
                simulation=sim_mode,
                simulation_interval=interval
            )
            sniffer_instance.start()
            
            # Log diagnostics
            with app.app_context():
                log_system('INFO', f"Flask Web Application Initialized. Background Sniffer Daemon launched. Simulation: {sim_mode}")

    return app

# Main execution entrypoint
if __name__ == '__main__':
    app = create_app()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
