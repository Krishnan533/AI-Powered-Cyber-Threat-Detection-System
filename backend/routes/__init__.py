from backend.routes.auth import auth_bp
from backend.routes.dashboard import dashboard_bp
from backend.routes.threats import threats_bp
from backend.routes.blocked_ips import blocked_ips_bp
from backend.routes.logs import logs_bp

def register_blueprints(app):
    """Registers all blueprints to the Flask application instance."""
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(threats_bp)
    app.register_blueprint(blocked_ips_bp)
    app.register_blueprint(logs_bp)
