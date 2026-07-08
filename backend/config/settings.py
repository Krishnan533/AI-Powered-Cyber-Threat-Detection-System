import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()

class Config:
    """Base Configuration class containing shared parameters."""
    SECRET_KEY = os.environ.get('SECRET_KEY', 'replace_with_a_very_secure_string_9018230')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Mail service defaults
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'localhost')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 1025))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'False').lower() in ('true', '1', 't')
    MAIL_USE_SSL = os.environ.get('MAIL_USE_SSL', 'False').lower() in ('true', '1', 't')
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME', '')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD', '')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER', 'threat-alerts@example.com')
    ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'admin-alerts@example.com')
    
    # Session configurations
    PERMANENT_SESSION_LIFETIME = timedelta(hours=2)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = False  # Set True in production with SSL
    SESSION_COOKIE_SAMESITE = 'Lax'

    # Default account bootstrap values; only seeded when enabled or in development.
    DEFAULT_ADMIN_USERNAME = os.environ.get('DEFAULT_ADMIN_USERNAME', 'admin')
    DEFAULT_ADMIN_PASSWORD = os.environ.get('DEFAULT_ADMIN_PASSWORD', 'AdminPass123!')
    DEFAULT_ANALYST_USERNAME = os.environ.get('DEFAULT_ANALYST_USERNAME', 'analyst')
    DEFAULT_ANALYST_PASSWORD = os.environ.get('DEFAULT_ANALYST_PASSWORD', 'AnalystPass456!')
    DEFAULT_VIEWER_USERNAME = os.environ.get('DEFAULT_VIEWER_USERNAME', 'viewer')
    DEFAULT_VIEWER_PASSWORD = os.environ.get('DEFAULT_VIEWER_PASSWORD', 'ViewerPass789!')
    SEED_DEFAULT_USERS = os.environ.get('SEED_DEFAULT_USERS', 'FALSE').lower() in ('true', '1', 't')
    SEND_EMAIL_NOTIFICATIONS = os.environ.get('SEND_EMAIL_NOTIFICATIONS', 'TRUE').lower() in ('true', '1', 't')

class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URL', 
        'mysql+pymysql://root:rootpassword@localhost:3306/network_monitor'
    )

class ProductionConfig(Config):
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URL', 
        'mysql+pymysql://root:rootpassword@db:3306/network_monitor'
    )
    SESSION_COOKIE_SECURE = True  # Enforce secure cookies in production

class TestingConfig(Config):
    TESTING = True
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False
    SESSION_COOKIE_SECURE = False

config_by_name = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig
}
