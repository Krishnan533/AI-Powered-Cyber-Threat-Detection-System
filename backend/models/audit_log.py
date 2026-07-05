from datetime import datetime
from backend.extensions import db

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'

    id = db.Column(db.BigInteger, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    action = db.Column(db.String(100), nullable=False) # e.g., USER_LOGIN, IP_BLOCKED, THREAT_RESOLVED
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45), nullable=True)
    details = db.Column(db.Text, nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'username': self.user.username if self.user else 'System',
            'action': self.action,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'ip_address': self.ip_address,
            'details': self.details
        }
