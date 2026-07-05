from datetime import datetime
from backend.extensions import db

class BlockedIP(db.Model):
    __tablename__ = 'blocked_ips'

    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), nullable=False, unique=True)
    reason = db.Column(db.String(255), nullable=True)
    blocked_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=True)
    blocked_by = db.Column(db.String(50), default='System')

    def is_expired(self):
        if self.expires_at is None:
            return False
        return datetime.utcnow() > self.expires_at

    def to_dict(self):
        return {
            'id': self.id,
            'ip_address': self.ip_address,
            'reason': self.reason,
            'blocked_at': self.blocked_at.isoformat() if self.blocked_at else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'blocked_by': self.blocked_by,
            'is_expired': self.is_expired()
        }
