from datetime import datetime
from backend.extensions import db

class SystemLog(db.Model):
    __tablename__ = 'system_logs'
    __table_args__ = (
        db.Index('idx_system_timestamp', 'timestamp'),
        db.Index('idx_system_level', 'level'),
    )

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    level = db.Column(db.String(15), nullable=False) # INFO, WARNING, ERROR
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'level': self.level,
            'message': self.message,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None
        }
