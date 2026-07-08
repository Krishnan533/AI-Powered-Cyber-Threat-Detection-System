from datetime import datetime
from backend.extensions import db

class Threat(db.Model):
    __tablename__ = 'threats'
    __table_args__ = (
        db.Index('idx_threat_source_ip', 'source_ip'),
        db.Index('idx_threat_type', 'type'),
        db.Index('idx_threat_status', 'status'),
        db.Index('idx_threat_severity_level', 'severity_level'),
        db.Index('idx_threat_timestamp', 'timestamp'),
    )

    id = db.Column(db.BigInteger().with_variant(db.Integer(), 'sqlite'), primary_key=True, autoincrement=True)
    type = db.Column(db.String(50), nullable=False) # DDoS, Port Scan, Brute Force, Unknown IP, Malware Traffic, AI Anomaly
    source_ip = db.Column(db.String(45), nullable=False)
    destination_ip = db.Column(db.String(45), nullable=True)
    severity_score = db.Column(db.Float, nullable=False)
    severity_level = db.Column(db.String(10), nullable=False) # Low, Medium, High, Critical
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), nullable=False, default='Active') # Active, Resolved, False Positive
    description = db.Column(db.Text, nullable=True)
    ai_detected = db.Column(db.Boolean, default=False)

    def to_dict(self):
        return {
            'id': self.id,
            'type': self.type,
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'severity_score': self.severity_score,
            'severity_level': self.severity_level,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'status': self.status,
            'description': self.description,
            'ai_detected': self.ai_detected
        }
