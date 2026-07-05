from datetime import datetime
from backend.extensions import db

class Packet(db.Model):
    __tablename__ = 'packets'

    id = db.Column(db.BigInteger, primary_key=True, autoincrement=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    src_ip = db.Column(db.String(45), nullable=False)
    dst_ip = db.Column(db.String(45), nullable=False)
    src_port = db.Column(db.Integer, nullable=True)
    dst_port = db.Column(db.Integer, nullable=True)
    protocol = db.Column(db.String(10), nullable=False)
    packet_size = db.Column(db.Integer, nullable=False)
    flags = db.Column(db.String(15), nullable=True)
    payload_preview = db.Column(db.String(255), nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'protocol': self.protocol,
            'packet_size': self.packet_size,
            'flags': self.flags,
            'payload_preview': self.payload_preview
        }
