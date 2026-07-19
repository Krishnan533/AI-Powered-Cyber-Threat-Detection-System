import pytest
from datetime import datetime
from backend.app import create_app
from backend.extensions import db
from backend.models.packet import Packet
from backend.models.threat import Threat
from backend.models.blocked_ip import BlockedIP
from backend.services.threat_detector import ThreatDetector

@pytest.fixture
def app():
    app = create_app('testing')
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    with app.app_context():
        db.create_all()
        yield app
        db.drop_all()

def test_ddos_detection_rule(app):
    """Verifies that threat detector flags DDoS when packet volume spikes."""
    with app.app_context():
        detector = ThreatDetector(app, email_service=None)
        src_ip = "192.168.10.99"
        
        # Log 110 packets in under 1 second from the same IP
        now = datetime.utcnow()
        for _ in range(110):
            p = Packet(
                src_ip=src_ip,
                dst_ip="192.168.10.1",
                protocol="UDP",
                packet_size=1000,
                timestamp=now
            )
            # Run detection (sliding window tracks it)
            detector.process_packet(p)
            
        # Verify threat was logged in database
        threats = Threat.query.filter_by(source_ip=src_ip, type="DDoS").all()
        assert len(threats) > 0
        assert threats[0].severity_level == "Critical"
        
        # Check if the IP was auto blocked
        blocked = BlockedIP.query.filter_by(ip_address=src_ip).first()
        assert blocked is not None
        assert "DDoS" in blocked.reason

def test_port_scan_detection_rule(app):
    """Verifies that threat detector flags Port Scanning when destination ports spike."""
    with app.app_context():
        detector = ThreatDetector(app, email_service=None)
        src_ip = "172.16.5.5"
        
        # Scan 20 unique destination ports in quick sequence
        for port in range(1, 22):
            p = Packet(
                src_ip=src_ip,
                dst_ip="172.16.5.1",
                protocol="TCP",
                src_port=54321,
                dst_port=port,
                flags="S",
                packet_size=64,
                timestamp=datetime.utcnow()
            )
            detector.process_packet(p)
            
        # Verify threat was logged in DB
        threats = Threat.query.filter_by(source_ip=src_ip, type="Port Scan").all()
        assert len(threats) > 0
        assert threats[0].severity_level == "High"
        
        # Check auto block
        blocked = BlockedIP.query.filter_by(ip_address=src_ip).first()
        assert blocked is not None
