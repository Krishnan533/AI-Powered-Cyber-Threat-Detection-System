import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from backend.extensions import db
from backend.models import Threat, BlockedIP, Packet
from backend.utils.helpers import log_system, log_audit
from ai_model.anomaly_detector import AnomalyDetector

class ThreatDetector:
    """
    Threat detection engine combining rule-based heuristics and an AI anomaly model.
    Maintains temporary sliding windows in-memory for fast event aggregation.
    """
    
    def __init__(self, app=None, email_service=None):
        self.app = app
        self.email_service = email_service
        self.ai_detector = AnomalyDetector()
        
        # In-memory sliding windows (tracked by source_ip)
        self.packet_timestamps = defaultdict(deque) # source_ip -> timestamps of packets for DDoS detection
        self.scanned_ports = defaultdict(lambda: defaultdict(list)) # source_ip -> {dst_port -> timestamps} for Port Scan
        self.failed_auth_attempts = defaultdict(deque) # source_ip -> timestamps targeting SSH/RDP/FTP/Telnet
        self.last_packet_time = {} # source_ip -> timestamp of the previous packet for AI delta calculations
        
        # Track active alerts in memory to prevent spamming duplicates in a short period (10-second cooldown per alert type)
        self.alert_cooldowns = defaultdict(float) # (source_ip, threat_type) -> timestamp of last alert

    def init_app(self, app, email_service):
        self.app = app
        self.email_service = email_service

    def process_packet(self, packet_model):
        """
        Analyzes a single packet logged in the system.
        
        Parameters:
        - packet_model (Packet): SQLAlchemy Packet model instance.
        """
        src_ip = packet_model.src_ip
        dst_ip = packet_model.dst_ip
        dport = packet_model.dst_port
        sport = packet_model.src_port
        protocol = packet_model.protocol
        size = packet_model.packet_size
        flags = packet_model.flags
        curr_time = packet_model.timestamp or datetime.utcnow()
        curr_ts = curr_time.timestamp()

        # Calculate time delta for AI model
        time_delta = 0.0
        if src_ip in self.last_packet_time:
            time_delta = max(0.0, curr_ts - self.last_packet_time[src_ip])
        self.last_packet_time[src_ip] = curr_ts

        # ------------------ RULE-BASED HEURISTICS ------------------
        
        # 1. DDoS Detection
        # Clean timestamps older than 1 second
        self.packet_timestamps[src_ip].append(curr_ts)
        while self.packet_timestamps[src_ip] and self.packet_timestamps[src_ip][0] < curr_ts - 1.0:
            self.packet_timestamps[src_ip].popleft()
            
        # Threshold: More than 100 packets/sec
        if len(self.packet_timestamps[src_ip]) > 100:
            self._trigger_threat(
                threat_type="DDoS",
                source_ip=src_ip,
                destination_ip=dst_ip,
                severity_score=9.5,
                severity_level="Critical",
                description=f"DDoS volumetric flood: {len(self.packet_timestamps[src_ip])} packets/sec from source IP.",
                ai_detected=False
            )

        # 2. Port Scan Detection
        # Clean timestamps older than 10 seconds
        if dport is not None:
            self.scanned_ports[src_ip][dport].append(curr_ts)
            # Cleanup for this port
            while self.scanned_ports[src_ip][dport] and self.scanned_ports[src_ip][dport][0] < curr_ts - 10.0:
                self.scanned_ports[src_ip][dport].pop(0)
                
            # Cleanup entirely empty ports from dict
            inactive_ports = []
            for p, ts_list in self.scanned_ports[src_ip].items():
                # Filter old entries
                self.scanned_ports[src_ip][p] = [t for t in ts_list if t >= curr_ts - 10.0]
                if not self.scanned_ports[src_ip][p]:
                    inactive_ports.append(p)
            for p in inactive_ports:
                del self.scanned_ports[src_ip][p]
                
            # Check unique port counts in the last 10 seconds
            unique_ports = len(self.scanned_ports[src_ip])
            if unique_ports >= 15:
                self._trigger_threat(
                    threat_type="Port Scan",
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    severity_score=8.0,
                    severity_level="High",
                    description=f"Port scanning pattern: scanned {unique_ports} unique ports in 10 seconds.",
                    ai_detected=False
                )

        # 3. Brute Force Connection Pattern
        # SSH (22), FTP (21), Telnet (23), RDP (3389)
        auth_ports = {21, 22, 23, 3389}
        if dport in auth_ports or sport in auth_ports:
            # Let's count connection attempts. TCP SYN 'S' flags or general traffic counts.
            if flags == 'S' or protocol.upper() == 'TCP':
                self.failed_auth_attempts[src_ip].append(curr_ts)
                
                # Cleanup older than 1 minute
                while self.failed_auth_attempts[src_ip] and self.failed_auth_attempts[src_ip][0] < curr_ts - 60.0:
                    self.failed_auth_attempts[src_ip].popleft()
                    
                # Threshold: > 10 attempts in 1 minute to authentication services
                if len(self.failed_auth_attempts[src_ip]) > 10:
                    self._trigger_threat(
                        threat_type="Brute Force",
                        source_ip=src_ip,
                        destination_ip=dst_ip,
                        severity_score=7.5,
                        severity_level="High",
                        description=f"Suspicious brute force sequence: {len(self.failed_auth_attempts[src_ip])} connection attempts targeting auth port {dport} in 1 min.",
                        ai_detected=False
                    )

        # 4. Malware Traffic Detection
        # Check signature ports or payload signatures
        malware_ports = {6667, 31337, 4444, 135, 139, 445}
        if dport in malware_ports or sport in malware_ports:
            # Trigger alert for communication on typical trojan/worm/IRC ports
            self._trigger_threat(
                threat_type="Malware Traffic",
                source_ip=src_ip,
                destination_ip=dst_ip,
                severity_score=8.5,
                severity_level="High",
                description=f"Identified connection attempt on known backdoor/malware port (Port: {dport or sport}).",
                ai_detected=False
            )

        # 5. Unknown IP / Extraterritorial IP Detection
        # For simulation: flag typical suspicious external ranges (e.g. IPs starting with 203., 198., or similar)
        suspicious_prefixes = ('203.0.113.', '198.51.100.', '192.0.2.')
        if src_ip.startswith(suspicious_prefixes):
            # Check if we have triggered Unknown IP alert
            self._trigger_threat(
                threat_type="Unknown IP",
                source_ip=src_ip,
                destination_ip=dst_ip,
                severity_score=4.0,
                severity_level="Low",
                description=f"Inbound traffic detected from unregistered/unusual security perimeter IP: {src_ip}",
                ai_detected=False
            )

        # ------------------ AI ANOMALY DETECTION ------------------
        is_anomaly, anomaly_score = self.ai_detector.predict_packet(
            packet_size=size,
            protocol=protocol,
            src_port=sport,
            dst_port=dport,
            time_delta=time_delta
        )
        
        if is_anomaly:
            severity = "Medium"
            score = anomaly_score * 10.0
            if score >= 8.5:
                severity = "Critical"
            elif score >= 7.0:
                severity = "High"
            elif score >= 4.0:
                severity = "Medium"
            else:
                severity = "Low"
                
            self._trigger_threat(
                threat_type="AI Anomaly",
                source_ip=src_ip,
                destination_ip=dst_ip,
                severity_score=round(score, 2),
                severity_level=severity,
                description=f"AI Isolation Forest outlier flagged. Threat score: {round(score, 2)}/10.0. Features: size={size}, protocol={protocol}, dport={dport}.",
                ai_detected=True
            )

    def _trigger_threat(self, threat_type, source_ip, destination_ip, severity_score, severity_level, description, ai_detected):
        """Creates a threat record in the database, runs alerts, and blocks IP if critical."""
        curr_time = time.time()
        
        # Check cooldown to prevent spam (max 1 notification/DB log per source IP per threat type every 10 seconds)
        cooldown_key = (source_ip, threat_type)
        if curr_time - self.alert_cooldowns[cooldown_key] < 10.0:
            return

        self.alert_cooldowns[cooldown_key] = curr_time

        try:
            # Check if this source IP is already blocked to avoid double blocks
            is_blocked = BlockedIP.query.filter_by(ip_address=source_ip).first() is not None
            
            # Create threat record
            threat = Threat(
                type=threat_type,
                source_ip=source_ip,
                destination_ip=destination_ip,
                severity_score=severity_score,
                severity_level=severity_level,
                timestamp=datetime.utcnow(),
                status='Active',
                description=description,
                ai_detected=ai_detected
            )
            db.session.add(threat)
            db.session.commit()
            
            # Retrieve model dictionary for event signaling
            threat_dict = threat.to_dict()

            log_system('WARNING', f"Security Threat Detected! Type: {threat_type}, Source: {source_ip}, Score: {severity_score}")
            
            # Auto-block IP if Critical or High threat (and not already blocked)
            if severity_level in ('High', 'Critical') and not is_blocked:
                block_duration = 24 if severity_level == 'Critical' else 2
                expiration = datetime.utcnow() + timedelta(hours=block_duration)
                
                block_ip = BlockedIP(
                    ip_address=source_ip,
                    reason=f"Auto blocked by threat detection daemon. Trigger: {threat_type}. Detail: {description[:120]}",
                    blocked_at=datetime.utcnow(),
                    expires_at=expiration,
                    blocked_by="System Daemon"
                )
                db.session.add(block_ip)
                db.session.commit()
                
                log_audit(
                    action="IP_AUTO_BLOCKED",
                    details=f"System automatically blocked IP {source_ip} for {block_duration} hours. Reason: {threat_type} detected.",
                    ip_address=source_ip
                )
                log_system('INFO', f"IP {source_ip} auto blocked due to {threat_type} ({severity_level})")

            # Dispatch Alert Email (Asynchronously in production, but here we invoke it gracefully)
            if self.email_service:
                self.email_service.send_threat_alert(threat_dict)
                
        except Exception as e:
            db.session.rollback()
            log_system('ERROR', f"Failed to record threat event in DB: {e}")
