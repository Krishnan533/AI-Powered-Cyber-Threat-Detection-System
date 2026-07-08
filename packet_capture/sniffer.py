import os
import sys
import time
import random
import threading
from datetime import datetime

# Handle potential import problems for scapy in different setups
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from backend.extensions import db
from backend.models import Packet
from backend.services.threat_detector import ThreatDetector
from backend.utils.helpers import log_system

class NetworkSniffer:
    """Background Daemon that sniffs network packets using Scapy, or simulates network traffic if configured."""

    def __init__(self, app, threat_detector, interface=None, simulation=False, simulation_interval=0.5):
        self.app = app
        self.threat_detector = threat_detector
        self.interface = interface or os.environ.get('SNIFFER_INTERFACE')
        self.simulation = simulation or (os.environ.get('SNIFFER_SIMULATION', 'TRUE').lower() in ('true', '1', 't'))
        self.simulation_interval = float(simulation_interval or os.environ.get('SNIFFER_SIMULATION_INTERVAL', 0.5))
        self.stop_event = threading.Event()
        self.thread = None

    def start(self):
        """Starts packet sniffing in a background daemon thread."""
        if self.thread and self.thread.is_alive():
            print("Sniffer thread is already running.")
            return
            
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._run, name="PacketSnifferDaemon", daemon=True)
        self.thread.start()
        log_system('INFO', f"NetworkSniffer thread started. Simulation mode: {self.simulation}")

    def stop(self):
        """Signals the background sniffer to stop execution."""
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=3.0)
        log_system('INFO', "NetworkSniffer thread stopped.")

    def _run(self):
        """Executes sniffing loop or simulated traffic loop depending on config."""
        if self.simulation:
            self._run_simulation()
        else:
            self._run_live_sniffing()

    def _run_live_sniffing(self):
        """Binds to network socket and captures actual system traffic."""
        if not SCAPY_AVAILABLE:
            log_system('ERROR', "Scapy is not installed. Live packet capturing unavailable. Falling back to simulation.")
            self._run_simulation()
            return

        log_system('INFO', f"Listening for packets on interface '{self.interface or 'default'}'...")
        
        def packet_handler(pkt):
            if self.stop_event.is_set():
                return True # Stops scapy sniff loop
                
            if IP in pkt:
                self._parse_and_log_packet(pkt)
                
        # Run scapy sniff
        try:
            sniff_args = {
                "prn": packet_handler,
                "store": 0,
                "stop_filter": lambda x: self.stop_event.is_set()
            }
            if self.interface:
                sniff_args["iface"] = self.interface
                
            sniff(**sniff_args)
        except Exception as e:
            log_system('ERROR', f"Live sniffing failed on adapter '{self.interface or 'default'}': {e}. Falling back to simulation.")
            self._run_simulation()

    def _parse_and_log_packet(self, pkt):
        """Extracts values from Scapy packet, commits to database, and triggers detector."""
        try:
            ip_layer = pkt[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            protocol = "OTHER"
            sport = None
            dport = None
            flags = None
            payload_preview = None
            
            # Layer 4 identification
            if TCP in pkt:
                protocol = "TCP"
                tcp_layer = pkt[TCP]
                sport = tcp_layer.sport
                dport = tcp_layer.dport
                flags = str(tcp_layer.flags)
            elif UDP in pkt:
                protocol = "UDP"
                udp_layer = pkt[UDP]
                sport = udp_layer.sport
                dport = udp_layer.dport
            elif ICMP in pkt:
                protocol = "ICMP"
                
            # Extract raw payload snippet if present
            if Raw in pkt:
                try:
                    payload_preview = str(pkt[Raw].load[:100].decode('utf-8', errors='ignore'))
                except Exception:
                    payload_preview = str(pkt[Raw].load[:50]) # raw binary preview

            # Create packet record inside Flask App Context
            with self.app.app_context():
                packet_record = Packet(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=sport,
                    dst_port=dport,
                    protocol=protocol,
                    packet_size=len(pkt),
                    flags=flags,
                    payload_preview=payload_preview[:250] if payload_preview else None,
                    timestamp=datetime.utcnow()
                )
                db.session.add(packet_record)
                db.session.commit()
                
                # Analyze packet
                self.threat_detector.process_packet(packet_record)
                
        except Exception as e:
            db.session.rollback()
            log_system('ERROR', f"Error parsing packet: {e}")
            print(f"Error parsing packet: {e}")

    def _run_simulation(self):
        """Generates mock packets simulating web usage, DNS lookup, and periodic threats."""
        log_system('INFO', "Starting packet simulation daemon loop...")
        
        # Test IPs
        normal_ips = ["192.168.1.15", "192.168.1.20", "192.168.1.35", "10.0.0.12"]
        dest_ips = ["192.168.1.254", "8.8.8.8", "142.250.190.46", "20.222.100.12"]
        
        threat_ips = {
            "ddos": "198.51.100.12",
            "scan": "203.0.113.45",
            "bruteforce": "198.51.100.99",
            "malware": "192.0.2.145",
            "anomaly": "192.168.1.111"
        }
        
        sim_counter = 0

        while not self.stop_event.is_set():
            sim_counter += 1
            time.sleep(self.simulation_interval)
            
            with self.app.app_context():
                try:
                    # Default is to generate a standard packet
                    pkt_type = "normal"
                    
                    # Periodically generate threat patterns for testing dashboard
                    # Every 40 packets: Port scan
                    if sim_counter % 60 == 0:
                        pkt_type = "scan"
                    # Every 80 packets: DDoS burst
                    elif sim_counter % 80 == 0:
                        pkt_type = "ddos"
                    # Every 100 packets: Brute force Sequence
                    elif sim_counter % 100 == 0:
                        pkt_type = "bruteforce"
                    # Every 120 packets: Malware C2 port attempt
                    elif sim_counter % 120 == 0:
                        pkt_type = "malware"
                    # Every 150 packets: AI anomaly (unusual size / packet delta)
                    elif sim_counter % 150 == 0:
                        pkt_type = "anomaly"

                    if pkt_type == "normal":
                        # Standard web or DNS packet
                        src = random.choice(normal_ips)
                        dst = random.choice(dest_ips)
                        proto = random.choice(["TCP", "TCP", "UDP", "ICMP"])
                        sport = random.choice([49152, 53210, 58443, 62111])
                        
                        if proto == "UDP":
                            dport = 53 # DNS
                            size = random.randint(50, 120)
                            payload = "Standard DNS query for google.com"
                            flags = None
                        else:
                            dport = random.choice([80, 443])
                            size = random.randint(100, 1500)
                            payload = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n"
                            flags = "A" if random.random() > 0.3 else "S"
                            
                    elif pkt_type == "scan":
                        # Simulate a rapid scan burst
                        src = threat_ips["scan"]
                        dst = "192.168.1.50"
                        proto = "TCP"
                        sport = random.randint(30000, 60000)
                        # Pick a random port to log at this specific step (threat detector aggregates over steps)
                        # We will log multiple packets in quick succession to trigger scan alarm
                        for port in range(1, 20):
                            packet_record = Packet(
                                src_ip=src,
                                dst_ip=dst,
                                src_port=sport,
                                dst_port=port,
                                protocol=proto,
                                packet_size=44,
                                flags="S",
                                payload_preview="SYN Port Scan Probe",
                                timestamp=datetime.utcnow()
                            )
                            db.session.add(packet_record)
                            db.session.commit()
                            self.threat_detector.process_packet(packet_record)
                        continue # Already processed multiple, skip the single log below
                        
                    elif pkt_type == "ddos":
                        # Simulate DDoS flood burst
                        src = threat_ips["ddos"]
                        dst = "192.168.1.50"
                        proto = "UDP"
                        sport = random.randint(1024, 65535)
                        dport = 80
                        # Insert 110 packets quickly to trigger volumetric threshold (>100 packets/sec)
                        for _ in range(110):
                            packet_record = Packet(
                                src_ip=src,
                                dst_ip=dst,
                                src_port=sport,
                                dst_port=dport,
                                protocol=proto,
                                packet_size=1250,
                                flags=None,
                                payload_preview="UDP Flooding attack payload block",
                                timestamp=datetime.utcnow()
                            )
                            db.session.add(packet_record)
                            db.session.commit()
                            self.threat_detector.process_packet(packet_record)
                        continue
                        
                    elif pkt_type == "bruteforce":
                        src = threat_ips["bruteforce"]
                        dst = "192.168.1.50"
                        proto = "TCP"
                        dport = 22 # SSH
                        for _ in range(12):
                            sport = random.randint(40000, 50000)
                            packet_record = Packet(
                                src_ip=src,
                                dst_ip=dst,
                                src_port=sport,
                                dst_port=dport,
                                protocol=proto,
                                packet_size=74,
                                flags="S",
                                payload_preview="SSH-2.0-OpenSSH_8.2p1 authentication sequence start",
                                timestamp=datetime.utcnow()
                            )
                            db.session.add(packet_record)
                            db.session.commit()
                            self.threat_detector.process_packet(packet_record)
                        continue
                        
                    elif pkt_type == "malware":
                        src = threat_ips["malware"]
                        dst = "10.0.0.12"
                        proto = "TCP"
                        sport = 55432
                        dport = 31337 # Trojan backdoor port
                        size = 250
                        payload = "C2 server callback instruction: exec /bin/bash"
                        flags = "AP"
                        
                    elif pkt_type == "anomaly":
                        # Isolation forest will flag large sizes to high/unusual ports
                        src = threat_ips["anomaly"]
                        dst = "10.0.0.10"
                        proto = "UDP"
                        sport = 65432
                        dport = 9999
                        size = 1480 # Large size
                        payload = "AI-flagged suspicious binary exfiltration segment"
                        flags = None

                    # Log the simulated packet
                    packet_record = Packet(
                        src_ip=src,
                        dst_ip=dst,
                        src_port=sport,
                        dst_port=dport,
                        protocol=proto,
                        packet_size=size,
                        flags=flags,
                        payload_preview=payload,
                        timestamp=datetime.utcnow()
                    )
                    db.session.add(packet_record)
                    db.session.commit()
                    
                    # Pipe to threat detection logic
                    self.threat_detector.process_packet(packet_record)
                    
                except Exception as e:
                    db.session.rollback()
                    print(f"Error in simulated packet processing loop: {e}")
                    time.sleep(2)
