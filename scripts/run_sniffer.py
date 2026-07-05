import os
import sys
import time
import signal
from dotenv import load_dotenv

# Ensure base directory is in path
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(base_dir)

load_dotenv()

from backend.app import create_app
from backend.services.email_notifier import EmailNotifier
from backend.services.threat_detector import ThreatDetector
from packet_capture.sniffer import NetworkSniffer

def run_standalone_sniffer():
    """Initializes and runs the NetworkSniffer daemon synchronously in the foreground."""
    print("AI-Powered Cyber Threat Detector - Standalone Sniffer process booting...")
    app = create_app()
    
    with app.app_context():
        # Setup detector & email notifier services
        email_notifier = EmailNotifier(app)
        threat_detector = ThreatDetector(app, email_notifier)
        
        # Read env configs
        iface = os.environ.get('SNIFFER_INTERFACE')
        sim_mode = os.environ.get('SNIFFER_SIMULATION', 'TRUE').lower() in ('true', '1', 't')
        interval = float(os.environ.get('SNIFFER_SIMULATION_INTERVAL', 0.5))
        
        sniffer = NetworkSniffer(
            app=app,
            threat_detector=threat_detector,
            interface=iface,
            simulation=sim_mode,
            simulation_interval=interval
        )
        
        # Define graceful shutdown
        def signal_handler(sig, frame):
            print("\nShutting down packet sniffer process...")
            sniffer.stop()
            sys.exit(0)
            
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        # Run sniffer in current thread (synchronous foreground execution)
        sniffer.stop_event.clear()
        print(f"Standalone Sniffer Daemon started. Simulation={sim_mode}. Press Ctrl+C to terminate.")
        sniffer._run()

if __name__ == '__main__':
    run_standalone_sniffer()
