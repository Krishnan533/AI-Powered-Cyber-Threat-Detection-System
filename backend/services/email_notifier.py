from flask_mail import Message
from backend.extensions import mail
from backend.utils.helpers import log_system
import os

class EmailNotifier:
    """Service to send SMTP email warning alerts when threat events occur."""
    
    def __init__(self, app=None):
        self.app = app
        
    def init_app(self, app):
        self.app = app

    def send_threat_alert(self, threat_dict):
        """
        Sends an email alert to the system admin containing details about a threat event.
        
        Parameters:
        - threat_dict (dict): Dictionary representation of the Threat model.
        """
        if not self.app:
            print("EmailNotifier Warning: App not initialized. Skipping email send.")
            return False
            
        admin_email = self.app.config.get('ADMIN_EMAIL')
        if not admin_email:
            log_system('WARNING', "EmailNotifier: ADMIN_EMAIL not configured. Alerts will not be sent.")
            return False

        with self.app.app_context():
            subject = f"[SECURITY ALERT] {threat_dict['severity_level']} threat: {threat_dict['type']} detected!"
            
            body = f"""
AI-POWERED CYBER THREAT DETECTOR ALERT

A security threat event has been detected on the network.

Threat Details:
----------------------------------------
Threat ID: {threat_dict['id']}
Type: {threat_dict['type']}
Source IP: {threat_dict['source_ip']}
Destination IP: {threat_dict['destination_ip'] or 'N/A'}
Severity Score: {threat_dict['severity_score']}/10.0
Severity Level: {threat_dict['severity_level']}
Detected Time: {threat_dict['timestamp']}
AI Detected: {threat_dict['ai_detected']}
Status: {threat_dict['status']}

Description:
{threat_dict['description']}

Action taken:
The event has been recorded in the database. 
"""
            # Add warning for critical/high threats
            if threat_dict['severity_level'] in ('High', 'Critical'):
                body += "\nRECOMMENDED ACTION: Verify the threat profile immediately. If necessary, ensure the IP is added to the blocked list via the Admin Console.\n"
            else:
                body += "\nRECOMMENDED ACTION: System logged. Monitoring source IP pattern.\n"
                
            body += "\n---\nAutomated alert from Cyber Threat Detection and Monitoring Daemon.\n"

            msg = Message(
                subject=subject,
                recipients=[admin_email],
                body=body
            )

            try:
                mail.send(msg)
                log_system('INFO', f"Alert email dispatched to {admin_email} for threat event {threat_dict['id']}")
                return True
            except Exception as e:
                # If smtp fails, log to system warnings and allow the system to proceed gracefully
                log_system('WARNING', f"Failed to send email alert for threat event {threat_dict['id']}: {e}")
                return False
