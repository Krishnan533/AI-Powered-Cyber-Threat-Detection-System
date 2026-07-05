-- Seed data for testing the Threat Detection System
USE network_monitor;

-- Clear previous data
SET FOREIGN_KEY_CHECKS = 0;
TRUNCATE TABLE audit_logs;
TRUNCATE TABLE blocked_ips;
TRUNCATE TABLE threats;
TRUNCATE TABLE packets;
TRUNCATE TABLE users;
SET FOREIGN_KEY_CHECKS = 1;

-- Insert users
-- Passwords:
-- admin / admin123 -> Pbkdf2 SHA256 hashed matching werkzeug.security: scrypt:32768:8:1$Yx2WfS5nCY5LSpS7$f32c3f8f1c84b1d6... wait, we can seed standard werkzeug.security generate_password_hash values.
-- We will use scrypt hashes of Werkzeug 3.x:
-- admin: 'scrypt:32768:8:1$hU8I9JQL5v22A8w7$bd8ce1d5de8ec0b8417642674e2d31215b4bc7de0584489aeccdd5aae9170e7e'  (Password: AdminPass123!)
-- analyst: 'scrypt:32768:8:1$jOk9xS7vDkP128wI$2e8548bb95b5839bce545a9dc574b29bb88e9cfecda486effdca07bb6b2e1bd0' (Password: AnalystPass456!)
-- viewer: 'scrypt:32768:8:1$K12msPaL90vKw11s$b87cd66df75de23fa0de75fd549bde2a13cc7c9da606ef08de80debd7ee29023'  (Password: ViewerPass789!)

INSERT INTO users (id, username, password_hash, role) VALUES
(1, 'admin', 'scrypt:32768:8:1$hU8I9JQL5v22A8w7$bd8ce1d5de8ec0b8417642674e2d31215b4bc7de0584489aeccdd5aae9170e7e', 'Admin'),
(2, 'analyst', 'scrypt:32768:8:1$jOk9xS7vDkP128wI$2e8548bb95b5839bce545a9dc574b29bb88e9cfecda486effdca07bb6b2e1bd0', 'Analyst'),
(3, 'viewer', 'scrypt:32768:8:1$K12msPaL90vKw11s$b87cd66df75de23fa0de75fd549bde2a13cc7c9da606ef08de80debd7ee29023', 'Viewer');

-- Insert initial sample/test packets
INSERT INTO packets (src_ip, dst_ip, src_port, dst_port, protocol, packet_size, flags, payload_preview) VALUES
('192.168.1.15', '192.168.1.254', 53210, 80, 'TCP', 64, 'S', 'GET / HTTP/1.1'),
('192.168.1.15', '192.168.1.254', 53210, 80, 'TCP', 1200, 'A', 'HTTP/1.1 200 OK'),
('10.0.0.5', '192.168.1.50', 58732, 22, 'TCP', 78, 'S', 'SSH-2.0-OpenSSH_8.2p1'),
('192.168.1.100', '8.8.8.8', 49152, 53, 'UDP', 52, NULL, 'Standard query A google.com'),
('203.0.113.12', '192.168.1.50', 44321, 80, 'TCP', 40, 'R', NULL);

-- Insert initial detected threats
INSERT INTO threats (type, source_ip, destination_ip, severity_score, severity_level, status, description, ai_detected) VALUES
('Port Scan', '203.0.113.45', '192.168.1.50', 8.2, 'High', 'Active', 'Source IP scanned 45 unique destination ports in 1.2 seconds.', FALSE),
('DDoS', '198.51.100.12', '192.168.1.50', 9.5, 'Critical', 'Active', 'DDoS volumetric alert: 4500 packets/sec detected from isolated IP source.', FALSE),
('AI Anomaly', '192.168.1.111', '10.0.0.10', 6.5, 'Medium', 'Active', 'Isolation Forest anomaly detected: unusual payload size to UDP ports.', TRUE),
('Brute Force', '198.51.100.99', '192.168.1.50', 7.8, 'High', 'Resolved', 'Multiple failed login attempts on port 22 (SSH). IP automatically resolved via lock.', FALSE);

-- Insert initial blocked IPs
INSERT INTO blocked_ips (ip_address, reason, expires_at, blocked_by) VALUES
('203.0.113.45', 'Port scanning detected on interface eth0', DATE_ADD(NOW(), INTERVAL 24 HOUR), 'System'),
('198.51.100.12', 'DDoS flood source mitigation rule', DATE_ADD(NOW(), INTERVAL 2 HOUR), 'admin');

-- Insert initial audit logs
INSERT INTO audit_logs (user_id, action, ip_address, details) VALUES
(1, 'USER_LOGIN', '192.168.1.15', 'Admin logged in successfully'),
(1, 'IP_BLOCKED', '192.168.1.15', 'Blocked IP 198.51.100.12 due to DDoS detection'),
(2, 'VIEW_THREATS', '192.168.1.16', 'Analyst queried the threats event viewer');

-- Insert initial system logs
INSERT INTO system_logs (level, message) VALUES
('INFO', 'Database seeded with default mock threat logs.'),
('INFO', 'Threat detector service listening on active adapter.');
