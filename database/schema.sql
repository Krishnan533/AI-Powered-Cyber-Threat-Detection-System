-- AI-Powered Cyber Threat Detection and Network Monitoring System
-- Database Schema for MySQL 8.0+

CREATE DATABASE IF NOT EXISTS network_monitor;
USE network_monitor;

-- Table: users (Authentication and Roles)
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'Analyst',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT chk_role CHECK (role IN ('Admin', 'Analyst', 'Viewer'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table: packets (Metadata logs for raw network packets captured by Scapy)
CREATE TABLE IF NOT EXISTS packets (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    timestamp TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    src_ip VARCHAR(45) NOT NULL,
    dst_ip VARCHAR(45) NOT NULL,
    src_port INT DEFAULT NULL,
    dst_port INT DEFAULT NULL,
    protocol VARCHAR(10) NOT NULL,
    packet_size INT NOT NULL,
    flags VARCHAR(15) DEFAULT NULL,
    payload_preview VARCHAR(255) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table: threats (Identified threats via rules or AI anomaly engine)
CREATE TABLE IF NOT EXISTS threats (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    type VARCHAR(50) NOT NULL, -- DDoS, Port Scan, Brute Force, Unknown IP, Malware Traffic, AI Anomaly
    source_ip VARCHAR(45) NOT NULL,
    destination_ip VARCHAR(45) DEFAULT NULL,
    severity_score FLOAT NOT NULL CHECK (severity_score BETWEEN 0.0 AND 10.0),
    severity_level VARCHAR(10) NOT NULL CHECK (severity_level IN ('Low', 'Medium', 'High', 'Critical')),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(20) NOT NULL DEFAULT 'Active' CHECK (status IN ('Active', 'Resolved', 'False Positive')),
    description TEXT DEFAULT NULL,
    ai_detected BOOLEAN DEFAULT FALSE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table: blocked_ips (IP firewall mitigation table)
CREATE TABLE IF NOT EXISTS blocked_ips (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL UNIQUE,
    reason VARCHAR(255) DEFAULT NULL,
    blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NULL DEFAULT NULL,
    blocked_by VARCHAR(50) DEFAULT 'System'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table: audit_logs (Log logins, role elevations, blocks, resolutions)
CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NULL,
    action VARCHAR(100) NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ip_address VARCHAR(45) DEFAULT NULL,
    details TEXT DEFAULT NULL,
    CONSTRAINT fk_audit_users FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table: system_logs (Diagnostics and internal warnings)
CREATE TABLE IF NOT EXISTS system_logs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    level VARCHAR(15) NOT NULL CHECK (level IN ('INFO', 'WARNING', 'ERROR')),
    message TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Indexes for performance optimizations
CREATE INDEX idx_packets_src_ip ON packets(src_ip);
CREATE INDEX idx_packets_dst_ip ON packets(dst_ip);
CREATE INDEX idx_packets_timestamp ON packets(timestamp DESC);
CREATE INDEX idx_threats_source_ip ON threats(source_ip);
CREATE INDEX idx_threats_timestamp ON threats(timestamp DESC);
CREATE INDEX idx_blocked_ips_ip ON blocked_ips(ip_address);
CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp DESC);
CREATE INDEX idx_system_logs_timestamp ON system_logs(timestamp DESC);
