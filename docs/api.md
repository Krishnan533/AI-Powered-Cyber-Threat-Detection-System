# REST APIs Reference Specifications

The system utilizes JSON REST API endpoints to exchange parameters and telemetry data between the frontend templates and the Flask backend.

---

## 1. Authentication APIs (`backend/routes/auth.py`)

### user Login
- **Endpoint**: `POST /api/auth/login`
- **Rate Limit**: Max 5 requests per minute per IP source.
- **Request Body**:
  ```json
  {
    "username": "admin",
    "password": "AdminPass123!"
  }
  {
    "success": true,
    "message": "Login successful.",
    "user": {
      "id": 1,
      "username": "admin",
      "role": "Admin",
      "created_at": "2026-07-05T07:20:00"
    }
  }
  ```

### user Logout
- **Endpoint**: `POST /api/auth/logout`
- **Security**: Requires a valid `X-CSRF-Token` session header.
- **Response**:
  ```json
  {
    "success": true,
    "message": "Logged out successfully."
  }
  ```

### user Session Profile
- **Endpoint**: `GET /api/auth/profile`
- **Response**:
  ```json
  {
    "authenticated": true,
    "user": {
      "id": 1,
      "username": "admin",
      "role": "Admin"
    }
  }
  ```

---

## 2. Dashboard Telemetry APIs (`backend/routes/dashboard.py`)

### Summary Telemetry Counts
- **Endpoint**: `GET /api/dashboard/stats`
- **Authorization**: Required (Viewer, Analyst, Admin)
- **Response**:
  ```json
  {
    "packets": {
      "total": 102540,
      "last_hour": 3400,
      "protocols": { "TCP": 85000, "UDP": 15000, "ICMP": 2540 }
    },
    "threats": {
      "total": 24,
      "active": 4,
      "resolved": 20,
      "severities": { "Low": 10, "Medium": 8, "High": 4, "Critical": 2 }
    },
    "blocked_ips": {
      "active_count": 3
    }
  }
  ```

### Interactive Timeline
- **Endpoint**: `GET /api/dashboard/timeline`
- **Response**: A list of binned logs in 5-minute segments for the past 6 hours:
  ```json
  [
    {
      "timestamp": "2026-07-05 01:25",
      "packets": 420,
      "threats": 0
    },
    {
      "timestamp": "2026-07-05 01:30",
      "packets": 510,
      "threats": 1
    }
  ]
  ```

### Spawn Model Retrain Process
- **Endpoint**: `POST /api/dashboard/retrain`
- **Authorization**: Requires `Admin` role. Enforces CSRF token check.
- **Response**:
  ```json
  {
    "success": true,
    "message": "Model training task scheduled in background."
  }
  ```

---

## 3. Threat Alerts APIs (`backend/routes/threats.py`)

### Query Paginated Threats
- **Endpoint**: `GET /api/threats`
- **Parameters**:
  - `page` (int, default: 1)
  - `limit` (int, default: 10)
  - `search` (string keyword search)
  - `severity` (Low, Medium, High, Critical)
  - `status` (Active, Resolved, False Positive)
- **Response**:
  ```json
  {
    "threats": [
      {
        "id": 14,
        "type": "Port Scan",
        "source_ip": "203.0.113.45",
        "destination_ip": "192.168.1.50",
        "severity_score": 8.0,
        "severity_level": "High",
        "timestamp": "2026-07-05T07:22:15",
        "status": "Active",
        "description": "Port scanning pattern detected: scanned 20 unique ports.",
        "ai_detected": false
      }
    ],
    "total": 1,
    "pages": 1,
    "current_page": 1
  }
  ```

### Update Threat Status
- **Endpoint**: `POST /api/threats/<threat_id>/status`
- **Authorization**: Requires `Admin` or `Analyst` roles.
- **Request Body**:
  ```json
  { "status": "Resolved" }
  ```
- **Response**:
  ```json
  {
    "success": true,
    "message": "Threat status updated successfully.",
    "threat": { ... }
  }
  ```

### Export Data Report
- **Endpoint**: `GET /api/threats/export`
- **Parameters**: `format` (csv, pdf), `severity` (filter), `status` (filter).
- **Response**: Returns binary stream attachments (`threat_report.csv` or `threat_report.pdf`).

---

## 4. Blocked IP Management APIs (`backend/routes/blocked_ips.py`)

### Query Active Block rules
- **Endpoint**: `GET /api/blocked-ips`
- **Response**:
  ```json
  {
    "blocked_ips": [
      {
        "id": 3,
        "ip_address": "203.0.113.45",
        "reason": "Port scan target defense rule.",
        "blocked_at": "2026-07-05T07:22:15",
        "expires_at": "2026-07-06T07:22:15",
        "blocked_by": "System Daemon",
        "is_expired": false
      }
    ],
    "total": 1,
    "pages": 1,
    "current_page": 1
  }
  ```

### Manually Block Host IP
- **Endpoint**: `POST /api/blocked-ips`
- **Authorization**: Requires `Admin` or `Analyst`.
- **Request Body**:
  ```json
  {
    "ip_address": "198.51.100.22",
    "reason": "Host scan command center block",
    "duration_hours": 24
  }
  ```
- **Response**:
  ```json
  {
    "success": true,
    "message": "IP Address blocked successfully.",
    "blocked_ip": { ... }
  }
  ```

### Remove Block Rule
- **Endpoint**: `DELETE /api/blocked-ips/<ip_id>`
- **Authorization**: Requires `Admin` role.
- **Response**:
  ```json
  {
    "success": true,
    "message": "IP Address 198.51.100.22 unblocked successfully."
  }
  ```
