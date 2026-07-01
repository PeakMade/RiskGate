# RiskGate 🛡️

**Impossible Login Detection & MFA Fraud Prevention**

A Flask application demonstrating advanced security techniques for detecting impossible travel and preventing fraudulent MFA creation during account takeover attempts.

<!-- Trigger deployment -->

---

## 🎯 Purpose

This application addresses a critical security gap: **attackers who steal passwords and successfully pass MFA can still hijack accounts by adding their own MFA methods**. RiskGate prevents this attack vector by:

1. **Detecting impossible logins** using geographic and temporal analysis
2. **Assigning risk scores** to login sessions based on multiple factors
3. **Blocking risky sessions** from creating, modifying, or removing MFA
4. **Logging all security events** for audit trails and threat analysis

---

## 🚨 The Attack Chain RiskGate Prevents

**Without RiskGate:**
1. Attacker steals user password (phishing, breach, etc.)
2. Attacker logs in from strange location (impossible travel)
3. Attacker successfully passes or tricks existing MFA
4. ⚠️ **Attacker adds their own MFA device**
5. ⚠️ **Attacker removes or disables original MFA**
6. User is permanently locked out

**With RiskGate:**
1. Attacker steals user password
2. Attacker logs in from strange location
3. ✅ **System detects impossible travel**
4. ✅ **Session is marked as high-risk**
5. Attacker successfully passes or tricks existing MFA
6. ✅ **Attacker tries to add their own MFA**
7. ⛔ **System blocks MFA creation due to risky session**
8. ✅ **Security alert is created**
9. ✅ **All actions are logged**
10. User is notified and can secure their account

---

## 🔍 Key Concepts

### What is Impossible Login?

An **impossible login** occurs when a user appears to log in from two locations that are physically too far apart, given the time between logins.

**Example:**
- User logs in from New York at 10:00 AM
- User logs in from Tokyo at 10:30 AM
- Distance: ~6,700 miles
- Time elapsed: 0.5 hours
- **Required travel speed: 13,400 mph** 🚀

Since commercial aircraft travel at ~550 mph and the fastest jets reach ~2,200 mph, this is physically impossible. This indicates either:
- Account compromise (most likely)
- VPN/proxy switching (false positive)
- IP geolocation error (false positive)

### Why Distance Alone Isn't Enough

Simply measuring distance between logins isn't sufficient:
- Tokyo to Sydney is ~4,800 miles (far)
- If 10 hours passed between logins, this is **legitimate** (~480 mph travel speed)
- If 30 minutes passed, this is **impossible** (~9,600 mph required)

**RiskGate calculates required travel speed:**
```python
required_speed = distance_miles / hours_between_logins
```

### Risk Score Thresholds

RiskGate assigns numeric risk scores based on suspicious factors:

| Risk Score | Level    | Description                                    |
|-----------|----------|------------------------------------------------|
| 0-29      | Low      | Normal login, minimal concerns                 |
| 30-59     | Medium   | Some risk factors present, monitor closely     |
| 60-89     | High     | Multiple risk factors, block MFA changes       |
| 90+       | Critical | Extreme risk, possible account takeover        |

**Risk Score Components:**
- New device: +20
- New country: +20
- Impossible travel (500+ mph): +40
- Extreme travel (1000+ mph): +30
- MFA prompt spam: +30

### Why MFA Success Doesn't Mean Safe

**Critical insight:** Just because an attacker successfully completes MFA doesn't mean the session is safe.

**How attackers bypass MFA:**
- Social engineering ("verify this code to prevent lockout")
- MFA fatigue attacks (spam push notifications until user approves)
- Session hijacking after legitimate MFA
- Malware on user's device
- SIM swapping for SMS-based MFA
- Phishing sites that relay MFA codes in real-time

**RiskGate's approach:**
- MFA verification is required but not sufficient
- Login risk score persists even after successful MFA
- Risky sessions have limited privileges
- Account-control actions (like MFA changes) require trusted sessions

---

## 🏗️ Project Structure

```
impossible_mfa_guard/
├── app/
│   ├── __init__.py              # Application factory
│   ├── models.py                # Database models
│   ├── routes.py                # Web routes and views
│   ├── auth_hooks.py            # Authentication lifecycle hooks
│   ├── risk.py                  # Risk calculation and impossible travel detection
│   ├── security_events.py       # Security event logging
│   ├── mfa_protection.py        # MFA creation/removal protection
│   └── utils.py                 # Utility functions (IP, geolocation, etc.)
├── migrations/                  # Database migration files (auto-generated)
├── config.py                    # Configuration settings
├── run.py                       # Application entry point
├── requirements.txt             # Python dependencies
└── README.md                    # This file
```

---

## 📊 Database Models

### User
Represents application users with authentication credentials and role-based access.

**Fields:**
- `id` - Primary key
- `email` - Unique email address
- `password_hash` - Bcrypt hashed password
- `role` - User role (user, admin, finance, security)
- `created_at` - Account creation timestamp

### LoginEvent
Records every login attempt with location, device, and risk information.

**Fields:**
- `id` - Primary key
- `user_id` - Foreign key to User
- `timestamp` - When the login occurred
- `success` - Whether login was successful
- `ip_address` - Client IP address
- `country` - Geographic country
- `city` - Geographic city
- `latitude` - Geographic latitude
- `longitude` - Geographic longitude
- `user_agent` - Browser user agent string
- `browser` - Parsed browser name/version
- `operating_system` - Parsed OS name/version
- `device_fingerprint` - Unique device identifier
- `mfa_required` - Whether MFA was required
- `mfa_success` - Whether MFA succeeded
- `risk_score` - Calculated risk score (0-100+)
- `risk_reason` - Comma-separated risk factors

### MfaMethod
Represents a multi-factor authentication method configured by a user.

**Fields:**
- `id` - Primary key
- `user_id` - Foreign key to User
- `method_type` - Type of MFA (totp, sms, hardware_key, backup_codes)
- `status` - Current status (pending, restricted, active, disabled, removed)
- `created_at` - When method was added
- `activated_at` - When method became active
- `trusted_after` - When method becomes fully trusted (24-hour waiting period)
- `created_from_ip` - IP address where method was created
- `created_from_device` - Device fingerprint where method was created

### MfaEvent
Audit log of all MFA-related events.

**Fields:**
- `id` - Primary key
- `user_id` - Foreign key to User
- `mfa_method_id` - Foreign key to MfaMethod (nullable)
- `event_type` - Type of event (create, remove, verify, block, reset)
- `timestamp` - When event occurred
- `ip_address` - Client IP address
- `country` - Geographic country
- `city` - Geographic city
- `device_fingerprint` - Device identifier
- `session_risk_score` - Session risk score at time of event
- `blocked` - Whether the action was blocked
- `reason` - Explanation of event or block reason

### SecurityAlert
High-level security alerts requiring attention.

**Fields:**
- `id` - Primary key
- `user_id` - Foreign key to User
- `alert_type` - Type of alert (impossible_travel, blocked_mfa_creation, etc.)
- `severity` - Severity level (low, medium, high, critical)
- `reason` - Detailed explanation
- `created_at` - When alert was created
- `status` - Alert status (active, acknowledged, resolved, false_positive)

### TrustedDevice
Tracks devices explicitly trusted by users.

**Fields:**
- `id` - Primary key
- `user_id` - Foreign key to User
- `device_fingerprint` - Unique device identifier
- `first_seen_at` - First time device was seen
- `last_seen_at` - Most recent time device was seen
- `trusted` - Whether device is explicitly trusted

---

## 🔐 Security Rules

### Impossible Travel Detection

1. **On every successful login:**
   - Create a `LoginEvent` record
   - Collect timestamp, IP, user agent, device fingerprint, geolocation
   - Compare to user's previous successful login
   - Calculate distance in miles
   - Calculate time difference in hours
   - Calculate required travel speed

2. **Risk assessment:**
   - If speed > 500 mph: Add +40 risk, flag as impossible_travel
   - If speed > 1000 mph: Add +30 additional risk, flag as extreme_impossible_travel
   - Create `SecurityAlert` with appropriate severity

3. **Store risk in session:**
   - Session carries risk score and level
   - Used for subsequent authorization checks

### MFA Creation Protection

**Before ANY MFA creation/modification, the system checks:**

1. **Session risk score:**
   - If risk ≥ 60: BLOCK
   - If user is admin/finance/security and risk ≥ 30: BLOCK

2. **Recent impossible travel:**
   - If impossible travel detected in last 24 hours: BLOCK

3. **Active high-security alerts:**
   - If user has active high/critical alerts: BLOCK

4. **If checks pass:**
   - Require password re-entry (placeholder)
   - Require existing MFA verification (placeholder)
   - Create MFA method with `status="pending"`
   - Set `trusted_after` to 24 hours in future
   - Notify existing trusted channels (placeholder)
   - Log `MfaEvent`

5. **If checks fail:**
   - Log `MfaEvent` with `blocked=True`
   - Create `SecurityAlert`
   - Return HTTP 403 with clear error message

### MFA Removal Protection

**Before MFA removal:**

1. Run all MFA creation checks (trusted session required)
2. Verify it's not the last active MFA method
3. Verify MFA method is fully trusted (24 hours have passed)
4. Only then allow removal

---

## 🚀 Installation & Setup

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Step-by-Step Setup

1. **Clone or download this repository**
   ```bash
   cd path/to/RiskGate
   ```

2. **Create a virtual environment (recommended)**
   ```bash
   python -m venv venv
   
   # Windows
   venv\Scripts\activate
   
   # macOS/Linux
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Initialize the database**
   ```bash
   flask db init
   flask db migrate -m "Initial migration"
   flask db upgrade
   ```

5. **Run the application**
   ```bash
   python run.py
   ```

6. **Open your browser**
   ```
   http://localhost:5000
   ```

---

## 🧪 Testing the Application

### Scenario 1: Normal Login (Low Risk)

1. Go to the Login Demo page
2. Login from "New York, USA"
3. **Expected:** Risk score 20-40 (new device, possibly new country)
4. Try to add MFA → **Should succeed**

### Scenario 2: Impossible Travel (High Risk)

1. Login from "New York, USA"
2. Immediately login from "Tokyo, Japan"
3. **Expected:** Risk score 60+ (impossible travel + new device + new country)
4. Check Security Alerts → Should see "impossible_travel" alert
5. Try to add MFA → **Should be BLOCKED**

### Scenario 3: Extreme Impossible Travel (Critical Risk)

1. Login from "New York, USA"
2. Wait 10 minutes
3. Login from "Sydney, Australia"
4. **Expected:** Risk score 90+ (extreme impossible travel)
5. Check Security Alerts → Should see "extreme_impossible_travel" alert
6. Try to add MFA → **Should be BLOCKED**

### Scenario 4: Legitimate Travel (Medium Risk)

1. Login from "New York, USA"
2. Wait several hours (or manually adjust timestamps)
3. Login from "San Francisco, USA"
4. **Expected:** Low to medium risk (same country, reasonable travel time)
5. Try to add MFA → **Should succeed**

### Scenario 5: MFA Removal Protection

1. Add an MFA method
2. Immediately try to remove it
3. **Expected:** Blocked (must wait 24 hours for trust period)

---

## 🔧 Configuration

Edit `config.py` to customize security parameters:

```python
# Risk score thresholds
RISK_THRESHOLD_LOW = 29          # 0-29: low risk
RISK_THRESHOLD_MEDIUM = 59       # 30-59: medium risk
RISK_THRESHOLD_HIGH = 89         # 60-89: high risk (blocks MFA)
                                 # 90+: critical risk

# Risk score values
RISK_SCORE_NEW_DEVICE = 20
RISK_SCORE_NEW_COUNTRY = 20
RISK_SCORE_IMPOSSIBLE_TRAVEL = 40
RISK_SCORE_EXTREME_TRAVEL = 30

# Travel speed thresholds (mph)
TRAVEL_SPEED_IMPOSSIBLE = 500    # Flag as impossible
TRAVEL_SPEED_EXTREME = 1000      # Flag as extreme

# MFA trust period
MFA_TRUST_PERIOD_HOURS = 24      # New MFA waiting period
```

---

## 🌐 Production Considerations

This is a **demonstration application**. For production use, implement:

### 1. Real IP Geolocation
Replace the placeholder in `app/utils.py:get_geolocation()`:
- MaxMind GeoIP2
- IP2Location
- ipapi.co
- ipinfo.io

### 2. Better Device Fingerprinting
Implement client-side fingerprinting:
- FingerprintJS
- Canvas/WebGL fingerprinting
- Font enumeration
- Audio context fingerprinting

### 3. Real Notification System
Replace placeholders in `app/utils.py`:
- Email alerts (SendGrid, AWS SES, Mailgun)
- SMS notifications (Twilio, AWS SNS)
- Push notifications (Firebase, OneSignal)
- In-app notification system

### 4. Actual Password Re-entry
Implement secure password verification flow:
- Separate password confirmation endpoint
- Rate limiting on verification attempts
- Session token for post-verification actions

### 5. Real MFA Implementation
Add actual MFA verification:
- TOTP (pyotp, Google Authenticator)
- SMS codes (Twilio)
- WebAuthn/FIDO2 (py_webauthn)
- Backup codes generation and validation

### 6. Additional Security Measures
- Rate limiting on login attempts
- CAPTCHA after failed attempts
- Session token rotation
- Database encryption at rest
- HTTPS/TLS in production
- Security headers (CSP, HSTS, etc.)
- Logging and monitoring integration
- SIEM integration for alerts

### 7. Database
- Switch from SQLite to PostgreSQL or MySQL for production
- Implement connection pooling
- Set up database backups
- Add database indices for performance

---

## 📚 API Reference

### Core Functions

#### risk.py

```python
distance_miles(lat1, lon1, lat2, lon2)
# Calculate distance between two coordinates in miles

detect_impossible_travel(previous_login, current_login)
# Detect if travel between logins is impossible
# Returns: dict with is_impossible, is_extreme, distance, speed, etc.

calculate_login_risk(user, current_login_data)
# Calculate comprehensive risk score for a login
# Returns: dict with risk_score, risk_reasons, risk_level

has_recent_impossible_travel(user_id, hours=24)
# Check if user has recent impossible travel
# Returns: Boolean

get_risk_level(risk_score)
# Convert numeric risk score to level (low/medium/high/critical)
# Returns: String
```

#### mfa_protection.py

```python
can_create_mfa(user, session_risk_score)
# Check if session is safe enough to create MFA
# Returns: dict with allowed, reason, requires_additional_auth

require_trusted_session_for_mfa_change(user)
# Gate function that blocks MFA changes from risky sessions
# Returns: dict with allowed, reason (logs and alerts if blocked)

can_remove_mfa(user, mfa_method)
# Check if MFA method can be removed
# Returns: dict with allowed, reason

is_mfa_method_fully_trusted(mfa_method)
# Check if MFA has passed 24-hour trust period
# Returns: Boolean
```

#### security_events.py

```python
create_login_event(user, success, additional_data=None)
# Create a LoginEvent record
# Returns: LoginEvent object

update_login_event_risk(login_event, risk_score, reasons)
# Update login event with risk information
# Returns: Updated LoginEvent

log_mfa_event(user_id, event_type, blocked, reason, mfa_method_id=None)
# Log an MFA-related event
# Returns: MfaEvent object

create_security_alert(user_id, alert_type, severity, reason)
# Create a high-level security alert
# Returns: SecurityAlert object

has_active_high_security_alert(user_id)
# Check for active high/critical alerts
# Returns: Boolean
```

---

## 🤝 Contributing

This is a demonstration project for educational purposes. Feel free to:
- Fork and extend
- Adapt for your own applications
- Use as a learning resource
- Submit improvements or bug fixes

---

## 📝 License

MIT License - Free to use for any purpose.

---

## ⚠️ Disclaimer

This is a **demonstration application** for educational purposes. It uses placeholder implementations for geolocation, notifications, and actual MFA verification. **Do not deploy directly to production without implementing proper security measures.**

---

## 🎓 Learning Resources

### Understanding Impossible Travel
- [MITRE ATT&CK: Impossible Travel](https://attack.mitre.org/)
- Analyzing login patterns for threat detection
- Geographic and temporal correlation in security

### Account Takeover Prevention
- Multi-factor authentication best practices
- Session risk scoring
- Behavioral biometrics
- Continuous authentication

### Security Monitoring
- Security Information and Event Management (SIEM)
- Audit logging best practices
- Incident response workflows

---

## 📧 Questions?

This starter application demonstrates core concepts of:
- Impossible login detection
- Risk-based authentication
- MFA fraud prevention
- Security event logging
- Threat detection and alerting

For a production implementation, consult with security professionals and follow industry best practices for your specific use case.

---

**Built with ❤️ and 🔐 to demonstrate advanced authentication security techniques.**
# RiskGate
