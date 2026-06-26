# RiskGate Architecture Overview

## System Architecture

RiskGate is built using a modular Flask architecture with clear separation of concerns:

```
┌─────────────────────────────────────────────────────────────┐
│                      Web Browser                             │
└───────────────────────┬─────────────────────────────────────┘
                        │ HTTP Requests
                        ▼
┌─────────────────────────────────────────────────────────────┐
│                    Flask Routes (routes.py)                  │
│  • /login-demo  • /mfa/add  • /mfa/remove  • /alerts       │
└───────────────────────┬─────────────────────────────────────┘
                        │
        ┌───────────────┼───────────────┐
        ▼               ▼               ▼
┌──────────────┐ ┌──────────────┐ ┌──────────────┐
│ Auth Hooks   │ │ MFA          │ │ Security     │
│ • Login      │ │ Protection   │ │ Events       │
│ • Risk Store │ │ • Can Create │ │ • Logging    │
│              │ │ • Can Remove │ │ • Alerts     │
└──────┬───────┘ └──────┬───────┘ └──────┬───────┘
       │                │                │
       └────────────────┼────────────────┘
                        ▼
                ┌──────────────┐
                │ Risk Engine  │
                │ • Distance   │
                │ • Travel     │
                │ • Score      │
                └──────┬───────┘
                       │
                       ▼
        ┌──────────────────────────┐
        │ Database Models          │
        │ • User                   │
        │ • LoginEvent             │
        │ • MfaMethod              │
        │ • MfaEvent               │
        │ • SecurityAlert          │
        │ • TrustedDevice          │
        └──────────────────────────┘
```

## Request Flow

### Login Flow

1. **User submits login** → routes.py `/login-demo`
2. **User authenticated** → Flask-Login validates credentials
3. **Auth hook triggered** → auth_hooks.py `after_login_attempt()`
4. **Login event created** → security_events.py `create_login_event()`
5. **Risk calculated** → risk.py `calculate_login_risk()`
   - Get previous login
   - Calculate distance
   - Detect impossible travel
   - Sum risk scores
6. **Risk stored in session** → Flask session
7. **Alerts created if needed** → security_events.py `create_security_alert()`
8. **User sees dashboard** → with risk score displayed

### MFA Creation Flow

1. **User requests to add MFA** → routes.py `/mfa/add`
2. **Session check** → mfa_protection.py `require_trusted_session_for_mfa_change()`
3. **Risk assessment**:
   - Get session risk score
   - Check for impossible travel
   - Check for active alerts
   - Check user role
4. **If blocked**:
   - Log MFA event (blocked)
   - Create security alert
   - Return 403 error
5. **If allowed**:
   - Require password re-entry (placeholder)
   - Require existing MFA (placeholder)
   - Create pending MFA method
   - Set 24-hour trust period
   - Log MFA event (allowed)
   - Notify user (placeholder)

### Risk Calculation Flow

```
Previous Login          Current Login
     │                       │
     │  Location:            │  Location:
     │  New York             │  Tokyo
     │  (40.7, -74.0)        │  (35.7, 139.7)
     │  Time: 10:00          │  Time: 10:30
     └───────────┬───────────┘
                 ▼
         Calculate Distance
         (Haversine Formula)
                 │
                 ▼
            ~6,700 miles
                 │
                 ▼
      Calculate Time Difference
                 │
                 ▼
            0.5 hours
                 │
                 ▼
      Calculate Required Speed
         distance / time
                 │
                 ▼
         13,400 mph (!)
                 │
                 ▼
      Compare to Thresholds
         > 1000 mph?
                 │
                 ▼
              YES ⚠️
                 │
                 ▼
      Add Risk Scores:
      • New device: +20
      • New country: +20
      • Impossible: +40
      • Extreme: +30
                 │
                 ▼
      Total Risk: 110
         (CRITICAL)
                 │
                 ▼
      Create Security Alert
      Store in Session
```

## Module Responsibilities

### app/models.py
**Purpose:** Database schema and ORM models  
**Key Classes:**
- `User` - Authentication and user data
- `LoginEvent` - Login attempt records with location/risk
- `MfaMethod` - MFA configuration with trust status
- `MfaEvent` - Audit log of MFA actions
- `SecurityAlert` - High-level security notifications
- `TrustedDevice` - Known/trusted device tracking

### app/routes.py
**Purpose:** HTTP endpoints and view logic  
**Key Routes:**
- `/login-demo` - Simulate login from different locations
- `/mfa/add` - Attempt to add MFA method
- `/mfa/remove/<id>` - Attempt to remove MFA method
- `/alerts` - View security alerts
- `/login-events` - View login history
- `/mfa-events` - View MFA audit log

### app/auth_hooks.py
**Purpose:** Authentication lifecycle integration  
**Key Functions:**
- `after_login_attempt()` - Post-login security checks
- `clear_session_risk()` - Clean up on logout
- `get_current_session_risk()` - Retrieve session risk data

### app/risk.py
**Purpose:** Risk detection and scoring engine  
**Key Functions:**
- `distance_miles()` - Geographic distance calculation
- `detect_impossible_travel()` - Travel feasibility analysis
- `calculate_login_risk()` - Comprehensive risk scoring
- `has_recent_impossible_travel()` - Historical risk check
- `get_risk_level()` - Risk categorization

### app/mfa_protection.py
**Purpose:** MFA change authorization and protection  
**Key Functions:**
- `can_create_mfa()` - Authorization check for MFA creation
- `require_trusted_session_for_mfa_change()` - Gate function
- `can_remove_mfa()` - Authorization check for MFA removal
- `create_pending_mfa_method()` - Safe MFA creation
- `remove_mfa_method()` - Safe MFA removal

### app/security_events.py
**Purpose:** Security event logging and alerting  
**Key Functions:**
- `create_login_event()` - Log login attempts
- `update_login_event_risk()` - Add risk assessment
- `log_mfa_event()` - Log MFA actions
- `create_security_alert()` - Create high-level alerts
- `has_active_high_security_alert()` - Check alert status

### app/utils.py
**Purpose:** Utility functions for cross-cutting concerns  
**Key Functions:**
- `get_ip_address()` - Extract client IP
- `get_geolocation()` - IP to location (placeholder)
- `get_device_fingerprint()` - Device identification
- `parse_user_agent()` - Browser/OS detection
- `notify_existing_trusted_channels()` - User notification (placeholder)
- `require_password_reentry()` - Password verification (placeholder)
- `require_existing_mfa()` - MFA verification (placeholder)

## Data Flow

### Session Data
```python
session = {
    'risk_score': 80,           # Numeric risk score
    'risk_level': 'high',       # low/medium/high/critical
    'login_event_id': 123,      # Reference to LoginEvent
    'user_id': 456              # Flask-Login manages this
}
```

### Risk Reasons
Risk reasons are stored as comma-separated strings in `LoginEvent.risk_reason`:
- `new_device` - Device fingerprint not seen before
- `new_country` - Country not seen before
- `impossible_travel` - Travel speed > 500 mph
- `extreme_impossible_travel` - Travel speed > 1000 mph
- `mfa_spam` - Multiple failed MFA attempts (future)

## Security Decision Points

### Login Risk Assessment
```
IF new_device THEN risk += 20
IF new_country THEN risk += 20
IF travel_speed > 1000 mph THEN risk += 30
IF travel_speed > 500 mph THEN risk += 40
```

### MFA Creation Authorization
```
BLOCK IF:
  risk_score >= 60 OR
  (is_high_privilege_user AND risk_score >= 30) OR
  has_recent_impossible_travel(24 hours) OR
  has_active_high_security_alert
  
ALLOW IF:
  All checks pass AND
  password_reentry_verified AND
  existing_mfa_verified (if exists)
```

### MFA Removal Authorization
```
BLOCK IF:
  session_not_trusted (same as creation) OR
  is_last_active_mfa OR
  mfa_not_fully_trusted (< 24 hours old)
  
ALLOW IF:
  All checks pass
```

## Configuration Hierarchy

1. **Environment Variables** (highest priority)
   - `SECRET_KEY`
   - `DATABASE_URL`

2. **config.py** (default configuration)
   - Risk thresholds
   - Risk score values
   - Travel speed limits
   - MFA trust period
   - High-privilege roles

3. **Hardcoded Defaults** (fallback)
   - Secret key: 'dev-secret-key-change-in-production'
   - Database: SQLite in project root

## Extension Points

### Adding New Risk Factors
1. Add score constant to `config.py`
2. Add detection logic to `risk.py:calculate_login_risk()`
3. Add reason string to risk_reasons list
4. Update `LoginEvent.risk_reason` documentation

### Adding New MFA Types
1. Add method_type to `MfaMethod` model
2. Implement verification logic in utils.py
3. Add UI in routes.py
4. Update documentation

### Adding Real Geolocation
1. Choose service (MaxMind, ipapi.co, etc.)
2. Sign up and get API key
3. Replace `utils.py:get_geolocation()`
4. Add error handling and fallbacks
5. Consider caching to reduce API calls

### Adding Real Notifications
1. Choose service (SendGrid, Twilio, etc.)
2. Configure credentials
3. Replace `utils.py:notify_existing_trusted_channels()`
4. Add notification templates
5. Add user notification preferences

## Testing Strategy

### Unit Tests (Recommended)
- `test_risk.py` - Distance calculation, risk scoring
- `test_mfa_protection.py` - Authorization logic
- `test_models.py` - Database model methods

### Integration Tests (Recommended)
- `test_login_flow.py` - Full login with risk assessment
- `test_mfa_flow.py` - MFA creation/removal scenarios
- `test_security_alerts.py` - Alert creation and management

### Manual Testing Scenarios
1. Normal login → Low risk
2. VPN switch → Medium risk (new country)
3. Impossible travel → High risk (blocked MFA)
4. Extreme impossible travel → Critical risk
5. MFA creation after impossible travel → Blocked
6. MFA removal immediately after creation → Blocked
7. MFA removal after 24 hours → Allowed

## Performance Considerations

### Database Queries
- Index on `user_id` in all event tables
- Index on `timestamp` for recent event queries
- Index on `device_fingerprint` for device lookups
- Consider archiving old LoginEvent records

### Session Storage
- Risk score stored in Flask session (encrypted cookie)
- Minimal session data (only IDs and scores)
- Session expires after 2 hours (configurable)

### Geolocation
- Implement caching (Redis recommended)
- Use database for known IP ranges
- Fallback to previous known location
- Handle API rate limits

## Monitoring and Alerting

### Metrics to Track (Production)
- Login attempts per minute
- Risk score distribution
- Blocked MFA attempts per day
- Security alerts by type and severity
- Average response time for risk calculation

### Alerts to Configure (Production)
- Spike in high-risk logins
- Multiple blocked MFA attempts for single user
- Critical security alerts
- System errors in risk calculation
- Geolocation API failures

## Security Hardening Checklist

- [ ] Change SECRET_KEY to random value
- [ ] Enable HTTPS/TLS
- [ ] Add rate limiting on login attempts
- [ ] Add CAPTCHA after failed logins
- [ ] Implement real IP geolocation
- [ ] Implement real device fingerprinting
- [ ] Add email/SMS notifications
- [ ] Add real password re-entry
- [ ] Add real MFA verification
- [ ] Add session token rotation
- [ ] Enable database encryption
- [ ] Add security headers (CSP, HSTS, etc.)
- [ ] Set up logging and monitoring
- [ ] Configure SIEM integration
- [ ] Implement data retention policies
- [ ] Add privacy policy compliance
- [ ] Conduct security audit
- [ ] Implement incident response plan

---

**This architecture provides a solid foundation for impossible login detection and MFA fraud prevention. Extend and harden as needed for your specific security requirements.**
