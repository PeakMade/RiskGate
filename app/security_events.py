"""
Security event logging and alert management.
Tracks login events, MFA events, and security alerts.
"""
from datetime import datetime, timedelta
from flask import request, session
from app.models import LoginEvent, MfaEvent, SecurityAlert
from app import db
from app.utils import get_ip_address, get_geolocation, get_device_fingerprint


def create_login_event(user, success, additional_data=None):
    """
    Create a LoginEvent record for a login attempt.
    Captures location, device, and timing information.
    
    Args:
        user: User object
        success: Boolean indicating if login was successful
        additional_data: Optional dict with extra login data
    
    Returns:
        LoginEvent object
    """
    # Get IP address and geolocation
    ip_address = get_ip_address(request)
    
    # Check if this is a simulated login with a specific location
    if 'simulated_location' in session:
        geo_data = session['simulated_location']
        print(f"\n*** USING SIMULATED LOCATION: {geo_data['name']} ***\n")
    else:
        geo_data = get_geolocation(ip_address)
    
    # Get device fingerprint and parse user agent
    device_fingerprint = get_device_fingerprint(request)
    from app.utils import parse_user_agent
    ua_data = parse_user_agent(request.headers.get('User-Agent', ''))
    
    # Merge any additional data
    if additional_data is None:
        additional_data = {}
    
    # Create the login event
    login_event = LoginEvent(
        user_id=user.id,
        timestamp=datetime.utcnow(),
        success=success,
        ip_address=ip_address,
        country=geo_data.get('country'),
        city=geo_data.get('city'),
        latitude=geo_data.get('latitude'),
        longitude=geo_data.get('longitude'),
        user_agent=request.headers.get('User-Agent', ''),
        browser=ua_data.get('browser'),
        operating_system=ua_data.get('os'),
        device_fingerprint=device_fingerprint,
        mfa_required=additional_data.get('mfa_required', False),
        mfa_success=additional_data.get('mfa_success'),
        risk_score=0,  # Will be updated by update_login_event_risk
        risk_reason=''
    )
    
    db.session.add(login_event)
    db.session.commit()
    
    return login_event


def update_login_event_risk(login_event, risk_score, reasons):
    """
    Update a LoginEvent with calculated risk information.
    
    Args:
        login_event: LoginEvent object to update
        risk_score: Integer risk score
        reasons: List of risk reason strings
    
    Returns:
        Updated LoginEvent object
    """
    login_event.risk_score = risk_score
    login_event.risk_reason = ','.join(reasons) if reasons else ''
    db.session.commit()
    
    return login_event


def log_mfa_event(user_id, event_type, blocked, reason, mfa_method_id=None):
    """
    Log an MFA-related event (creation, removal, verification, block).
    
    Args:
        user_id: User ID
        event_type: String type of event (create, remove, verify, block, etc.)
        blocked: Boolean indicating if action was blocked
        reason: String explanation
        mfa_method_id: Optional MFA method ID
    
    Returns:
        MfaEvent object
    """
    # Get current location and device information
    ip_address = get_ip_address(request)
    geo_data = get_geolocation(ip_address)
    device_fingerprint = get_device_fingerprint(request)
    
    # Get current session risk score if available
    from flask import session
    session_risk_score = session.get('risk_score', 0)
    
    # Create the MFA event
    mfa_event = MfaEvent(
        user_id=user_id,
        mfa_method_id=mfa_method_id,
        event_type=event_type,
        timestamp=datetime.utcnow(),
        ip_address=ip_address,
        country=geo_data.get('country'),
        city=geo_data.get('city'),
        device_fingerprint=device_fingerprint,
        session_risk_score=session_risk_score,
        blocked=blocked,
        reason=reason
    )
    
    db.session.add(mfa_event)
    db.session.commit()
    
    return mfa_event


def create_security_alert(user_id, alert_type, severity, reason):
    """
    Create a high-level security alert.
    Used for impossible travel, blocked MFA changes, and other critical events.
    
    Args:
        user_id: User ID
        alert_type: String type of alert (impossible_travel, blocked_mfa_creation, etc.)
        severity: String severity level (low, medium, high, critical)
        reason: String explanation of the alert
    
    Returns:
        SecurityAlert object
    """
    alert = SecurityAlert(
        user_id=user_id,
        alert_type=alert_type,
        severity=severity,
        reason=reason,
        created_at=datetime.utcnow(),
        status='active'
    )
    
    db.session.add(alert)
    db.session.commit()
    
    return alert


def has_active_high_security_alert(user_id):
    """
    Check if user has any active high or critical severity alerts.
    
    Args:
        user_id: User ID to check
    
    Returns:
        Boolean indicating if high-severity active alerts exist
    """
    alert = SecurityAlert.query.filter(
        SecurityAlert.user_id == user_id,
        SecurityAlert.status == 'active',
        SecurityAlert.severity.in_(['high', 'critical'])
    ).first()
    
    return alert is not None


def get_previous_successful_login(user_id):
    """
    Get the most recent successful login for a user.
    Excludes the current login by skipping the first result.
    Used for impossible travel detection.
    
    Args:
        user_id: User ID
    
    Returns:
        LoginEvent object or None
    """
    # Skip the first (current) login and get the second most recent
    all_logins = LoginEvent.query.filter_by(
        user_id=user_id,
        success=True
    ).order_by(LoginEvent.timestamp.desc()).limit(2).all()
    
    # Return the second login if it exists
    return all_logins[1] if len(all_logins) >= 2 else None


def get_recent_security_alerts(user_id, hours=24, status='active'):
    """
    Get recent security alerts for a user.
    
    Args:
        user_id: User ID
        hours: How many hours back to look
        status: Alert status filter (default 'active')
    
    Returns:
        List of SecurityAlert objects
    """
    cutoff_time = datetime.utcnow() - timedelta(hours=hours)
    
    query = SecurityAlert.query.filter(
        SecurityAlert.user_id == user_id,
        SecurityAlert.created_at >= cutoff_time
    )
    
    if status:
        query = query.filter(SecurityAlert.status == status)
    
    return query.order_by(SecurityAlert.created_at.desc()).all()


def get_recent_login_events(user_id, limit=10):
    """
    Get recent login events for a user.
    
    Args:
        user_id: User ID
        limit: Maximum number of events to return
    
    Returns:
        List of LoginEvent objects
    """
    return LoginEvent.query.filter_by(
        user_id=user_id
    ).order_by(LoginEvent.timestamp.desc()).limit(limit).all()


def get_recent_mfa_events(user_id, limit=10):
    """
    Get recent MFA events for a user.
    
    Args:
        user_id: User ID
        limit: Maximum number of events to return
    
    Returns:
        List of MfaEvent objects
    """
    return MfaEvent.query.filter_by(
        user_id=user_id
    ).order_by(MfaEvent.timestamp.desc()).limit(limit).all()


def acknowledge_alert(alert_id):
    """
    Mark a security alert as acknowledged.
    
    Args:
        alert_id: SecurityAlert ID
    
    Returns:
        Boolean indicating success
    """
    alert = SecurityAlert.query.get(alert_id)
    if alert:
        alert.status = 'acknowledged'
        db.session.commit()
        return True
    return False


def resolve_alert(alert_id):
    """
    Mark a security alert as resolved.
    
    Args:
        alert_id: SecurityAlert ID
    
    Returns:
        Boolean indicating success
    """
    alert = SecurityAlert.query.get(alert_id)
    if alert:
        alert.status = 'resolved'
        db.session.commit()
        return True
    return False


def mark_alert_false_positive(alert_id):
    """
    Mark a security alert as a false positive.
    
    Args:
        alert_id: SecurityAlert ID
    
    Returns:
        Boolean indicating success
    """
    alert = SecurityAlert.query.get(alert_id)
    if alert:
        alert.status = 'false_positive'
        db.session.commit()
        return True
    return False
