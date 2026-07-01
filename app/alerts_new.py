"""
Security alert creation and management for RiskGate.

Creates security alerts when suspicious patterns are detected:
- Impossible login
- Extreme impossible login
- MFA change after risky login
- Possible MFA takeover
- Temporary Access Pass created after risk event

Prevents duplicate alerts for the same event combinations.
"""
from datetime import datetime
from flask import current_app
from app import db
from app.models_new import EntraSecurityAlert


def check_duplicate_alert(entra_user_id, alert_type, related_signin_id=None, related_mfa_id=None, hours=24):
    """
    Check if a similar alert already exists to avoid duplicates.
    
    Args:
        entra_user_id: Azure AD object ID
        alert_type: Type of alert
        related_signin_id: ID of related sign-in event
        related_mfa_id: ID of related MFA event
        hours: Time window to check for duplicates (default 24)
    
    Returns:
        EntraSecurityAlert object if duplicate exists, None otherwise
    """
    from datetime import timedelta
    lookback_time = datetime.utcnow() - timedelta(hours=hours)
    
    # Build query
    query = EntraSecurityAlert.query.filter(
        EntraSecurityAlert.entra_user_id == entra_user_id,
        EntraSecurityAlert.alert_type == alert_type,
        EntraSecurityAlert.created_at >= lookback_time
    )
    
    # Add related event filters if provided
    if related_signin_id:
        query = query.filter(EntraSecurityAlert.related_signin_event_id == related_signin_id)
    if related_mfa_id:
        query = query.filter(EntraSecurityAlert.related_mfa_event_id == related_mfa_id)
    
    return query.first()


def create_security_alert(entra_user_id, user_principal_name, alert_type, severity, reason,
                         related_signin_event_id=None, related_mfa_event_id=None):
    """
    Create a security alert.
    
    Args:
        entra_user_id: Azure AD object ID
        user_principal_name: user@domain.com
        alert_type: Type of alert (impossible_login, mfa_change_after_risky_login, etc.)
        severity: Severity level (low, medium, high, critical)
        reason: Human-readable explanation
        related_signin_event_id: Optional ID of related EntraSignInEvent
        related_mfa_event_id: Optional ID of related EntraMfaEvent
    
    Returns:
        EntraSecurityAlert object
    """
    # Check for duplicate
    existing = check_duplicate_alert(
        entra_user_id, alert_type,
        related_signin_event_id, related_mfa_event_id
    )
    
    if existing:
        current_app.logger.debug(
            f"Duplicate alert {alert_type} for {user_principal_name} already exists, skipping"
        )
        return existing
    
    # Create new alert
    alert = EntraSecurityAlert(
        entra_user_id=entra_user_id,
        user_principal_name=user_principal_name,
        alert_type=alert_type,
        severity=severity,
        reason=reason,
        status='open',
        related_signin_event_id=related_signin_event_id,
        related_mfa_event_id=related_mfa_event_id
    )
    
    db.session.add(alert)
    
    current_app.logger.warning(
        f"ALERT CREATED [{severity.upper()}] {alert_type}: {user_principal_name} - {reason}"
    )
    
    return alert


def create_impossible_login_alert(signin_event, impossible_travel_data):
    """
    Create an alert for impossible login (travel speed > 500 mph).
    
    Args:
        signin_event: EntraSignInEvent object
        impossible_travel_data: Dict from detect_impossible_travel()
    
    Returns:
        EntraSecurityAlert object or None
    """
    if not impossible_travel_data['is_impossible']:
        return None
    
    distance = impossible_travel_data['distance_miles']
    hours = impossible_travel_data['hours_between']
    speed = impossible_travel_data['required_speed_mph']
    
    reason = (
        f"Impossible login detected: User appeared to travel {distance:.0f} miles "
        f"in {hours:.2f} hours (required speed: {speed:.0f} mph). "
        f"This may indicate account compromise, though VPN/proxy usage can cause false positives."
    )
    
    return create_security_alert(
        entra_user_id=signin_event.entra_user_id,
        user_principal_name=signin_event.user_principal_name,
        alert_type='impossible_login',
        severity='high',
        reason=reason,
        related_signin_event_id=signin_event.id
    )


def create_extreme_impossible_login_alert(signin_event, impossible_travel_data):
    """
    Create an alert for extreme impossible login (travel speed > 1000 mph).
    
    Args:
        signin_event: EntraSignInEvent object
        impossible_travel_data: Dict from detect_impossible_travel()
    
    Returns:
        EntraSecurityAlert object or None
    """
    if not impossible_travel_data['is_extreme']:
        return None
    
    distance = impossible_travel_data['distance_miles']
    hours = impossible_travel_data['hours_between']
    speed = impossible_travel_data['required_speed_mph']
    
    reason = (
        f"EXTREME impossible login detected: User appeared to travel {distance:.0f} miles "
        f"in {hours:.2f} hours (required speed: {speed:.0f} mph). "
        f"This requires faster-than-aircraft travel and strongly suggests account compromise or VPN usage."
    )
    
    return create_security_alert(
        entra_user_id=signin_event.entra_user_id,
        user_principal_name=signin_event.user_principal_name,
        alert_type='extreme_impossible_login',
        severity='critical',
        reason=reason,
        related_signin_event_id=signin_event.id
    )


def create_mfa_change_after_risky_login_alert(mfa_event, correlation_data):
    """
    Create an alert for MFA method change after risky sign-in.
    
    This is a strong indicator of account takeover:
    1. Attacker logs in (detected as risky)
    2. Attacker immediately adds their own MFA method for persistence
    
    Args:
        mfa_event: EntraMfaEvent object
        correlation_data: Dict from correlate_mfa_change_after_risky_login()
    
    Returns:
        EntraSecurityAlert object or None
    """
    if not correlation_data['has_correlation']:
        return None
    
    related_signin = correlation_data['related_signin']
    time_diff = correlation_data['time_difference_minutes']
    signin_risk_score = correlation_data['signin_risk_score']
    
    reason = (
        f"CRITICAL: MFA method change detected {time_diff:.0f} minutes after risky sign-in. "
        f"Activity: {mfa_event.activity_name}. "
        f"Sign-in risk score: {signin_risk_score}. "
        f"This pattern strongly suggests account takeover where the attacker is adding "
        f"their own MFA method for persistent access."
    )
    
    return create_security_alert(
        entra_user_id=mfa_event.entra_user_id,
        user_principal_name=mfa_event.user_principal_name,
        alert_type='mfa_change_after_risky_login',
        severity='critical',
        reason=reason,
        related_signin_event_id=related_signin.id if related_signin else None,
        related_mfa_event_id=mfa_event.id
    )


def create_possible_mfa_takeover_alert(added_event, removed_event, time_between_minutes):
    """
    Create an alert for possible MFA takeover pattern.
    
    Pattern: New MFA method added, then another method removed shortly after.
    
    Args:
        added_event: EntraMfaEvent for method addition
        removed_event: EntraMfaEvent for method removal
        time_between_minutes: Time between the two events
    
    Returns:
        EntraSecurityAlert object
    """
    reason = (
        f"Possible MFA takeover detected: "
        f"New authentication method added ({added_event.activity_name}), "
        f"then another method removed ({removed_event.activity_name}) "
        f"{time_between_minutes:.0f} minutes later. "
        f"This pattern suggests an attacker adding their own MFA method "
        f"and removing the victim's method to lock them out."
    )
    
    return create_security_alert(
        entra_user_id=added_event.entra_user_id,
        user_principal_name=added_event.user_principal_name,
        alert_type='possible_mfa_takeover',
        severity='critical',
        reason=reason,
        related_mfa_event_id=added_event.id
    )


def create_tap_after_risk_alert(mfa_event, tap_detection_data):
    """
    Create an alert for Temporary Access Pass created after risky sign-in.
    
    Args:
        mfa_event: EntraMfaEvent for TAP creation
        tap_detection_data: Dict from detect_tap_after_risky_login()
    
    Returns:
        EntraSecurityAlert object or None
    """
    if not tap_detection_data['detected']:
        return None
    
    related_signin = tap_detection_data['related_signin']
    time_diff = tap_detection_data['time_difference_minutes']
    
    reason = (
        f"CRITICAL: Temporary Access Pass created {time_diff:.0f} minutes after risky sign-in. "
        f"TAP allows passwordless authentication and may be used by attacker for persistent access. "
        f"Sign-in risk score: {related_signin.local_risk_score if related_signin else 'unknown'}. "
        f"Investigate immediately."
    )
    
    return create_security_alert(
        entra_user_id=mfa_event.entra_user_id,
        user_principal_name=mfa_event.user_principal_name,
        alert_type='tap_created_after_risk',
        severity='critical',
        reason=reason,
        related_signin_event_id=related_signin.id if related_signin else None,
        related_mfa_event_id=mfa_event.id
    )


def resolve_alert(alert_id, resolved_by, resolution_notes):
    """
    Mark an alert as resolved.
    
    Args:
        alert_id: ID of the alert to resolve
        resolved_by: Who resolved the alert (email/username)
        resolution_notes: Notes about the resolution
    
    Returns:
        EntraSecurityAlert object or None
    """
    alert = EntraSecurityAlert.query.get(alert_id)
    
    if not alert:
        current_app.logger.warning(f"Alert {alert_id} not found")
        return None
    
    alert.status = 'resolved'
    alert.resolved_at = datetime.utcnow()
    alert.resolved_by = resolved_by
    alert.resolution_notes = resolution_notes
    
    db.session.commit()
    
    current_app.logger.info(f"Alert {alert_id} resolved by {resolved_by}")
    
    return alert


def mark_alert_false_positive(alert_id, resolved_by, notes):
    """
    Mark an alert as a false positive.
    
    Args:
        alert_id: ID of the alert
        resolved_by: Who marked it as false positive
        notes: Explanation of why it's a false positive
    
    Returns:
        EntraSecurityAlert object or None
    """
    alert = EntraSecurityAlert.query.get(alert_id)
    
    if not alert:
        current_app.logger.warning(f"Alert {alert_id} not found")
        return None
    
    alert.status = 'false_positive'
    alert.resolved_at = datetime.utcnow()
    alert.resolved_by = resolved_by
    alert.resolution_notes = f"False Positive: {notes}"
    
    db.session.commit()
    
    current_app.logger.info(f"Alert {alert_id} marked as false positive by {resolved_by}")
    
    return alert


def get_open_alerts(limit=100):
    """
    Get all open alerts, ordered by severity and creation time.
    
    Args:
        limit: Maximum number of alerts to return
    
    Returns:
        List of EntraSecurityAlert objects
    """
    # Define severity order for sorting (critical first)
    severity_order = {'critical': 1, 'high': 2, 'medium': 3, 'low': 4}
    
    alerts = EntraSecurityAlert.query.filter_by(status='open').order_by(
        EntraSecurityAlert.created_at.desc()
    ).limit(limit).all()
    
    # Sort by severity then by created_at
    alerts.sort(key=lambda a: (severity_order.get(a.severity, 5), -a.created_at.timestamp()))
    
    return alerts


def get_alerts_for_user(entra_user_id, status=None, limit=50):
    """
    Get alerts for a specific user.
    
    Args:
        entra_user_id: Azure AD object ID
        status: Optional status filter (open, resolved, false_positive)
        limit: Maximum number of alerts to return
    
    Returns:
        List of EntraSecurityAlert objects
    """
    query = EntraSecurityAlert.query.filter_by(entra_user_id=entra_user_id)
    
    if status:
        query = query.filter_by(status=status)
    
    alerts = query.order_by(EntraSecurityAlert.created_at.desc()).limit(limit).all()
    
    return alerts


def get_alert_statistics():
    """
    Get summary statistics about alerts.
    
    Returns:
        Dict with alert counts by status and severity
    """
    from sqlalchemy import func
    
    # Count by status
    status_counts = db.session.query(
        EntraSecurityAlert.status,
        func.count(EntraSecurityAlert.id)
    ).group_by(EntraSecurityAlert.status).all()
    
    # Count by severity (open alerts only)
    severity_counts = db.session.query(
        EntraSecurityAlert.severity,
        func.count(EntraSecurityAlert.id)
    ).filter_by(status='open').group_by(EntraSecurityAlert.severity).all()
    
    # Count by alert type (open alerts only)
    type_counts = db.session.query(
        EntraSecurityAlert.alert_type,
        func.count(EntraSecurityAlert.id)
    ).filter_by(status='open').group_by(EntraSecurityAlert.alert_type).all()
    
    return {
        'by_status': dict(status_counts),
        'by_severity': dict(severity_counts),
        'by_type': dict(type_counts)
    }
