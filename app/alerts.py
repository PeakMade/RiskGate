"""
Security Alert Management for RiskGate.

Creates and manages security alerts based on detected patterns:
- Impossible login detection
- MFA change after risky login
- Possible MFA takeover
- Temporary Access Pass after risk

Alerts are the primary output of RiskGate's correlation engine.
"""
from datetime import datetime
from flask import current_app
from app import db
from app.models_new import EntraSecurityAlert, UserRiskState


def create_security_alert(entra_user_id, user_principal_name, alert_type, severity, 
                         reason, related_signin_event_id=None, related_mfa_event_id=None):
    """
    Create a security alert.
    
    Args:
        entra_user_id: Entra user ID
        user_principal_name: User principal name
        alert_type: Type of alert (impossible_login, mfa_change_after_risky_login, etc.)
        severity: Alert severity (low, medium, high, critical)
        reason: Human-readable explanation
        related_signin_event_id: Optional related sign-in event ID
        related_mfa_event_id: Optional related MFA event ID
    
    Returns:
        SecurityAlert object
    """
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
    
    try:
        db.session.commit()
        current_app.logger.warning(
            f"SECURITY ALERT [{severity.upper()}]: {alert_type} for {user_principal_name}"
        )
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Failed to create security alert: {e}")
    
    return alert


def create_impossible_login_alert(signin_event, travel_details):
    """
    Create alert for impossible login detection.
    
    Args:
        signin_event: EntraSignInEvent object
        travel_details: Dict with impossible travel analysis
    
    Returns:
        SecurityAlert object or None
    """
    # Determine severity based on speed
    if travel_details.get('is_extreme'):
        severity = 'critical'
        alert_type = 'impossible_login_extreme'
    else:
        severity = 'high'
        alert_type = 'impossible_login'
    
    reason = (
        f"Impossible travel detected:\n\n"
        f"User signed in from {signin_event.city or 'Unknown'}, {signin_event.country or 'Unknown'} "
        f"at {signin_event.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}.\n\n"
        f"Required travel speed: {travel_details['required_speed_mph']} mph\n"
        f"Distance: {travel_details['distance_miles']} miles\n"
        f"Time between sign-ins: {travel_details['hours_between']} hours\n\n"
        f"This speed is physically impossible for normal travel.\n\n"
        f"Possible causes:\n"
        f"- VPN or proxy usage\n"
        f"- Mobile carrier routing\n"
        f"- Cloud service distributed locations\n"
        f"- Inaccurate IP geolocation\n"
        f"- Account compromise\n\n"
        f"Investigate recent account activity and MFA changes."
    )
    
    return create_security_alert(
        entra_user_id=signin_event.entra_user_id,
        user_principal_name=signin_event.user_principal_name,
        alert_type=alert_type,
        severity=severity,
        reason=reason,
        related_signin_event_id=signin_event.id
    )


def create_mfa_change_after_risky_login_alert(mfa_event, correlation):
    """
    Create alert for MFA change after risky login.
    This is the most critical alert type - indicates possible account takeover with persistence.
    
    Args:
        mfa_event: EntraMfaEvent object
        correlation: Dict with correlation details from mfa_detection
    
    Returns:
        SecurityAlert object or None
    """
    return create_security_alert(
        entra_user_id=mfa_event.entra_user_id,
        user_principal_name=mfa_event.user_principal_name,
        alert_type='mfa_change_after_risky_login',
        severity=correlation['alert_severity'],
        reason=correlation['correlation_reason'],
        related_signin_event_id=correlation['risky_signin'].id if correlation['risky_signin'] else None,
        related_mfa_event_id=mfa_event.id
    )


def create_possible_mfa_takeover_alert(entra_user_id, user_principal_name, takeover_details):
    """
    Create alert for possible MFA takeover pattern (add then remove).
    
    Args:
        entra_user_id: Entra user ID
        user_principal_name: User principal name
        takeover_details: Dict with takeover detection details
    
    Returns:
        SecurityAlert object or None
    """
    return create_security_alert(
        entra_user_id=entra_user_id,
        user_principal_name=user_principal_name,
        alert_type='possible_mfa_takeover',
        severity='critical',
        reason=takeover_details['reason'],
        related_mfa_event_id=takeover_details['added_event'].id if takeover_details.get('added_event') else None
    )


def create_tap_after_risk_alert(mfa_event, tap_details):
    """
    Create alert for Temporary Access Pass created after risky sign-in.
    
    Args:
        mfa_event: EntraMfaEvent object (TAP creation)
        tap_details: Dict with TAP detection details
    
    Returns:
        SecurityAlert object or None
    """
    return create_security_alert(
        entra_user_id=mfa_event.entra_user_id,
        user_principal_name=mfa_event.user_principal_name,
        alert_type='tap_created_after_risk',
        severity='critical',
        reason=tap_details['reason'],
        related_signin_event_id=tap_details['risky_signin'].id if tap_details.get('risky_signin') else None,
        related_mfa_event_id=mfa_event.id
    )


def get_open_alerts(entra_user_id=None, severity=None, alert_type=None, limit=100):
    """
    Get open security alerts with optional filters.
    
    Args:
        entra_user_id: Optional filter by user
        severity: Optional filter by severity
        alert_type: Optional filter by alert type
        limit: Maximum number of results
    
    Returns:
        List of EntraSecurityAlert objects
    """
    query = EntraSecurityAlert.query.filter_by(status='open')
    
    if entra_user_id:
        query = query.filter_by(entra_user_id=entra_user_id)
    if severity:
        query = query.filter_by(severity=severity)
    if alert_type:
        query = query.filter_by(alert_type=alert_type)
    
    return query.order_by(SecurityAlert.created_at.desc()).limit(limit).all()


def get_critical_open_alerts(limit=50):
    """Get all open critical alerts."""
    return get_open_alerts(severity='critical', limit=limit)


def create_new_mfa_creation_alert(mfa_event, detection_details):
    """
    Create informational alert for new MFA method creation.
    This provides visibility into ALL MFA additions for audit purposes.
    
    Args:
        mfa_event: EntraMfaEvent object
        detection_details: Dict with detection details
    
    Returns:
        SecurityAlert object or None
    """
    return create_security_alert(
        entra_user_id=mfa_event.entra_user_id,
        user_principal_name=mfa_event.user_principal_name,
        alert_type='new_mfa_method_created',
        severity='low',  # Informational only
        reason=detection_details['reason'],
        related_mfa_event_id=mfa_event.id
    )


def get_high_risk_users(risk_threshold=60, limit=50):
    """
    Get users with high current risk scores.
    
    Args:
        risk_threshold: Minimum risk score to include
        limit: Maximum number of results
    
    Returns:
        List of UserRiskState objects
    """
    return UserRiskState.query.filter(
        UserRiskState.current_risk_score >= risk_threshold
    ).order_by(UserRiskState.current_risk_score.desc()).limit(limit).all()


def update_alert_status(alert_id, new_status):
    """
    Update alert status.
    
    Args:
        alert_id: Alert ID
        new_status: New status (open, investigating, resolved, false_positive)
    
    Returns:
        Boolean success
    """
    alert = SecurityAlert.query.get(alert_id)
    if not alert:
        return False
    
    alert.status = new_status
    
    try:
        db.session.commit()
        current_app.logger.info(f"Updated alert {alert_id} status to {new_status}")
        return True
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Failed to update alert status: {e}")
        return False


def get_alert_summary():
    """
    Get summary statistics for alerts.
    
    Returns:
        Dict with alert counts by severity and status
    """
    from sqlalchemy import func
    
    # Count by severity and status
    severity_counts = db.session.query(
        SecurityAlert.severity,
        SecurityAlert.status,
        func.count(SecurityAlert.id)
    ).group_by(SecurityAlert.severity, SecurityAlert.status).all()
    
    summary = {
        'total': SecurityAlert.query.count(),
        'open': SecurityAlert.query.filter_by(status='open').count(),
        'critical_open': SecurityAlert.query.filter_by(status='open', severity='critical').count(),
        'high_open': SecurityAlert.query.filter_by(status='open', severity='high').count(),
        'by_severity_status': {}
    }
    
    for severity, status, count in severity_counts:
        key = f"{severity}_{status}"
        summary['by_severity_status'][key] = count
    
    return summary
