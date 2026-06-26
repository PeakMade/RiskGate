"""
Authentication hooks that integrate security checks into the login flow.
These hooks are called during authentication to assess risk and create security events.
"""
from datetime import datetime
from flask import session, current_app
from app.models import User
from app.security_events import create_login_event, update_login_event_risk, create_security_alert
from app.risk import calculate_login_risk, detect_impossible_travel, get_previous_successful_login
from app import db


def after_login_attempt(user, success, additional_data=None):
    """
    Hook called after each login attempt (successful or failed).
    Creates login event, calculates risk, and stores risk in session.
    
    Args:
        user: User object
        success: Boolean indicating if login was successful
        additional_data: Optional dict with extra login information
    
    Returns:
        Dict with login risk assessment
    """
    # Create the login event
    login_event = create_login_event(user, success, additional_data)
    
    if not success:
        # Failed login - no need for risk calculation yet
        return {
            'login_event_id': login_event.id,
            'risk_score': 0,
            'risk_level': 'low'
        }
    
    # For successful logins, calculate risk
    current_login_data = {
        'timestamp': login_event.timestamp,
        'ip_address': login_event.ip_address,
        'country': login_event.country,
        'city': login_event.city,
        'latitude': login_event.latitude,
        'longitude': login_event.longitude,
        'device_fingerprint': login_event.device_fingerprint
    }
    
    # Calculate risk score
    risk_assessment = calculate_login_risk(user, current_login_data)
    
    # Update the login event with risk information
    update_login_event_risk(
        login_event,
        risk_assessment['risk_score'],
        risk_assessment['risk_reasons']
    )
    
    # Store risk score in session for MFA protection checks
    session['risk_score'] = risk_assessment['risk_score']
    session['risk_level'] = risk_assessment['risk_level']
    session['login_event_id'] = login_event.id
    
    # Check for impossible travel and create alerts if needed
    if 'impossible_travel' in risk_assessment['risk_reasons'] or \
       'extreme_impossible_travel' in risk_assessment['risk_reasons']:
        
        # Get travel details
        previous_login = get_previous_successful_login(user.id)
        if previous_login:
            travel_analysis = detect_impossible_travel(previous_login, current_login_data)
            
            # Determine severity
            if 'extreme_impossible_travel' in risk_assessment['risk_reasons']:
                severity = 'critical'
                alert_type = 'extreme_impossible_travel'
            else:
                severity = 'high'
                alert_type = 'impossible_travel'
            
            # Create security alert
            alert_reason = (
                f"Impossible travel detected: {travel_analysis['distance_miles']:.0f} miles "
                f"in {travel_analysis['hours_between']:.1f} hours "
                f"(requires {travel_analysis['required_speed']:.0f} mph). "
                f"Previous: {previous_login.city}, {previous_login.country}. "
                f"Current: {login_event.city}, {login_event.country}."
            )
            
            create_security_alert(
                user_id=user.id,
                alert_type=alert_type,
                severity=severity,
                reason=alert_reason
            )
    
    # Block app access if risk is critical (>= 90)
    if risk_assessment['risk_score'] >= current_app.config.get('RISK_THRESHOLD_CRITICAL_BLOCK', 90):
        session['app_access_blocked'] = True
        session['block_reason'] = f"Critical security risk detected (score: {risk_assessment['risk_score']}). Contact security."
    else:
        session['app_access_blocked'] = False
    
    return {
        'login_event_id': login_event.id,
        'risk_score': risk_assessment['risk_score'],
        'risk_level': risk_assessment['risk_level'],
        'risk_reasons': risk_assessment['risk_reasons']
    }


def clear_session_risk():
    """
    Clear risk-related data from the session.
    Call this on logout or when risk assessment should be reset.
    """
    session.pop('risk_score', None)
    session.pop('risk_level', None)
    session.pop('login_event_id', None)
    session.pop('app_access_blocked', None)
    session.pop('block_reason', None)


def is_app_access_blocked():
    """
    Check if the current session has app access blocked due to critical risk.
    
    Returns:
        Tuple: (blocked: Boolean, reason: String or None)
    """
    blocked = session.get('app_access_blocked', False)
    reason = session.get('block_reason', None) if blocked else None
    return (blocked, reason)


def get_current_session_risk():
    """
    Get the current session's risk information.
    
    Returns:
        Dict with risk_score, risk_level, and login_event_id
    """
    return {
        'risk_score': session.get('risk_score', 0),
        'risk_level': session.get('risk_level', 'low'),
        'login_event_id': session.get('login_event_id')
    }
