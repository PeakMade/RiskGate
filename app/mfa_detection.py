"""
MFA/Authentication Method Detection and Correlation.

Core security logic for detecting account takeover persistence:

Attack chain:
1. Attacker steals password
2. Attacker signs in from impossible location
3. Microsoft login/MFA may still succeed
4. RiskGate detects impossible travel → marks user risky
5. Soon after, attacker adds their own MFA method
6. RiskGate correlates MFA change with risky sign-in
7. RiskGate creates critical alert

Key insight: MFA success does NOT erase sign-in risk.
If a user has a risky or impossible login and then changes MFA,
that's a possible account takeover/persistence event.
"""
import json
from datetime import datetime, timedelta
from flask import current_app
from app import db
from app.models_new import EntraSignInEvent, EntraMfaEvent, UserRiskState


def is_mfa_change_event(mfa_event):
    """
    Determine if an audit event represents an MFA/authentication method change.
    
    Looks for activities like:
    - User registered security info
    - Authentication method registered
    - Authentication method deleted
    - Admin updated authentication method
    - Temporary Access Pass created
    
    Args:
        mfa_event: EntraMfaEvent object
    
    Returns:
        Boolean
    """
    if not mfa_event:
        return False
    
    activity_name = (mfa_event.activity_name or '').lower()
    
    mfa_keywords = [
        'security info', 'authentication method', 'authenticator',
        'registered', 'deleted', 'updated', 'removed', 'reset',
        'temporary access pass', 'phone', 'fido', 'passkey'
    ]
    
    return any(keyword in activity_name for keyword in mfa_keywords)


def is_method_added_event(mfa_event):
    """Check if event represents adding a new MFA method."""
    activity_name = (mfa_event.activity_name or '').lower()
    operation_type = (mfa_event.operation_type or '').lower()
    
    return ('registered' in activity_name or
            'added' in activity_name or
            operation_type == 'add')


def is_method_removed_event(mfa_event):
    """Check if event represents removing an MFA method."""
    activity_name = (mfa_event.activity_name or '').lower()
    operation_type = (mfa_event.operation_type or '').lower()
    
    return ('deleted' in activity_name or
            'removed' in activity_name or
            'reset' in activity_name or
            operation_type == 'delete')


def is_tap_event(mfa_event):
    """Check if event represents Temporary Access Pass creation."""
    activity_name = (mfa_event.activity_name or '').lower()
    return 'temporary access pass' in activity_name


def get_recent_risky_signin(entra_user_id, mfa_event_time, lookback_minutes=60):
    """
    Find the most recent risky sign-in for a user before an MFA event.
    
    Args:
        entra_user_id: Entra user ID
        mfa_event_time: DateTime of MFA event
        lookback_minutes: How many minutes back to search (default 60)
    
    Returns:
        EntraSignInEvent object or None
    """
    cutoff_time = mfa_event_time - timedelta(minutes=lookback_minutes)
    
    # Look for recent sign-ins with:
    # - Impossible travel detected, OR
    # - Local risk score >= 60 (high), OR
    # - Microsoft risk level medium/high
    risky_signin = EntraSignInEvent.query.filter(
        EntraSignInEvent.entra_user_id == entra_user_id,
        EntraSignInEvent.created_at >= cutoff_time,
        EntraSignInEvent.created_at <= mfa_event_time,
        EntraSignInEvent.status == 'success',
        db.or_(
            EntraSignInEvent.impossible_travel_detected == True,
            EntraSignInEvent.local_risk_score >= 60,
            EntraSignInEvent.risk_level_aggregated.in_(['medium', 'high'])
        )
    ).order_by(EntraSignInEvent.created_at.desc()).first()
    
    return risky_signin


def correlate_mfa_change_after_risky_signin(mfa_event):
    """
    Correlate an MFA change event with recent risky sign-ins.
    
    This is the core correlation logic that detects account takeover.
    
    If an MFA/authentication method change occurs within 60 minutes after:
    - Impossible login
    - Extreme impossible login
    - Microsoft medium/high risk sign-in
    - Local risk score >= 60
    
    Then create a critical security alert.
    
    Args:
        mfa_event: EntraMfaEvent object
    
    Returns:
        Dict with:
            - correlated: Boolean (True if risky pattern found)
            - risky_signin: EntraSignInEvent or None
            - correlation_reason: String explanation
            - alert_severity: String (critical, high, medium, low)
    """
    result = {
        'correlated': False,
        'risky_signin': None,
        'correlation_reason': None,
        'alert_severity': 'low'
    }
    
    # Only correlate actual MFA change events
    if not is_mfa_change_event(mfa_event):
        return result
    
    # Find recent risky sign-in
    risky_signin = get_recent_risky_signin(
        mfa_event.entra_user_id,
        mfa_event.created_at,
        lookback_minutes=60
    )
    
    if not risky_signin:
        return result
    
    # Calculate time between risky sign-in and MFA change
    time_delta = mfa_event.created_at - risky_signin.created_at
    minutes_between = time_delta.total_seconds() / 60
    
    # Build correlation reason
    risk_reasons = json.loads(risky_signin.local_risk_reasons or '[]')
    
    reason_parts = []
    reason_parts.append(f"MFA/authentication method change detected {int(minutes_between)} minutes after a risky sign-in.")
    reason_parts.append(f"\nRisky sign-in details:")
    reason_parts.append(f"- Time: {risky_signin.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    reason_parts.append(f"- Location: {risky_signin.city or 'Unknown'}, {risky_signin.country or 'Unknown'}")
    reason_parts.append(f"- IP: {risky_signin.ip_address or 'Unknown'}")
    reason_parts.append(f"- Risk Score: {risky_signin.local_risk_score} ({risky_signin.local_risk_level})")
    reason_parts.append(f"- Risk Reasons: {', '.join(risk_reasons)}")
    
    if risky_signin.impossible_travel_detected:
        reason_parts.append(
            f"- Impossible Travel: Yes ({risky_signin.required_travel_speed_mph} mph required)"
        )
    
    reason_parts.append(f"\nMFA event details:")
    reason_parts.append(f"- Time: {mfa_event.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    reason_parts.append(f"- Activity: {mfa_event.activity_name}")
    reason_parts.append(f"- Method Type: {mfa_event.method_type or 'Unknown'}")
    reason_parts.append(f"- Initiated By: {mfa_event.initiated_by}")
    
    if mfa_event.ip_address:
        reason_parts.append(f"- IP: {mfa_event.ip_address}")
    
    reason_parts.append(
        f"\nThis pattern may indicate account takeover with persistence. "
        f"An attacker who successfully logged in despite impossible travel "
        f"may have added their own MFA method to maintain access."
    )
    
    correlation_reason = '\n'.join(reason_parts)
    
    # Determine severity based on risk factors
    if 'extreme_impossible_travel' in risk_reasons:
        severity = 'critical'
    elif risky_signin.impossible_travel_detected:
        severity = 'critical'
    elif risky_signin.local_risk_score >= 90:
        severity = 'critical'
    elif risky_signin.local_risk_score >= 60:
        severity = 'high'
    else:
        severity = 'medium'
    
    result.update({
        'correlated': True,
        'risky_signin': risky_signin,
        'correlation_reason': correlation_reason,
        'alert_severity': severity
    })
    
    # Update MFA event with correlation data
    mfa_event.risk_score_at_time = risky_signin.local_risk_score
    mfa_event.related_recent_signin_id = risky_signin.id
    
    current_app.logger.warning(
        f"CRITICAL: MFA change after risky sign-in detected for {mfa_event.user_principal_name}. "
        f"Risk score: {risky_signin.local_risk_score}, Minutes between: {int(minutes_between)}"
    )
    
    return result


def detect_mfa_takeover_pattern(entra_user_id, hours_back=24):
    """
    Detect pattern: new MFA method added → another method removed soon after.
    
    This pattern suggests an attacker added their own method and
    removed the legitimate user's method.
    
    Args:
        entra_user_id: Entra user ID
        hours_back: How many hours of history to analyze
    
    Returns:
        Dict with:
            - detected: Boolean
            - added_event: EntraMfaEvent or None
            - removed_event: EntraMfaEvent or None
            - reason: String explanation
    """
    cutoff_time = datetime.utcnow() - timedelta(hours=hours_back)
    
    # Get recent MFA events
    recent_events = EntraMfaEvent.query.filter(
        EntraMfaEvent.entra_user_id == entra_user_id,
        EntraMfaEvent.created_at >= cutoff_time
    ).order_by(EntraMfaEvent.created_at.asc()).all()
    
    # Look for add-then-remove pattern
    for i in range(len(recent_events) - 1):
        current_event = recent_events[i]
        next_event = recent_events[i + 1]
        
        if is_method_added_event(current_event) and is_method_removed_event(next_event):
            time_delta = next_event.created_at - current_event.created_at
            minutes_between = time_delta.total_seconds() / 60
            
            reason = (
                f"Possible MFA takeover detected:\n"
                f"1. New method added at {current_event.created_at.strftime('%H:%M:%S UTC')}: "
                f"{current_event.activity_name}\n"
                f"2. Another method removed {int(minutes_between)} minutes later at "
                f"{next_event.created_at.strftime('%H:%M:%S UTC')}: {next_event.activity_name}\n\n"
                f"This pattern may indicate an attacker adding their own MFA method "
                f"and removing the legitimate user's method."
            )
            
            return {
                'detected': True,
                'added_event': current_event,
                'removed_event': next_event,
                'reason': reason
            }
    
    return {
        'detected': False,
        'added_event': None,
        'removed_event': None,
        'reason': None
    }


def detect_tap_after_risk(entra_user_id, tap_event):
    """
    Detect if a Temporary Access Pass was created after a risky sign-in.
    
    TAPs bypass normal MFA, so creating one after risk is highly suspicious.
    
    Args:
        entra_user_id: Entra user ID
        tap_event: EntraMfaEvent representing TAP creation
    
    Returns:
        Dict with:
            - detected: Boolean
            - risky_signin: EntraSignInEvent or None
            - reason: String explanation
    """
    if not is_tap_event(tap_event):
        return {'detected': False, 'risky_signin': None, 'reason': None}
    
    # Look for recent risky sign-in (within 24 hours)
    risky_signin = get_recent_risky_signin(
        entra_user_id,
        tap_event.created_at,
        lookback_minutes=1440  # 24 hours
    )
    
    if not risky_signin:
        return {'detected': False, 'risky_signin': None, 'reason': None}
    
    time_delta = tap_event.created_at - risky_signin.created_at
    hours_between = time_delta.total_seconds() / 3600
    
    reason = (
        f"Temporary Access Pass created {round(hours_between, 1)} hours after a risky sign-in.\n\n"
        f"Risky sign-in: {risky_signin.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
        f"Location: {risky_signin.city}, {risky_signin.country}\n"
        f"Risk Score: {risky_signin.local_risk_score}\n\n"
        f"TAP created: {tap_event.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
        f"Created by: {tap_event.initiated_by}\n\n"
        f"TAPs bypass normal MFA. Creating one after a risky sign-in may indicate "
        f"an attacker attempting to maintain access."
    )
    
    return {
        'detected': True,
        'risky_signin': risky_signin,
        'reason': reason
    }


def detect_new_mfa_creation(mfa_event):
    """
    Detect when a new MFA method is created/registered.
    Creates informational alert for ALL new MFA additions for visibility.
    
    Args:
        mfa_event: EntraMfaEvent object
    
    Returns:
        Dict with:
            - detected: Boolean
            - reason: String explanation
    """
    if not is_method_added_event(mfa_event):
        return {'detected': False, 'reason': None}
    
    activity_name = mfa_event.activity_name or ''
    method_type = mfa_event.method_type or 'Unknown method'
    created_at_str = mfa_event.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')
    
    reason = (
        f"New MFA/authentication method registered:\n\n"
        f"User: {mfa_event.user_principal_name}\n"
        f"Activity: {activity_name}\n"
        f"Method Type: {method_type}\n"
        f"Time: {created_at_str}\n"
        f"Initiated By: {mfa_event.initiated_by}\n"
    )
    
    if mfa_event.ip_address:
        reason += f"IP Address: {mfa_event.ip_address}\n"
    
    reason += (
        f"\nThis is an informational alert for audit purposes. "
        f"All new MFA method registrations are logged for security monitoring. "
        f"If this was not initiated by the user, investigate immediately."
    )
    
    return {
        'detected': True,
        'reason': reason
    }


def analyze_mfa_event_for_correlation(mfa_event):
    """
    Analyze an MFA event for all correlation patterns.
    
    Args:
        mfa_event: EntraMfaEvent object
    
    Returns:
        Dict with:
            - alerts: List of alert dicts to create
    """
    alerts = []
    
    # Pattern 1: MFA change after risky sign-in (most important)
    correlation = correlate_mfa_change_after_risky_signin(mfa_event)
    if correlation['correlated']:
        alerts.append({
            'alert_type': 'mfa_change_after_risky_login',
            'severity': correlation['alert_severity'],
            'reason': correlation['correlation_reason'],
            'related_signin_event_id': correlation['risky_signin'].id if correlation['risky_signin'] else None,
            'related_mfa_event_id': mfa_event.id
        })
    
    # Pattern 2: MFA takeover (add then remove)
    takeover = detect_mfa_takeover_pattern(mfa_event.entra_user_id)
    if takeover['detected']:
        alerts.append({
            'alert_type': 'possible_mfa_takeover',
            'severity': 'critical',
            'reason': takeover['reason'],
            'related_signin_event_id': None,
            'related_mfa_event_id': mfa_event.id
        })
    
    # Pattern 3: TAP after risk
    if is_tap_event(mfa_event):
        tap_risk = detect_tap_after_risk(mfa_event.entra_user_id, mfa_event)
        if tap_risk['detected']:
            alerts.append({
                'alert_type': 'tap_created_after_risk',
                'severity': 'critical',
                'reason': tap_risk['reason'],
                'related_signin_event_id': tap_risk['risky_signin'].id if tap_risk['risky_signin'] else None,
                'related_mfa_event_id': mfa_event.id
            })
    
    # Pattern 4: New MFA creation (informational - always detect)
    # Only create alert if no critical/high severity alert already exists for this event
    # This prevents duplicate alerts for the same event
    if not correlation['correlated'] and not takeover['detected']:
        new_mfa = detect_new_mfa_creation(mfa_event)
        if new_mfa['detected']:
            alerts.append({
                'alert_type': 'new_mfa_method_created',
                'severity': 'low',  # Informational only
                'reason': new_mfa['reason'],
                'related_signin_event_id': None,
                'related_mfa_event_id': mfa_event.id
            })
    
    return {'alerts': alerts}
