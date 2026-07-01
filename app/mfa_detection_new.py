"""
MFA/Authentication Method change detection for RiskGate.

Detects suspicious authentication method changes that may indicate
account takeover persistence.

Attack pattern: When an attacker gains access to an account (via phishing,
password spray, session hijacking, etc.), they often add their own MFA method
to maintain persistent access even if the victim changes their password.

This module correlates MFA/auth method changes with recent risky sign-ins
to detect potential account takeover.
"""
from datetime import datetime, timedelta
from flask import current_app
from app import db
from app.models_new import EntraMfaEvent, EntraSignInEvent


# MFA-related activity keywords
MFA_ACTIVITY_KEYWORDS = [
    'security info',
    'authentication method',
    'authenticator',
    'phone',
    'fido',
    'fido2',
    'temporary access pass',
    'passkey',
    'security key',
    'registered',
    'deleted',
    'updated',
    'reset',
    'removed',
    'added',
    'changed'
]


def is_mfa_related_audit_event(audit_record):
    """
    Determine if an audit log record is related to MFA/authentication methods.
    
    Args:
        audit_record: Dict from Microsoft Graph directoryAudits API
    
    Returns:
        Boolean indicating if this is an MFA-related event
    """
    activity_name = audit_record.get('activityDisplayName', '').lower()
    
    # Check if any MFA keyword appears in the activity name
    for keyword in MFA_ACTIVITY_KEYWORDS:
        if keyword in activity_name:
            return True
    
    # Check category
    category = audit_record.get('category', '')
    if category in ['UserManagement', 'AuthenticationMethod']:
        # Still check for keywords to be more specific
        return any(keyword in activity_name for keyword in MFA_ACTIVITY_KEYWORDS)
    
    return False


def extract_mfa_method_type(audit_record):
    """
    Extract the type of MFA/authentication method from an audit record.
    
    Args:
        audit_record: Dict from Microsoft Graph directoryAudits API
    
    Returns:
        String method type or None
    """
    activity_name = audit_record.get('activityDisplayName', '').lower()
    
    # Map activity names to method types
    if 'authenticator' in activity_name:
        return 'microsoftAuthenticator'
    elif 'phone' in activity_name or 'sms' in activity_name:
        return 'phoneNumber'
    elif 'fido' in activity_name or 'security key' in activity_name:
        return 'fido2SecurityKey'
    elif 'passkey' in activity_name:
        return 'passkey'
    elif 'temporary access pass' in activity_name or 'tap' in activity_name:
        return 'temporaryAccessPass'
    elif 'email' in activity_name:
        return 'emailAuthentication'
    elif 'password' in activity_name:
        return 'password'
    
    # Try to extract from modified properties
    target_resources = audit_record.get('targetResources', []) or []
    if target_resources:
        modified_properties = target_resources[0].get('modifiedProperties', []) or []
        for prop in modified_properties:
            if 'authenticationmethod' in prop.get('displayName', '').lower():
                new_value = prop.get('newValue', '')
                if new_value:
                    return new_value
    
    return None


def classify_mfa_event(audit_record):
    """
    Classify an MFA event into operation type.
    
    Args:
        audit_record: Dict from Microsoft Graph directoryAudits API
    
    Returns:
        Dict with keys:
            - operation: String (added, removed, updated, reset, unknown)
            - method_type: String or None
            - is_high_risk: Boolean
    """
    activity_name = audit_record.get('activityDisplayName', '').lower()
    operation_type = audit_record.get('operationType', '').lower()
    method_type = extract_mfa_method_type(audit_record)
    
    # Determine operation
    operation = 'unknown'
    if 'added' in activity_name or 'registered' in activity_name or operation_type == 'add':
        operation = 'added'
    elif 'deleted' in activity_name or 'removed' in activity_name or operation_type == 'delete':
        operation = 'removed'
    elif 'updated' in activity_name or 'changed' in activity_name or operation_type == 'update':
        operation = 'updated'
    elif 'reset' in activity_name:
        operation = 'reset'
    
    # High-risk operations
    # Adding/removing MFA methods is more sensitive than just updating
    is_high_risk = operation in ['added', 'removed', 'reset']
    
    # Temporary Access Pass creation is especially sensitive
    if method_type == 'temporaryAccessPass' and operation == 'added':
        is_high_risk = True
    
    return {
        'operation': operation,
        'method_type': method_type,
        'is_high_risk': is_high_risk
    }


def correlate_mfa_change_after_risky_login(mfa_event):
    """
    Check if an MFA event occurred shortly after a risky sign-in.
    
    This is a strong indicator of account takeover:
    1. Attacker logs in (detected as risky/impossible)
    2. Attacker immediately adds their own MFA method
    
    Args:
        mfa_event: EntraMfaEvent object
    
    Returns:
        Dict with keys:
            - has_correlation: Boolean
            - related_signin: EntraSignInEvent object or None
            - time_difference_minutes: Float or None
            - signin_risk_score: Integer or None
            - reason: String description
    """
    result = {
        'has_correlation': False,
        'related_signin': None,
        'time_difference_minutes': None,
        'signin_risk_score': None,
        'reason': None
    }
    
    # Look for recent risky sign-ins (within 60 minutes before MFA event)
    lookback_time = mfa_event.created_at - timedelta(minutes=60)
    
    # Find the most recent sign-in by this user before the MFA event
    recent_signin = EntraSignInEvent.query.filter(
        EntraSignInEvent.entra_user_id == mfa_event.entra_user_id,
        EntraSignInEvent.created_at >= lookback_time,
        EntraSignInEvent.created_at <= mfa_event.created_at,
        EntraSignInEvent.status == 'success'
    ).order_by(
        EntraSignInEvent.created_at.desc()
    ).first()
    
    if not recent_signin:
        # No recent sign-in found
        return result
    
    # Calculate time difference
    time_diff = mfa_event.created_at - recent_signin.created_at
    time_diff_minutes = time_diff.total_seconds() / 60
    result['time_difference_minutes'] = round(time_diff_minutes, 2)
    result['related_signin'] = recent_signin
    result['signin_risk_score'] = recent_signin.local_risk_score
    
    # Check if the sign-in was risky
    is_risky = False
    risk_reasons = []
    
    # Condition 1: Impossible or extreme impossible login
    if recent_signin.impossible_travel_detected:
        is_risky = True
        if recent_signin.required_travel_speed_mph and recent_signin.required_travel_speed_mph > 1000:
            risk_reasons.append('extreme_impossible_login')
        else:
            risk_reasons.append('impossible_login')
    
    # Condition 2: Microsoft assessed high/medium risk
    if recent_signin.risk_level_aggregated:
        risk_level_lower = recent_signin.risk_level_aggregated.lower()
        if risk_level_lower in ['high', 'medium']:
            is_risky = True
            risk_reasons.append(f'microsoft_{risk_level_lower}_risk')
    
    # Condition 3: Local risk score >= 60 (high)
    if recent_signin.local_risk_score >= 60:
        is_risky = True
        risk_reasons.append('high_local_risk')
    
    if is_risky:
        result['has_correlation'] = True
        result['reason'] = (
            f"MFA method change {time_diff_minutes:.0f} minutes after risky sign-in. "
            f"Sign-in risk: {recent_signin.local_risk_level} "
            f"({', '.join(risk_reasons)})"
        )
        
        current_app.logger.warning(
            f"CORRELATION DETECTED: {mfa_event.user_principal_name} changed MFA "
            f"{time_diff_minutes:.0f} min after risky sign-in (score: {recent_signin.local_risk_score})"
        )
    
    return result


def detect_new_method_then_old_method_removed(entra_user_id, hours=24):
    """
    Detect if a user added a new MFA method and then removed another method shortly after.
    
    This pattern suggests:
    1. Attacker adds their own MFA method
    2. Attacker removes victim's MFA method to lock them out
    
    Args:
        entra_user_id: Azure AD object ID
        hours: Time window to search (default 24 hours)
    
    Returns:
        Dict with keys:
            - detected: Boolean
            - added_event: EntraMfaEvent or None
            - removed_event: EntraMfaEvent or None
            - time_between_minutes: Float or None
            - reason: String description
    """
    result = {
        'detected': False,
        'added_event': None,
        'removed_event': None,
        'time_between_minutes': None,
        'reason': None
    }
    
    lookback_time = datetime.utcnow() - timedelta(hours=hours)
    
    # Get all recent MFA events for this user
    recent_mfa_events = EntraMfaEvent.query.filter(
        EntraMfaEvent.entra_user_id == entra_user_id,
        EntraMfaEvent.created_at >= lookback_time
    ).order_by(
        EntraMfaEvent.created_at.asc()
    ).all()
    
    if len(recent_mfa_events) < 2:
        # Need at least 2 events
        return result
    
    # Look for pattern: added then removed
    for i in range(len(recent_mfa_events) - 1):
        event1 = recent_mfa_events[i]
        event2 = recent_mfa_events[i + 1]
        
        # Check if event1 is an add and event2 is a remove
        event1_classification = classify_mfa_event({'activityDisplayName': event1.activity_name})
        event2_classification = classify_mfa_event({'activityDisplayName': event2.activity_name})
        
        if event1_classification['operation'] == 'added' and event2_classification['operation'] == 'removed':
            time_diff = event2.created_at - event1.created_at
            time_diff_minutes = time_diff.total_seconds() / 60
            
            # If removal happens within 2 hours of addition
            if time_diff_minutes <= 120:
                result['detected'] = True
                result['added_event'] = event1
                result['removed_event'] = event2
                result['time_between_minutes'] = round(time_diff_minutes, 2)
                result['reason'] = (
                    f"New MFA method added, then another method removed {time_diff_minutes:.0f} minutes later"
                )
                
                current_app.logger.warning(
                    f"POSSIBLE MFA TAKEOVER: {event1.user_principal_name} - "
                    f"method added then removed pattern detected"
                )
                
                return result
    
    return result


def detect_tap_after_risky_login(mfa_event):
    """
    Detect if a Temporary Access Pass was created after a risky sign-in.
    
    Temporary Access Pass (TAP) is a time-limited passcode that allows
    passwordless sign-in. If an attacker creates a TAP after gaining access,
    they can use it to bypass other authentication requirements.
    
    Args:
        mfa_event: EntraMfaEvent object (should be TAP creation event)
    
    Returns:
        Dict with keys:
            - detected: Boolean
            - related_signin: EntraSignInEvent or None
            - time_difference_minutes: Float or None
            - reason: String description
    """
    result = {
        'detected': False,
        'related_signin': None,
        'time_difference_minutes': None,
        'reason': None
    }
    
    # Check if this is a TAP creation event
    if not mfa_event.method_type or 'temporary' not in mfa_event.method_type.lower():
        if not any(keyword in mfa_event.activity_name.lower() for keyword in ['temporary access pass', 'tap']):
            return result
    
    # Look for recent risky sign-ins (within 2 hours before TAP creation)
    lookback_time = mfa_event.created_at - timedelta(hours=2)
    
    recent_risky_signin = EntraSignInEvent.query.filter(
        EntraSignInEvent.entra_user_id == mfa_event.entra_user_id,
        EntraSignInEvent.created_at >= lookback_time,
        EntraSignInEvent.created_at <= mfa_event.created_at,
        EntraSignInEvent.status == 'success',
        db.or_(
            EntraSignInEvent.impossible_travel_detected == True,
            EntraSignInEvent.local_risk_score >= 60
        )
    ).order_by(
        EntraSignInEvent.created_at.desc()
    ).first()
    
    if recent_risky_signin:
        time_diff = mfa_event.created_at - recent_risky_signin.created_at
        time_diff_minutes = time_diff.total_seconds() / 60
        
        result['detected'] = True
        result['related_signin'] = recent_risky_signin
        result['time_difference_minutes'] = round(time_diff_minutes, 2)
        result['reason'] = (
            f"Temporary Access Pass created {time_diff_minutes:.0f} minutes after "
            f"risky sign-in (risk score: {recent_risky_signin.local_risk_score})"
        )
        
        current_app.logger.critical(
            f"CRITICAL: TAP created after risky sign-in for {mfa_event.user_principal_name}"
        )
    
    return result


def analyze_mfa_event_risk(mfa_event):
    """
    Comprehensive risk analysis of an MFA event.
    
    Runs all detection rules and returns consolidated results.
    
    Args:
        mfa_event: EntraMfaEvent object
    
    Returns:
        Dict with keys:
            - should_alert: Boolean
            - alert_type: String or None
            - severity: String (low, medium, high, critical)
            - detections: Dict of detection results
            - reason: String description
    """
    result = {
        'should_alert': False,
        'alert_type': None,
        'severity': 'low',
        'detections': {},
        'reason': None
    }
    
    # Classify the MFA event
    classification = classify_mfa_event({
        'activityDisplayName': mfa_event.activity_name,
        'operationType': mfa_event.operation_type
    })
    
    # Detection 1: MFA change after risky login
    risky_login_correlation = correlate_mfa_change_after_risky_login(mfa_event)
    result['detections']['risky_login_correlation'] = risky_login_correlation
    
    if risky_login_correlation['has_correlation']:
        result['should_alert'] = True
        result['alert_type'] = 'mfa_change_after_risky_login'
        result['severity'] = 'critical'
        result['reason'] = risky_login_correlation['reason']
        return result
    
    # Detection 2: TAP created after risky sign-in
    tap_detection = detect_tap_after_risky_login(mfa_event)
    result['detections']['tap_after_risk'] = tap_detection
    
    if tap_detection['detected']:
        result['should_alert'] = True
        result['alert_type'] = 'tap_created_after_risk'
        result['severity'] = 'critical'
        result['reason'] = tap_detection['reason']
        return result
    
    # Detection 3: New method added, then old method removed
    takeover_pattern = detect_new_method_then_old_method_removed(mfa_event.entra_user_id)
    result['detections']['takeover_pattern'] = takeover_pattern
    
    if takeover_pattern['detected']:
        result['should_alert'] = True
        result['alert_type'] = 'possible_mfa_takeover'
        result['severity'] = 'critical'
        result['reason'] = takeover_pattern['reason']
        return result
    
    return result
