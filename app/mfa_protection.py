"""
MFA (Multi-Factor Authentication) protection logic.
Prevents fraudulent MFA creation and modification from risky sessions.
"""
from datetime import datetime, timedelta
from flask import session, current_app, abort
from app.models import User, MfaMethod, SecurityAlert
from app import db


def can_create_mfa(user, session_risk_score):
    """
    Determine if the current session is safe enough to create MFA.
    
    Args:
        user: User object
        session_risk_score: Current session's risk score
    
    Returns:
        Dict with keys:
            - allowed: Boolean
            - reason: String explanation if not allowed
            - requires_additional_auth: Boolean (if password/existing MFA needed)
    """
    # Check if user has high-privilege role
    if user.is_high_privilege():
        # High-privilege users need stricter controls
        threshold = current_app.config['HIGH_PRIVILEGE_RISK_THRESHOLD']
        if session_risk_score >= threshold:
            return {
                'allowed': False,
                'reason': f'High-privilege account requires risk score below {threshold}. Current: {session_risk_score}',
                'requires_additional_auth': False
            }
    
    # Check general risk threshold for MFA changes
    if session_risk_score >= 60:
        return {
            'allowed': False,
            'reason': f'Session risk score too high for MFA changes: {session_risk_score}',
            'requires_additional_auth': False
        }
    
    # Check for recent impossible travel
    from app.risk import has_recent_impossible_travel
    if has_recent_impossible_travel(user.id, hours=24):
        return {
            'allowed': False,
            'reason': 'Recent impossible travel detected. MFA changes blocked for security.',
            'requires_additional_auth': False
        }
    
    # Check for active high-severity security alerts
    from app.security_events import has_active_high_security_alert
    if has_active_high_security_alert(user.id):
        return {
            'allowed': False,
            'reason': 'Active high-severity security alert. Resolve alert before changing MFA.',
            'requires_additional_auth': False
        }
    
    # All checks passed - allow MFA creation but require additional auth
    return {
        'allowed': True,
        'reason': None,
        'requires_additional_auth': True
    }


def require_trusted_session_for_mfa_change(user):
    """
    Gate function that blocks MFA changes from risky sessions.
    Call this before ANY MFA creation, removal, reset, or modification.
    
    Args:
        user: User object
    
    Returns:
        Dict with 'allowed' (Boolean) and 'reason' (String if blocked)
    
    Raises:
        HTTP 403 if the session is not trusted enough for MFA changes
    """
    # Get current session risk score
    session_risk_score = session.get('risk_score', 0)
    
    # Run all safety checks
    check_result = can_create_mfa(user, session_risk_score)
    
    if not check_result['allowed']:
        # Log this blocked attempt
        from app.security_events import log_mfa_event, create_security_alert
        log_mfa_event(
            user_id=user.id,
            event_type='blocked_mfa_change',
            blocked=True,
            reason=check_result['reason']
        )
        
        # Create security alert
        create_security_alert(
            user_id=user.id,
            alert_type='blocked_mfa_change',
            severity='high',
            reason=check_result['reason']
        )
        
        # Return the blocked result
        return {
            'allowed': False,
            'reason': check_result['reason']
        }
    
    return {
        'allowed': True,
        'reason': None
    }


def can_remove_mfa(user, mfa_method):
    """
    Check if an MFA method can be safely removed.
    Prevents removing the last MFA method and blocks removal during risky sessions.
    
    Args:
        user: User object
        mfa_method: MfaMethod object to potentially remove
    
    Returns:
        Dict with keys:
            - allowed: Boolean
            - reason: String explanation if not allowed
    """
    # First, check if session is trusted enough for MFA changes
    session_check = require_trusted_session_for_mfa_change(user)
    if not session_check['allowed']:
        return session_check
    
    # Check if this is the last active MFA method
    active_mfa_count = MfaMethod.query.filter_by(
        user_id=user.id,
        status='active'
    ).count()
    
    if active_mfa_count <= 1 and mfa_method.status == 'active':
        return {
            'allowed': False,
            'reason': 'Cannot remove the last active MFA method. Add another method first.'
        }
    
    # Check if the MFA method was recently added and not fully trusted
    if not mfa_method.is_fully_trusted():
        hours_until_trusted = 'unknown'
        if mfa_method.trusted_after:
            delta = mfa_method.trusted_after - datetime.utcnow()
            hours_until_trusted = max(0, delta.total_seconds() / 3600)
        
        return {
            'allowed': False,
            'reason': f'MFA method must be trusted for {hours_until_trusted:.1f} more hours before removal.'
        }
    
    return {
        'allowed': True,
        'reason': None
    }


def is_mfa_method_fully_trusted(mfa_method):
    """
    Check if an MFA method has passed its trust period.
    New MFA methods require a 24-hour waiting period before full trust.
    
    Args:
        mfa_method: MfaMethod object
    
    Returns:
        Boolean indicating if the method is fully trusted
    """
    return mfa_method.is_fully_trusted()


def create_pending_mfa_method(user, method_type, ip_address, device_fingerprint):
    """
    Create a new MFA method in pending/restricted status.
    Does not immediately activate - requires trust period.
    
    Args:
        user: User object
        method_type: String type of MFA (totp, sms, hardware_key, backup_codes)
        ip_address: IP address where MFA was created
        device_fingerprint: Device fingerprint where MFA was created
    
    Returns:
        MfaMethod object
    """
    # Calculate when this method will be fully trusted
    trust_period_hours = current_app.config['MFA_TRUST_PERIOD_HOURS']
    trusted_after = datetime.utcnow() + timedelta(hours=trust_period_hours)
    
    # Create the new MFA method
    mfa_method = MfaMethod(
        user_id=user.id,
        method_type=method_type,
        status='pending',  # Not immediately active
        created_at=datetime.utcnow(),
        trusted_after=trusted_after,
        created_from_ip=ip_address,
        created_from_device=device_fingerprint
    )
    
    db.session.add(mfa_method)
    db.session.commit()
    
    # Log the MFA creation event
    from app.security_events import log_mfa_event
    log_mfa_event(
        user_id=user.id,
        event_type='create',
        blocked=False,
        reason=f'MFA method created, pending trust period until {trusted_after}',
        mfa_method_id=mfa_method.id
    )
    
    return mfa_method


def activate_mfa_method(mfa_method):
    """
    Activate a pending MFA method after it has been verified.
    
    Args:
        mfa_method: MfaMethod object to activate
    
    Returns:
        Boolean indicating success
    """
    if mfa_method.status == 'pending':
        mfa_method.status = 'active'
        mfa_method.activated_at = datetime.utcnow()
        db.session.commit()
        
        # Log activation
        from app.security_events import log_mfa_event
        log_mfa_event(
            user_id=mfa_method.user_id,
            event_type='activate',
            blocked=False,
            reason='MFA method activated',
            mfa_method_id=mfa_method.id
        )
        return True
    
    return False


def remove_mfa_method(user, mfa_method):
    """
    Remove an MFA method after passing all safety checks.
    
    Args:
        user: User object
        mfa_method: MfaMethod object to remove
    
    Returns:
        Dict with 'success' (Boolean) and 'message' (String)
    """
    # Run safety checks
    check_result = can_remove_mfa(user, mfa_method)
    
    if not check_result['allowed']:
        # Log the blocked removal attempt
        from app.security_events import log_mfa_event
        log_mfa_event(
            user_id=user.id,
            event_type='blocked_remove',
            blocked=True,
            reason=check_result['reason'],
            mfa_method_id=mfa_method.id
        )
        
        return {
            'success': False,
            'message': check_result['reason']
        }
    
    # Mark as removed (don't delete for audit trail)
    mfa_method.status = 'removed'
    db.session.commit()
    
    # Log successful removal
    from app.security_events import log_mfa_event
    log_mfa_event(
        user_id=user.id,
        event_type='remove',
        blocked=False,
        reason='MFA method successfully removed',
        mfa_method_id=mfa_method.id
    )
    
    return {
        'success': True,
        'message': 'MFA method removed successfully'
    }
