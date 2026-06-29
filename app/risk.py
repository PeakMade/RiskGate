"""
Risk detection and impossible travel analysis.
Core logic for identifying suspicious login patterns.
"""
import math
from datetime import datetime, timedelta
from flask import current_app
from app.models import LoginEvent, SecurityAlert
from app import db


def distance_miles(lat1, lon1, lat2, lon2):
    """
    Calculate the distance between two geographic coordinates in miles.
    Uses the Haversine formula for great-circle distance.
    
    Args:
        lat1: Latitude of first location (in degrees)
        lon1: Longitude of first location (in degrees)
        lat2: Latitude of second location (in degrees)
        lon2: Longitude of second location (in degrees)
    
    Returns:
        Distance in miles as a float
    """
    # Handle None values or invalid coordinates
    if None in [lat1, lon1, lat2, lon2]:
        return 0
    
    # Earth's radius in miles
    earth_radius_miles = 3958.8
    
    # Convert degrees to radians
    lat1_rad = math.radians(lat1)
    lat2_rad = math.radians(lat2)
    delta_lat = math.radians(lat2 - lat1)
    delta_lon = math.radians(lon2 - lon1)
    
    # Haversine formula
    a = math.sin(delta_lat / 2) ** 2 + \
        math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(delta_lon / 2) ** 2
    c = 2 * math.asin(math.sqrt(a))
    
    distance = earth_radius_miles * c
    return distance


def detect_impossible_travel(previous_login, current_login):
    """
    Detect if travel between two logins is physically impossible.
    
    Args:
        previous_login: LoginEvent object for the previous successful login
        current_login: Dict or LoginEvent with current login data
    
    Returns:
        Dict with keys:
            - is_impossible: Boolean
            - is_extreme: Boolean
            - distance_miles: Float
            - hours_between: Float
            - required_speed: Float
            - reason: String description
    """
    result = {
        'is_impossible': False,
        'is_extreme': False,
        'distance_miles': 0,
        'hours_between': 0,
        'required_speed': 0,
        'reason': None
    }
    
    # If no previous login, this can't be impossible travel
    if not previous_login:
        return result
    
    # Extract coordinates from current login (could be dict or object)
    if isinstance(current_login, dict):
        curr_lat = current_login.get('latitude')
        curr_lon = current_login.get('longitude')
        curr_time = current_login.get('timestamp', datetime.utcnow())
    else:
        curr_lat = current_login.latitude
        curr_lon = current_login.longitude
        curr_time = current_login.timestamp
    
    prev_lat = previous_login.latitude
    prev_lon = previous_login.longitude
    prev_time = previous_login.timestamp
    
    # If coordinates are missing, we can't calculate distance
    if None in [prev_lat, prev_lon, curr_lat, curr_lon]:
        return result
    
    # Calculate distance between locations
    distance = distance_miles(prev_lat, prev_lon, curr_lat, curr_lon)
    result['distance_miles'] = round(distance, 2)
    
    # Calculate time between logins in hours
    time_delta = curr_time - prev_time
    hours_between = time_delta.total_seconds() / 3600
    result['hours_between'] = round(hours_between, 2)
    
    # Avoid division by zero
    if hours_between == 0:
        # Same second login from different location is highly suspicious
        if distance > 10:  # More than 10 miles
            result['is_extreme'] = True
            result['is_impossible'] = True
            result['required_speed'] = float('inf')
            result['reason'] = 'Same-second login from different location'
        return result
    
    # Calculate required travel speed
    required_speed = distance / hours_between
    result['required_speed'] = round(required_speed, 2)
    
    # Check against thresholds
    impossible_threshold = current_app.config['TRAVEL_SPEED_IMPOSSIBLE']
    extreme_threshold = current_app.config['TRAVEL_SPEED_EXTREME']
    
    if required_speed > extreme_threshold:
        result['is_extreme'] = True
        result['is_impossible'] = True
        result['reason'] = f'Extreme impossible travel: {required_speed:.0f} mph required'
    elif required_speed > impossible_threshold:
        result['is_impossible'] = True
        result['reason'] = f'Impossible travel: {required_speed:.0f} mph required'
    
    return result


def calculate_login_risk(user, current_login_data):
    """
    Calculate the risk score for a login attempt.
    Considers multiple risk factors: new device, new country, impossible travel.
    
    Args:
        user: User object
        current_login_data: Dict with current login information
    
    Returns:
        Dict with keys:
            - risk_score: Integer total risk score
            - risk_reasons: List of reason strings
            - risk_level: String (low, medium, high, critical)
    """
    risk_score = 0
    risk_reasons = []
    
    # Get configuration values
    config = current_app.config
    
    # Extract current login information
    device_fingerprint = current_login_data.get('device_fingerprint')
    country = current_login_data.get('country')
    
    # Check if this is a new device
    from app.models import TrustedDevice
    if device_fingerprint:
        previous_device = TrustedDevice.query.filter_by(
            user_id=user.id,
            device_fingerprint=device_fingerprint
        ).first()
        
        if not previous_device:
            # New device
            risk_score += config['RISK_SCORE_NEW_DEVICE']
            risk_reasons.append('new_device')
    
    # Check if this is a new country
    if country:
        previous_country_login = LoginEvent.query.filter_by(
            user_id=user.id,
            success=True,
            country=country
        ).first()
        
        if not previous_country_login:
            # New country
            risk_score += config['RISK_SCORE_NEW_COUNTRY']
            risk_reasons.append('new_country')
    
    # Check for impossible travel
    previous_login = get_previous_successful_login(user.id)
    
    # DEBUG: Print what we found
    print(f"\n=== IMPOSSIBLE TRAVEL CHECK ===")
    print(f"User ID: {user.id}")
    print(f"Previous login found: {previous_login is not None}")
    if previous_login:
        print(f"Previous: {previous_login.city}, {previous_login.country} ({previous_login.latitude}, {previous_login.longitude}) at {previous_login.timestamp}")
        print(f"Current: {current_login_data.get('city')}, {current_login_data.get('country')} ({current_login_data.get('latitude')}, {current_login_data.get('longitude')}) at {current_login_data.get('timestamp')}")
    
    if previous_login:
        travel_analysis = detect_impossible_travel(previous_login, current_login_data)
        
        # DEBUG: Print travel analysis
        print(f"Travel Analysis:")
        print(f"  Distance: {travel_analysis['distance_miles']} miles")
        print(f"  Time: {travel_analysis['hours_between']} hours")
        print(f"  Speed: {travel_analysis['required_speed']} mph")
        print(f"  Is Impossible: {travel_analysis['is_impossible']}")
        print(f"  Is Extreme: {travel_analysis['is_extreme']}")
        print(f"  Reason: {travel_analysis['reason']}")
        print(f"=== END CHECK ===\n")
        
        if travel_analysis['is_extreme']:
            risk_score += config['RISK_SCORE_EXTREME_TRAVEL']
            risk_reasons.append('extreme_impossible_travel')
        elif travel_analysis['is_impossible']:
            risk_score += config['RISK_SCORE_IMPOSSIBLE_TRAVEL']
            risk_reasons.append('impossible_travel')
    
    # TODO: Add check for recent MFA prompt spam
    # This would check if there have been many failed MFA attempts recently
    # risk_score += config['RISK_SCORE_MFA_SPAM']
    # risk_reasons.append('mfa_spam')
    
    # Determine risk level based on thresholds
    risk_level = get_risk_level(risk_score)
    
    return {
        'risk_score': risk_score,
        'risk_reasons': risk_reasons,
        'risk_level': risk_level
    }


def has_recent_impossible_travel(user_id, hours=24):
    """
    Check if user has recent impossible travel events.
    
    Args:
        user_id: User ID to check
        hours: How many hours back to look (default 24)
    
    Returns:
        Boolean indicating if recent impossible travel was detected
    """
    cutoff_time = datetime.utcnow() - timedelta(hours=hours)
    
    # Look for recent login events with impossible travel in the risk reason
    recent_impossible = LoginEvent.query.filter(
        LoginEvent.user_id == user_id,
        LoginEvent.timestamp >= cutoff_time,
        LoginEvent.success == True,
        db.or_(
            LoginEvent.risk_reason.like('%impossible_travel%'),
            LoginEvent.risk_reason.like('%extreme_impossible_travel%')
        )
    ).first()
    
    return recent_impossible is not None


def get_risk_level(risk_score):
    """
    Convert a numeric risk score into a risk level category.
    
    Args:
        risk_score: Integer risk score
    
    Returns:
        String: 'low', 'medium', 'high', or 'critical'
    """
    config = current_app.config
    
    if risk_score <= config['RISK_THRESHOLD_LOW']:
        return 'low'
    elif risk_score <= config['RISK_THRESHOLD_MEDIUM']:
        return 'medium'
    elif risk_score <= config['RISK_THRESHOLD_HIGH']:
        return 'high'
    else:
        return 'critical'


def get_previous_successful_login(user_id):
    """
    Get the most recent successful login for a user.
    Excludes the current login attempt by skipping the first result.
    
    Args:
        user_id: User ID to query
    
    Returns:
        LoginEvent object or None
    """
    # Skip the first (current) login and get the second most recent
    all_logins = LoginEvent.query.filter_by(
        user_id=user_id,
        success=True
    ).order_by(LoginEvent.timestamp.desc()).limit(2).all()
    
    # DEBUG
    print(f"\n=== GET PREVIOUS LOGIN ===")
    print(f"User ID: {user_id}")
    print(f"Total successful logins found: {len(all_logins)}")
    for i, login in enumerate(all_logins):
        print(f"  [{i}] {login.city}, {login.country} at {login.timestamp} (ID: {login.id})")
    
    # Return the second login if it exists
    result = all_logins[1] if len(all_logins) >= 2 else None
    print(f"Returning: {result.city if result else 'None'}")
    print(f"=== END GET PREVIOUS ===\n")
    
    return result


def detect_cross_user_breach_patterns(hours=24):
    """
    Detect breach patterns across multiple users.
    Indicators: Multiple users with impossible travel in same time window.
    
    Args:
        hours: Time window to analyze (default 24 hours)
    
    Returns:
        Dict with keys:
            - is_breach_likely: Boolean
            - affected_users_count: Integer
            - affected_user_ids: List of user IDs
            - severity: String (low, medium, high, critical)
            - reason: String description
    """
    cutoff_time = datetime.utcnow() - timedelta(hours=hours)
    
    # Find all users with impossible travel in the time window
    impossible_travel_logins = LoginEvent.query.filter(
        LoginEvent.timestamp >= cutoff_time,
        LoginEvent.success == True,
        db.or_(
            LoginEvent.risk_reason.like('%impossible_travel%'),
            LoginEvent.risk_reason.like('%extreme_impossible_travel%')
        )
    ).all()
    
    # Get unique user IDs
    affected_user_ids = list(set([login.user_id for login in impossible_travel_logins]))
    affected_count = len(affected_user_ids)
    
    # Determine if this is likely a breach
    is_breach_likely = False
    severity = 'low'
    reason = f'{affected_count} user(s) with impossible travel in last {hours} hours'
    
    if affected_count >= 5:
        is_breach_likely = True
        severity = 'critical'
        reason = f'BREACH ALERT: {affected_count} users showing impossible travel patterns - possible credential stuffing attack'
    elif affected_count >= 3:
        is_breach_likely = True
        severity = 'high'
        reason = f'Multiple users ({affected_count}) with impossible travel - investigate for breach'
    elif affected_count >= 2:
        severity = 'medium'
        reason = f'{affected_count} users with impossible travel - monitor for escalation'
    
    return {
        'is_breach_likely': is_breach_likely,
        'affected_users_count': affected_count,
        'affected_user_ids': affected_user_ids,
        'severity': severity,
        'reason': reason,
        'time_window_hours': hours
    }


def get_mfa_creation_after_risky_login(user_id, hours=1):
    """
    Check if user created MFA methods shortly after a risky login.
    This is a key indicator of account takeover.
    
    Args:
        user_id: User ID to check
        hours: Time window after risky login to check for MFA creation
    
    Returns:
        Dict with keys:
            - correlation_found: Boolean
            - risky_login: LoginEvent object or None
            - mfa_events: List of MfaEvent objects
            - time_between_minutes: Float or None
            - is_suspicious: Boolean
    """
    from app.models import MfaEvent
    
    # Find risky logins (risk score >= 60) in last 24 hours
    cutoff_time = datetime.utcnow() - timedelta(hours=24)
    risky_login = LoginEvent.query.filter(
        LoginEvent.user_id == user_id,
        LoginEvent.timestamp >= cutoff_time,
        LoginEvent.success == True,
        LoginEvent.risk_score >= 60
    ).order_by(LoginEvent.timestamp.desc()).first()
    
    if not risky_login:
        return {
            'correlation_found': False,
            'risky_login': None,
            'mfa_events': [],
            'time_between_minutes': None,
            'is_suspicious': False
        }
    
    # Check for MFA creation within X hours after the risky login
    mfa_window_end = risky_login.timestamp + timedelta(hours=hours)
    mfa_events = MfaEvent.query.filter(
        MfaEvent.user_id == user_id,
        MfaEvent.timestamp >= risky_login.timestamp,
        MfaEvent.timestamp <= mfa_window_end,
        MfaEvent.event_type == 'create'
    ).all()
    
    correlation_found = len(mfa_events) > 0
    time_between_minutes = None
    
    if correlation_found and mfa_events:
        # Calculate time between risky login and first MFA creation
        first_mfa = mfa_events[0]
        time_delta = first_mfa.timestamp - risky_login.timestamp
        time_between_minutes = time_delta.total_seconds() / 60
    
    # Consider it suspicious if MFA was created within 30 minutes of risky login
    is_suspicious = correlation_found and (time_between_minutes is not None and time_between_minutes <= 30)
    
    return {
        'correlation_found': correlation_found,
        'risky_login': risky_login,
        'mfa_events': mfa_events,
        'time_between_minutes': time_between_minutes,
        'is_suspicious': is_suspicious
    }


def get_all_users_with_risky_mfa_correlation(hours=24):
    """
    Get all users who had risky logins followed by MFA creation.
    Used for breach detection dashboard.
    
    Args:
        hours: Time window to analyze
    
    Returns:
        List of dicts, each containing:
            - user_id: Integer
            - user_email: String
            - risky_login: LoginEvent
            - mfa_events: List of MfaEvent
            - time_between_minutes: Float
            - risk_score: Integer
    """
    from app.models import User, MfaEvent
    
    cutoff_time = datetime.utcnow() - timedelta(hours=hours)
    
    # Find all risky logins
    risky_logins = LoginEvent.query.filter(
        LoginEvent.timestamp >= cutoff_time,
        LoginEvent.success == True,
        LoginEvent.risk_score >= 60
    ).order_by(LoginEvent.timestamp.desc()).all()
    
    correlations = []
    
    for login in risky_logins:
        # Check if MFA was created within 1 hour after this risky login
        mfa_window_end = login.timestamp + timedelta(hours=1)
        mfa_events = MfaEvent.query.filter(
            MfaEvent.user_id == login.user_id,
            MfaEvent.timestamp >= login.timestamp,
            MfaEvent.timestamp <= mfa_window_end,
            MfaEvent.event_type == 'create'
        ).all()
        
        if mfa_events:
            user = User.query.get(login.user_id)
            time_delta = mfa_events[0].timestamp - login.timestamp
            time_between_minutes = time_delta.total_seconds() / 60
            
            correlations.append({
                'user_id': login.user_id,
                'user_email': user.email if user else 'Unknown',
                'risky_login': login,
                'mfa_events': mfa_events,
                'time_between_minutes': round(time_between_minutes, 1),
                'risk_score': login.risk_score
            })
    
    return correlations
