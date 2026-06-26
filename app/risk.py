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
