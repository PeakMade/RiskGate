"""
Risk detection and impossible travel analysis for RiskGate.

Core logic for identifying suspicious login patterns from Microsoft Entra sign-in logs.

IMPORTANT: Impossible travel detection is a risk signal, not proof of compromise.
False positives can occur due to:
- VPN usage (user appears to "teleport" when VPN connects)
- Mobile device IP routing (cell towers route through distant data centers)
- Cloud services/RDP (user connects to cloud VM in different region)
- Bad IP geolocation data (IP databases can be inaccurate)
- Shared accounts (multiple legitimate users in different locations)
- Corporate proxy servers (traffic routed through central office)

Use impossible travel as one signal in a broader risk assessment,
not as automatic proof of account compromise.
"""
import math
from datetime import datetime, timedelta
from flask import current_app
from app import db
from app.models_new import EntraSignInEvent, UserRiskState


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
        return 0.0
    
    # If coordinates are identical, distance is zero
    if lat1 == lat2 and lon1 == lon2:
        return 0.0
    
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


def get_previous_successful_signin(entra_user_id, before_datetime):
    """
    Get the most recent successful sign-in for a user before a given time.
    
    Args:
        entra_user_id: Azure AD object ID
        before_datetime: Get sign-ins before this timestamp
    
    Returns:
        EntraSignInEvent object or None
    """
    previous_signin = EntraSignInEvent.query.filter(
        EntraSignInEvent.entra_user_id == entra_user_id,
        EntraSignInEvent.created_at < before_datetime,
        EntraSignInEvent.status == 'success'
    ).order_by(
        EntraSignInEvent.created_at.desc()
    ).first()
    
    return previous_signin


def detect_impossible_travel(previous_signin, current_signin):
    """
    Detect if travel between two sign-ins is physically impossible.
    
    IMPORTANT: This is a risk indicator, not proof of compromise.
    See module docstring for common false positive causes.
    
    Args:
        previous_signin: EntraSignInEvent object for the previous successful sign-in
        current_signin: EntraSignInEvent object for the current sign-in
    
    Returns:
        Dict with keys:
            - is_impossible: Boolean (speed > 500 mph)
            - is_extreme: Boolean (speed > 1000 mph)
            - distance_miles: Float
            - hours_between: Float
            - required_speed_mph: Float
            - reason: String description or None
    """
    result = {
        'is_impossible': False,
        'is_extreme': False,
        'distance_miles': 0.0,
        'hours_between': 0.0,
        'required_speed_mph': 0.0,
        'reason': None
    }
    
    # If no previous sign-in, this can't be impossible travel
    if not previous_signin:
        return result
    
    # Extract coordinates
    prev_lat = previous_signin.latitude
    prev_lon = previous_signin.longitude
    curr_lat = current_signin.latitude
    curr_lon = current_signin.longitude
    
    # If coordinates are missing, we can't calculate distance
    if None in [prev_lat, prev_lon, curr_lat, curr_lon]:
        current_app.logger.debug(
            f"Missing coordinates for impossible travel detection: "
            f"prev=({prev_lat}, {prev_lon}), curr=({curr_lat}, {curr_lon})"
        )
        return result
    
    # Calculate distance between locations
    distance = distance_miles(prev_lat, prev_lon, curr_lat, curr_lon)
    result['distance_miles'] = round(distance, 2)
    
    # If distance is very small, no impossible travel
    if distance < 10:  # Less than 10 miles
        return result
    
    # Calculate time between sign-ins in hours
    prev_time = previous_signin.created_at
    curr_time = current_signin.created_at
    time_delta = curr_time - prev_time
    hours_between = time_delta.total_seconds() / 3600
    result['hours_between'] = round(hours_between, 2)
    
    # Avoid division by zero
    if hours_between <= 0.01:  # Less than ~36 seconds
        # Same-second or backwards-time login from different location
        if distance > 10:
            result['is_extreme'] = True
            result['is_impossible'] = True
            result['required_speed_mph'] = 999999.0  # Effectively infinite
            result['reason'] = f'Simultaneous login from {distance:.0f} miles away'
        return result
    
    # Calculate required travel speed in mph
    required_speed = distance / hours_between
    result['required_speed_mph'] = round(required_speed, 2)
    
    # Threshold for impossible travel: 500 mph
    # (Commercial aircraft cruise at ~550 mph, but accounting for airport access,
    # security, boarding, taxi, and travel to/from airports makes 500 mph a reasonable threshold)
    if required_speed > 1000:
        # Extreme impossible travel (faster than any commercial aircraft)
        result['is_extreme'] = True
        result['is_impossible'] = True
        result['reason'] = f'Extreme impossible travel: {required_speed:.0f} mph required'
        current_app.logger.warning(
            f"EXTREME impossible travel detected: {previous_signin.user_principal_name} "
            f"traveled {distance:.0f} miles in {hours_between:.2f} hours "
            f"(required speed: {required_speed:.0f} mph)"
        )
    elif required_speed > 500:
        # Impossible travel (faster than realistic commercial travel)
        result['is_impossible'] = True
        result['reason'] = f'Impossible travel: {required_speed:.0f} mph required'
        current_app.logger.warning(
            f"Impossible travel detected: {previous_signin.user_principal_name} "
            f"traveled {distance:.0f} miles in {hours_between:.2f} hours "
            f"(required speed: {required_speed:.0f} mph)"
        )
    
    return result


def calculate_signin_risk(signin_event, previous_signin=None):
    """
    Calculate the risk score for a sign-in event.
    Considers multiple risk factors from both Microsoft and local analysis.
    
    Risk scoring:
    - New device: +20
    - New country: +20
    - Impossible travel (> 500 mph): +40
    - Extreme impossible travel (> 1000 mph): +30 additional
    - Microsoft risk level medium: +30
    - Microsoft risk level high: +50
    
    Risk levels:
    - 0-29: low
    - 30-59: medium
    - 60-89: high
    - 90+: critical
    
    Args:
        signin_event: EntraSignInEvent object
        previous_signin: Optional previous EntraSignInEvent for impossible travel detection
    
    Returns:
        Dict with keys:
            - risk_score: Integer total risk score
            - risk_level: String (low, medium, high, critical)
            - risk_reasons: List of reason strings
            - impossible_travel_data: Dict from detect_impossible_travel() or None
    """
    risk_score = 0
    risk_reasons = []
    impossible_travel_data = None
    
    # Factor 1: Microsoft's risk assessment
    if signin_event.risk_level_aggregated:
        risk_level_lower = signin_event.risk_level_aggregated.lower()
        if risk_level_lower == 'high':
            risk_score += 50
            risk_reasons.append('microsoft_high_risk')
            current_app.logger.info(f"Microsoft high risk sign-in: {signin_event.user_principal_name}")
        elif risk_level_lower == 'medium':
            risk_score += 30
            risk_reasons.append('microsoft_medium_risk')
            current_app.logger.info(f"Microsoft medium risk sign-in: {signin_event.user_principal_name}")
        elif risk_level_lower == 'low':
            risk_score += 10
            risk_reasons.append('microsoft_low_risk')
    
    # Factor 2: New device
    # Check if this device_id has been seen before for this user
    if signin_event.device_id:
        previous_device_signin = EntraSignInEvent.query.filter(
            EntraSignInEvent.entra_user_id == signin_event.entra_user_id,
            EntraSignInEvent.device_id == signin_event.device_id,
            EntraSignInEvent.created_at < signin_event.created_at,
            EntraSignInEvent.status == 'success'
        ).first()
        
        if not previous_device_signin:
            risk_score += 20
            risk_reasons.append('new_device')
            current_app.logger.debug(f"New device for {signin_event.user_principal_name}")
    
    # Factor 3: New country
    # Check if this country has been seen before for this user
    if signin_event.country:
        previous_country_signin = EntraSignInEvent.query.filter(
            EntraSignInEvent.entra_user_id == signin_event.entra_user_id,
            EntraSignInEvent.country == signin_event.country,
            EntraSignInEvent.created_at < signin_event.created_at,
            EntraSignInEvent.status == 'success'
        ).first()
        
        if not previous_country_signin:
            risk_score += 20
            risk_reasons.append('new_country')
            current_app.logger.debug(f"New country for {signin_event.user_principal_name}: {signin_event.country}")
    
    # Factor 4: Impossible travel
    # If no previous_signin provided, look it up
    if not previous_signin:
        previous_signin = get_previous_successful_signin(
            signin_event.entra_user_id,
            signin_event.created_at
        )
    
    if previous_signin:
        impossible_travel_data = detect_impossible_travel(previous_signin, signin_event)
        
        if impossible_travel_data['is_extreme']:
            risk_score += 70  # 40 for impossible + 30 for extreme
            risk_reasons.append('extreme_impossible_travel')
            # Update signin_event with impossible travel data
            signin_event.impossible_travel_detected = True
            signin_event.required_travel_speed_mph = impossible_travel_data['required_speed_mph']
        elif impossible_travel_data['is_impossible']:
            risk_score += 40
            risk_reasons.append('impossible_travel')
            # Update signin_event with impossible travel data
            signin_event.impossible_travel_detected = True
            signin_event.required_travel_speed_mph = impossible_travel_data['required_speed_mph']
    
    # Determine risk level
    risk_level = get_risk_level(risk_score)
    
    # Update signin_event with calculated risk
    signin_event.local_risk_score = risk_score
    signin_event.local_risk_level = risk_level
    import json
    signin_event.local_risk_reasons = json.dumps(risk_reasons)
    
    return {
        'risk_score': risk_score,
        'risk_level': risk_level,
        'risk_reasons': risk_reasons,
        'impossible_travel_data': impossible_travel_data
    }


def get_risk_level(score):
    """
    Convert risk score to risk level.
    
    Args:
        score: Integer risk score
    
    Returns:
        String risk level: low, medium, high, or critical
    """
    if score >= 90:
        return 'critical'
    elif score >= 60:
        return 'high'
    elif score >= 30:
        return 'medium'
    else:
        return 'low'


def update_user_risk_state(entra_user_id, user_principal_name, score, reasons):
    """
    Update the UserRiskState for a user.
    
    Args:
        entra_user_id: Azure AD object ID
        user_principal_name: user@domain.com
        score: Integer risk score
        reasons: List of risk reason strings
    
    Returns:
        UserRiskState object
    """
    import json
    
    risk_state = UserRiskState.query.filter_by(entra_user_id=entra_user_id).first()
    
    if not risk_state:
        risk_state = UserRiskState(
            entra_user_id=entra_user_id,
            user_principal_name=user_principal_name
        )
        db.session.add(risk_state)
        current_app.logger.info(f"Created UserRiskState for {user_principal_name}")
    
    # Update risk state
    risk_state.current_risk_score = score
    risk_state.current_risk_level = get_risk_level(score)
    risk_state.reasons = json.dumps(reasons)
    
    # Update timestamps based on risk reasons
    now = datetime.utcnow()
    if any('impossible' in r for r in reasons):
        risk_state.last_impossible_login_at = now
        risk_state.last_risky_signin_at = now
    elif score >= 30:
        risk_state.last_risky_signin_at = now
    
    risk_state.updated_at = now
    
    return risk_state
