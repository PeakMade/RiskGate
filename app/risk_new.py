"""
Risk detection and analysis for Microsoft Entra sign-in events.

Core security logic:
- Impossible travel detection using Haversine formula
- Risk score calculation from multiple signals
- User risk state management

Important: Impossible travel can have false positives due to:
- VPNs and proxies
- Mobile carrier routing
- Cloud services with distributed edge locations
- Inaccurate IP geolocation databases

RiskGate raises risk and triggers investigation.
The app explains these limitations to users.
"""
import math
import json
from datetime import datetime, timedelta
from flask import current_app
from app import db
from app.models_new import EntraSignInEvent, UserRiskState


def distance_miles(lat1, lon1, lat2, lon2):
    """
    Calculate the great-circle distance between two geographic coordinates.
    Uses the Haversine formula for accuracy over Earth's spherical surface.
    
    Args:
        lat1: Latitude of first location (degrees)
        lon1: Longitude of first location (degrees)
        lat2: Latitude of second location (degrees)
        lon2: Longitude of second location (degrees)
    
    Returns:
        Distance in miles as a float
    """
    # Handle None or missing coordinates
    if None in [lat1, lon1, lat2, lon2]:
        return 0.0
    
    # Earth's radius in miles
    earth_radius_miles = 3958.8
    
    # Convert degrees to radians
    lat1_rad = math.radians(lat1)
    lat2_rad = math.radians(lat2)
    delta_lat = math.radians(lat2 - lat1)
    delta_lon = math.radians(lon2 - lon1)
    
    # Haversine formula
    a = (math.sin(delta_lat / 2) ** 2 +
         math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(delta_lon / 2) ** 2)
    c = 2 * math.asin(math.sqrt(a))
    
    distance = earth_radius_miles * c
    return distance


def detect_impossible_travel(previous_signin, current_signin):
    """
    Detect if travel between two sign-ins is physically impossible.
    
    Calculates required travel speed in miles per hour.
    Speed thresholds:
    - Over 500 mph: Impossible for normal travel (faster than commercial flight)
    - Over 1000 mph: Extreme impossible travel (faster than supersonic flight)
    
    Args:
        previous_signin: EntraSignInEvent object (previous successful sign-in)
        current_signin: EntraSignInEvent object (current sign-in)
    
    Returns:
        Dict with:
            - is_impossible: Boolean
            - is_extreme: Boolean
            - distance_miles: Float
            - hours_between: Float
            - required_speed_mph: Float
            - reason: String description
    """
    result = {
        'is_impossible': False,
        'is_extreme': False,
        'distance_miles': 0.0,
        'hours_between': 0.0,
        'required_speed_mph': 0.0,
        'reason': None
    }
    
    # If no previous sign-in, can't be impossible travel
    if not previous_signin:
        return result
    
    # Extract coordinates
    prev_lat = previous_signin.latitude
    prev_lon = previous_signin.longitude
    curr_lat = current_signin.latitude
    curr_lon = current_signin.longitude
    
    # If coordinates missing, can't calculate
    if None in [prev_lat, prev_lon, curr_lat, curr_lon]:
        result['reason'] = 'Missing geographic coordinates'
        return result
    
    # Calculate distance
    distance = distance_miles(prev_lat, prev_lon, curr_lat, curr_lon)
    result['distance_miles'] = round(distance, 2)
    
    # Calculate time between sign-ins
    time_delta = current_signin.created_at - previous_signin.created_at
    hours_between = time_delta.total_seconds() / 3600
    result['hours_between'] = round(hours_between, 2)
    
    # Handle edge case: same second or very close timestamps
    if hours_between == 0:
        if distance > 10:  # More than 10 miles in same second
            result['is_extreme'] = True
            result['is_impossible'] = True
            result['required_speed_mph'] = float('inf')
            result['reason'] = 'Same-second sign-in from different location'
        return result
    
    # Calculate required travel speed
    required_speed = distance / hours_between
    result['required_speed_mph'] = round(required_speed, 2)
    
    # Check thresholds from config
    impossible_threshold = current_app.config.get('TRAVEL_SPEED_IMPOSSIBLE', 500)
    extreme_threshold = current_app.config.get('TRAVEL_SPEED_EXTREME', 1000)
    
    if required_speed > extreme_threshold:
        result['is_extreme'] = True
        result['is_impossible'] = True
        result['reason'] = (
            f"Extreme impossible travel: {round(required_speed)} mph required "
            f"to travel {round(distance)} miles in {round(hours_between, 1)} hours. "
            f"From {previous_signin.city or 'Unknown'}, {previous_signin.country or 'Unknown'} "
            f"to {current_signin.city or 'Unknown'}, {current_signin.country or 'Unknown'}."
        )
    elif required_speed > impossible_threshold:
        result['is_impossible'] = True
        result['reason'] = (
            f"Impossible travel: {round(required_speed)} mph required "
            f"to travel {round(distance)} miles in {round(hours_between, 1)} hours. "
            f"From {previous_signin.city or 'Unknown'}, {previous_signin.country or 'Unknown'} "
            f"to {current_signin.city or 'Unknown'}, {current_signin.country or 'Unknown'}."
        )
    
    return result


def calculate_signin_risk(signin_event, previous_signin=None):
    """
    Calculate risk score for a Microsoft Entra sign-in event.
    
    Risk signals:
    - New device: +20
    - New country: +20
    - Impossible travel (500-1000 mph): +40
    - Extreme impossible travel (>1000 mph): +70 (changed from +30 to match config)
    - Microsoft risk level medium: +30
    - Microsoft risk level high: +50
    
    Risk levels:
    - 0-29: low
    - 30-59: medium
    - 60-89: high
    - 90+: critical
    
    Args:
        signin_event: EntraSignInEvent object
        previous_signin: Optional previous EntraSignInEvent for impossible travel
    
    Returns:
        Dict with:
            - risk_score: Integer
            - risk_level: String (low, medium, high, critical)
            - risk_reasons: List of reason strings
            - impossible_travel_details: Dict or None
    """
    risk_score = 0
    risk_reasons = []
    impossible_travel_details = None
    
    # Get configuration
    config = current_app.config
    
    # Check for new device
    if signin_event.device_id:
        previous_device_signin = EntraSignInEvent.query.filter(
            EntraSignInEvent.entra_user_id == signin_event.entra_user_id,
            EntraSignInEvent.device_id == signin_event.device_id,
            EntraSignInEvent.created_at < signin_event.created_at,
            EntraSignInEvent.status == 'success'
        ).first()
        
        if not previous_device_signin:
            risk_score += config.get('RISK_SCORE_NEW_DEVICE', 20)
            risk_reasons.append('new_device')
    
    # Check for new country
    if signin_event.country:
        previous_country_signin = EntraSignInEvent.query.filter(
            EntraSignInEvent.entra_user_id == signin_event.entra_user_id,
            EntraSignInEvent.country == signin_event.country,
            EntraSignInEvent.created_at < signin_event.created_at,
            EntraSignInEvent.status == 'success'
        ).first()
        
        if not previous_country_signin:
            risk_score += config.get('RISK_SCORE_NEW_COUNTRY', 20)
            risk_reasons.append('new_country')
    
    # Check for impossible travel
    if previous_signin:
        travel_analysis = detect_impossible_travel(previous_signin, signin_event)
        
        if travel_analysis['is_extreme']:
            risk_score += config.get('RISK_SCORE_EXTREME_TRAVEL', 70)
            risk_reasons.append('extreme_impossible_travel')
            impossible_travel_details = travel_analysis
        elif travel_analysis['is_impossible']:
            risk_score += config.get('RISK_SCORE_IMPOSSIBLE_TRAVEL', 40)
            risk_reasons.append('impossible_travel')
            impossible_travel_details = travel_analysis
    
    # Check Microsoft's risk assessment
    microsoft_risk = (signin_event.risk_level_aggregated or '').lower()
    if microsoft_risk == 'medium':
        risk_score += config.get('RISK_SCORE_MICROSOFT_MEDIUM', 30)
        risk_reasons.append('microsoft_risk_medium')
    elif microsoft_risk == 'high':
        risk_score += config.get('RISK_SCORE_MICROSOFT_HIGH', 50)
        risk_reasons.append('microsoft_risk_high')
    
    # Determine risk level
    risk_level = get_risk_level(risk_score)
    
    return {
        'risk_score': risk_score,
        'risk_level': risk_level,
        'risk_reasons': risk_reasons,
        'impossible_travel_details': impossible_travel_details
    }


def get_risk_level(risk_score):
    """
    Convert numeric risk score to risk level category.
    
    Args:
        risk_score: Integer risk score
    
    Returns:
        String: 'low', 'medium', 'high', or 'critical'
    """
    config = current_app.config
    
    if risk_score >= config.get('RISK_THRESHOLD_CRITICAL_BLOCK', 90):
        return 'critical'
    elif risk_score >= config.get('RISK_THRESHOLD_HIGH', 60):
        return 'high'
    elif risk_score >= config.get('RISK_THRESHOLD_MEDIUM', 30):
        return 'medium'
    else:
        return 'low'


def get_previous_successful_signin(entra_user_id, before_datetime=None):
    """
    Get the most recent successful sign-in for a user before a given time.
    
    Args:
        entra_user_id: Entra user ID
        before_datetime: Only consider sign-ins before this time (default: now)
    
    Returns:
        EntraSignInEvent object or None
    """
    query = EntraSignInEvent.query.filter(
        EntraSignInEvent.entra_user_id == entra_user_id,
        EntraSignInEvent.status == 'success'
    )
    
    if before_datetime:
        query = query.filter(EntraSignInEvent.created_at < before_datetime)
    
    return query.order_by(EntraSignInEvent.created_at.desc()).first()


def analyze_and_update_signin_risk(signin_event):
    """
    Analyze a sign-in event and update its risk fields.
    Also updates the user's overall risk state.
    
    Args:
        signin_event: EntraSignInEvent object
    
    Returns:
        Dict with risk assessment
    """
    # Get previous successful sign-in for impossible travel detection
    previous_signin = get_previous_successful_signin(
        signin_event.entra_user_id,
        before_datetime=signin_event.created_at
    )
    
    # Calculate risk
    risk_assessment = calculate_signin_risk(signin_event, previous_signin)
    
    # Update sign-in event with risk information
    signin_event.local_risk_score = risk_assessment['risk_score']
    signin_event.local_risk_level = risk_assessment['risk_level']
    signin_event.local_risk_reasons = json.dumps(risk_assessment['risk_reasons'])
    
    if risk_assessment['impossible_travel_details']:
        signin_event.impossible_travel_detected = True
        signin_event.required_travel_speed_mph = risk_assessment['impossible_travel_details']['required_speed_mph']
    
    # Update user risk state
    update_user_risk_state(
        signin_event.entra_user_id,
        signin_event.user_principal_name,
        risk_assessment
    )
    
    try:
        db.session.commit()
        current_app.logger.info(
            f"Analyzed sign-in risk for {signin_event.user_principal_name}: "
            f"score={risk_assessment['risk_score']}, level={risk_assessment['risk_level']}"
        )
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Failed to update sign-in risk: {e}")
    
    return risk_assessment


def update_user_risk_state(entra_user_id, user_principal_name, risk_assessment):
    """
    Update the user's overall risk state based on a risk assessment.
    
    Args:
        entra_user_id: Entra user ID
        user_principal_name: User principal name
        risk_assessment: Dict with risk_score, risk_level, risk_reasons
    """
    # Get or create user risk state
    risk_state = UserRiskState.query.filter_by(entra_user_id=entra_user_id).first()
    
    if not risk_state:
        risk_state = UserRiskState(
            entra_user_id=entra_user_id,
            user_principal_name=user_principal_name
        )
        db.session.add(risk_state)
    
    # Update with latest risk assessment
    risk_state.current_risk_score = risk_assessment['risk_score']
    risk_state.current_risk_level = risk_assessment['risk_level']
    risk_state.reasons = json.dumps(risk_assessment['risk_reasons'])
    risk_state.updated_at = datetime.utcnow()
    
    # Update timestamps for specific events
    if risk_assessment['risk_score'] >= 30:
        risk_state.last_risky_signin_at = datetime.utcnow()
    
    if 'impossible_travel' in risk_assessment['risk_reasons'] or \
       'extreme_impossible_travel' in risk_assessment['risk_reasons']:
        risk_state.last_impossible_login_at = datetime.utcnow()
    
    current_app.logger.debug(
        f"Updated risk state for {user_principal_name}: "
        f"score={risk_assessment['risk_score']}, level={risk_assessment['risk_level']}"
    )
