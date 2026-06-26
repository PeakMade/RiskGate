"""
Utility functions for IP handling, geolocation, device fingerprinting, and notifications.
"""
import hashlib
from user_agents import parse


def get_ip_address(request):
    """
    Extract the client's IP address from the request.
    Handles proxies and load balancers by checking X-Forwarded-For header.
    
    Args:
        request: Flask request object
    
    Returns:
        String IP address
    """
    # Check for proxy headers first
    if request.headers.get('X-Forwarded-For'):
        # X-Forwarded-For can contain multiple IPs, get the first (client)
        ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        ip = request.headers.get('X-Real-IP')
    else:
        ip = request.remote_addr
    
    return ip


def get_geolocation(ip_address):
    """
    Get geographic location information from an IP address.
    
    PLACEHOLDER IMPLEMENTATION:
    This currently returns mock data for development.
    In production, integrate with a real IP geolocation service like:
    - MaxMind GeoIP2
    - IP2Location
    - ipapi.co
    - ipinfo.io
    
    Args:
        ip_address: String IP address
    
    Returns:
        Dict with keys: country, city, latitude, longitude
    """
    # TODO: Replace with real geolocation service
    # Example with ipapi.co:
    # import requests
    # response = requests.get(f'https://ipapi.co/{ip_address}/json/')
    # data = response.json()
    # return {
    #     'country': data.get('country_name'),
    #     'city': data.get('city'),
    #     'latitude': data.get('latitude'),
    #     'longitude': data.get('longitude')
    # }
    
    # Mock data for development
    # Different IPs get different mock locations for testing
    mock_locations = {
        '127.0.0.1': {
            'country': 'United States',
            'city': 'New York',
            'latitude': 40.7128,
            'longitude': -74.0060
        },
        'default': {
            'country': 'United States',
            'city': 'San Francisco',
            'latitude': 37.7749,
            'longitude': -122.4194
        }
    }
    
    return mock_locations.get(ip_address, mock_locations['default'])


def get_device_fingerprint(request):
    """
    Generate a device fingerprint from request headers.
    Combines User-Agent, Accept headers, and other browser characteristics.
    
    Note: This is a simple fingerprint. For production, consider:
    - Client-side JavaScript fingerprinting (Canvas, WebGL, fonts)
    - FingerprintJS or similar libraries
    - More sophisticated server-side analysis
    
    Args:
        request: Flask request object
    
    Returns:
        String device fingerprint (hash)
    """
    # Gather fingerprint components
    components = [
        request.headers.get('User-Agent', ''),
        request.headers.get('Accept-Language', ''),
        request.headers.get('Accept-Encoding', ''),
        request.headers.get('Accept', ''),
    ]
    
    # Combine and hash
    fingerprint_string = '|'.join(components)
    fingerprint_hash = hashlib.sha256(fingerprint_string.encode()).hexdigest()
    
    return fingerprint_hash


def parse_user_agent(user_agent_string):
    """
    Parse a User-Agent string to extract browser and OS information.
    
    Args:
        user_agent_string: String User-Agent header value
    
    Returns:
        Dict with keys: browser, os, device
    """
    if not user_agent_string:
        return {
            'browser': 'Unknown',
            'os': 'Unknown',
            'device': 'Unknown'
        }
    
    # Parse using user-agents library
    user_agent = parse(user_agent_string)
    
    return {
        'browser': f"{user_agent.browser.family} {user_agent.browser.version_string}",
        'os': f"{user_agent.os.family} {user_agent.os.version_string}",
        'device': user_agent.device.family
    }


def notify_existing_trusted_channels(user):
    """
    Send notification to user's existing trusted communication channels.
    Used when MFA is being added or modified to alert the user.
    
    PLACEHOLDER IMPLEMENTATION:
    In production, this should send notifications via:
    - Email to verified email addresses
    - SMS to verified phone numbers
    - Push notifications to trusted devices
    - In-app notifications
    
    Args:
        user: User object
    
    Returns:
        Boolean indicating if notification was sent
    """
    # TODO: Implement real notification system
    # Example structure:
    # - Check user's verified email
    # - Send email with security alert
    # - Include details: what changed, when, from where
    # - Provide link to review and reverse if unauthorized
    
    print(f"[NOTIFICATION] User {user.email}: MFA change detected. Review your security settings.")
    return True


def require_password_reentry(user):
    """
    Require the user to re-enter their password for sensitive operations.
    
    PLACEHOLDER IMPLEMENTATION:
    In production, this should:
    - Present a password re-entry form
    - Verify the password matches
    - Only proceed if verification succeeds
    
    Args:
        user: User object
    
    Returns:
        Boolean indicating if password was verified
    """
    # TODO: Implement actual password re-entry flow
    # This would typically involve:
    # - Redirecting to a password confirmation page
    # - Storing the intended action in session
    # - Verifying password
    # - Proceeding with original action if verified
    
    print(f"[SECURITY] Password re-entry required for user {user.email}")
    return True  # Mock approval


def require_existing_mfa(user):
    """
    Require verification with an existing MFA method before allowing changes.
    
    PLACEHOLDER IMPLEMENTATION:
    In production, this should:
    - Check if user has any active MFA methods
    - Prompt for MFA verification
    - Only proceed if verification succeeds
    
    Args:
        user: User object
    
    Returns:
        Boolean indicating if MFA was verified
    """
    # TODO: Implement actual MFA verification flow
    # This would typically involve:
    # - Finding user's active MFA methods
    # - Presenting appropriate verification challenge (TOTP code, SMS, etc.)
    # - Verifying the response
    # - Proceeding only if verification succeeds
    
    from app.models import MfaMethod
    active_mfa = MfaMethod.query.filter_by(user_id=user.id, status='active').first()
    
    if active_mfa:
        print(f"[SECURITY] MFA verification required for user {user.email}")
        return True  # Mock approval
    
    return False  # No MFA to verify with


def create_sample_locations():
    """
    Helper function to create sample geographic locations for testing.
    Returns a list of locations with varying distances for impossible travel testing.
    
    Returns:
        List of dicts with location data
    """
    return [
        {
            'name': 'New York, USA',
            'country': 'United States',
            'city': 'New York',
            'latitude': 40.7128,
            'longitude': -74.0060
        },
        {
            'name': 'London, UK',
            'country': 'United Kingdom',
            'city': 'London',
            'latitude': 51.5074,
            'longitude': -0.1278
        },
        {
            'name': 'Tokyo, Japan',
            'country': 'Japan',
            'city': 'Tokyo',
            'latitude': 35.6762,
            'longitude': 139.6503
        },
        {
            'name': 'Sydney, Australia',
            'country': 'Australia',
            'city': 'Sydney',
            'latitude': -33.8688,
            'longitude': 151.2093
        },
        {
            'name': 'San Francisco, USA',
            'country': 'United States',
            'city': 'San Francisco',
            'latitude': 37.7749,
            'longitude': -122.4194
        },
        {
            'name': 'Moscow, Russia',
            'country': 'Russia',
            'city': 'Moscow',
            'latitude': 55.7558,
            'longitude': 37.6173
        }
    ]
