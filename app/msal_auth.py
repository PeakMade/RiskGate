"""
Microsoft Authentication Library (MSAL) integration for RiskGate.
Handles OAuth 2.0 authentication flow with Microsoft/Entra ID.
"""
import msal
import os
from flask import session, url_for, current_app
from functools import wraps


def get_msal_app():
    """
    Create and configure an MSAL ConfidentialClientApplication.
    
    Returns:
        msal.ConfidentialClientApplication instance
    """
    return msal.ConfidentialClientApplication(
        client_id=current_app.config['AZURE_CLIENT_ID'],
        client_credential=current_app.config['AZURE_CLIENT_SECRET'],
        authority=current_app.config['MSAL_AUTHORITY']
    )


def get_auth_url():
    """
    Generate the Microsoft login authorization URL.
    
    Returns:
        Dict with 'auth_url' and 'state' for CSRF protection
    """
    msal_app = get_msal_app()
    
    # Build redirect URI (must match Azure App Registration)
    # Always use HTTPS (local development uses self-signed cert)
    redirect_uri = url_for('main.auth_callback', _external=True, _scheme='https')
    
    # Generate authorization URL
    auth_result = msal_app.initiate_auth_code_flow(
        scopes=current_app.config['MSAL_SCOPE'],
        redirect_uri=redirect_uri
    )
    
    # Store flow in session for validation in callback
    session['msal_flow'] = auth_result
    
    return {
        'auth_url': auth_result['auth_uri'],
        'state': auth_result.get('state')
    }


def complete_auth_flow(auth_response):
    """
    Complete the OAuth 2.0 authorization code flow.
    
    Args:
        auth_response: Dict containing the authorization response
        
    Returns:
        Dict with user information if successful, None if failed
    """
    # Retrieve the flow from session
    flow = session.get('msal_flow', {})
    
    if not flow:
        print("ERROR: No MSAL flow found in session")
        return None
    
    # Exchange authorization code for access token
    msal_app = get_msal_app()
    
    try:
        print(f"DEBUG: Auth response received: {auth_response}")
        result = msal_app.acquire_token_by_auth_code_flow(
            auth_code_flow=flow,
            auth_response=auth_response
        )
        
        print(f"DEBUG: MSAL result: {result}")
        
        if 'error' in result:
            print(f"ERROR: MSAL authentication failed: {result.get('error')}")
            print(f"ERROR: Error description: {result.get('error_description')}")
            return None
        
        # Extract only essential user claims (don't store full token - too large for session cookie)
        id_token_claims = result.get('id_token_claims', {})
        essential_claims = {
            'oid': id_token_claims.get('oid'),  # Object ID (Entra User ID)
            'preferred_username': id_token_claims.get('preferred_username'),  # Email
            'name': id_token_claims.get('name'),  # Display name
            'email': id_token_claims.get('email')
        }
        
        # Store only essential user info in session (not the full token)
        session['msal_user'] = essential_claims
        
        # Clear the flow from session
        session.pop('msal_flow', None)
        
        print("SUCCESS: MSAL authentication completed")
        return id_token_claims
        
    except Exception as e:
        print(f"ERROR: MSAL auth exception: {e}")
        import traceback
        traceback.print_exc()
        return None


def get_token_from_cache():
    """
    Get access token from session cache or refresh if needed.
    
    Returns:
        Access token string or None
    """
    token_cache = session.get('msal_token', {})
    
    if not token_cache:
        return None
    
    # Check if token is still valid
    accounts = msal.PublicClientApplication(
        client_id=current_app.config['AZURE_CLIENT_ID'],
        authority=current_app.config['MSAL_AUTHORITY']
    ).get_accounts()
    
    if accounts:
        msal_app = get_msal_app()
        result = msal_app.acquire_token_silent(
            scopes=current_app.config['MSAL_SCOPE'],
            account=accounts[0]
        )
        
        if result and 'access_token' in result:
            session['msal_token'] = result
            return result['access_token']
    
    return token_cache.get('access_token')


def get_current_msal_user():
    """
    Get the currently authenticated MSAL user from session.
    
    Returns:
        Dict with user claims or None
    """
    return session.get('msal_user')


def is_authenticated():
    """
    Check if user is authenticated via MSAL.
    
    Returns:
        Boolean
    """
    return 'msal_user' in session


def clear_msal_session():
    """Clear MSAL authentication data from session."""
    session.pop('msal_token', None)
    session.pop('msal_user', None)
    session.pop('msal_flow', None)


def msal_required(f):
    """
    Decorator to require MSAL authentication for a route.
    
    Usage:
        @app.route('/protected')
        @msal_required
        def protected_route():
            return 'This requires Microsoft login'
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_authenticated():
            from flask import redirect, url_for
            return redirect(url_for('main.login_demo'))
        return f(*args, **kwargs)
    return decorated_function
