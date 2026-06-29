"""
Application routes for demonstration and testing.
Includes login simulation, MFA management, and security event viewing.
"""
from flask import Blueprint, render_template, request, session, redirect, url_for, abort, current_app
from flask_login import login_user, logout_user, login_required, current_user
from datetime import datetime
from app import db
from app.models import User, LoginEvent, MfaMethod, MfaEvent, SecurityAlert
from app.auth_hooks import after_login_attempt, clear_session_risk, get_current_session_risk, is_app_access_blocked
from app.mfa_protection import require_trusted_session_for_mfa_change, can_remove_mfa, \
    create_pending_mfa_method, remove_mfa_method
from app.security_events import get_recent_security_alerts, get_recent_login_events, \
    get_recent_mfa_events
from app.utils import get_ip_address, get_device_fingerprint, create_sample_locations

bp = Blueprint('main', __name__)


@bp.before_request
def check_critical_risk():
    """
    Check if the current session has critical risk that blocks app access.
    Runs before every request to protected routes.
    """
    # Skip check for login and logout routes
    if request.endpoint in ['main.login_demo', 'main.logout', None]:
        return
    
    # Check if user is logged in
    if current_user.is_authenticated:
        blocked, reason = is_app_access_blocked()
        if blocked:
            # Render blocked access page
            return render_template('blocked.html', 
                                 reason=reason,
                                 risk_score=session.get('risk_score', 0))


@bp.route('/', methods=['GET'])
@bp.route('/login-demo', methods=['GET'])
def login_demo():
    """
    Main login page - Microsoft authentication and simulation.
    """
    messages = []
    session_risk = get_current_session_risk()
    
    return render_template(
        'login.html',
        messages=messages,
        session_risk=session_risk
    )


@bp.route('/simulate-login', methods=['POST'])
def simulate_login():
    """
    Simulate a login from a specific location for testing.
    """
    messages = []
    locations = create_sample_locations()
    
    email = request.form.get('email')
    location_index = int(request.form.get('location', 0))
    
    # Get or create test user
    user = User.query.filter_by(email=email).first()
    if not user:
        user = User(email=email, role='user')
        user.set_password('password123')
        db.session.add(user)
        db.session.commit()
        messages.append({
            'type': 'alert-success',
            'text': f'Created new test user: {email}'
        })
    
    # Override geolocation for this simulated login
    selected_location = locations[location_index]
    
    # Temporarily store selected location in session for the hooks to use
    session['simulated_location'] = selected_location
    
    # Log the user in
    login_user(user, remember=True)
    
    # Run post-login security checks
    risk_assessment = after_login_attempt(user, success=True)
    
    # Clear simulated location
    session.pop('simulated_location', None)
    
    # Show risk assessment
    if risk_assessment['risk_score'] >= 60:
        alert_type = 'alert-danger'
    elif risk_assessment['risk_score'] >= 30:
        alert_type = 'alert-warning'
    else:
        alert_type = 'alert-success'
    
    messages.append({
        'type': alert_type,
        'text': f"""
            <strong>Simulation Complete!</strong><br>
            Location: {selected_location['name']}<br>
            Risk Score: {risk_assessment['risk_score']} ({risk_assessment['risk_level']})<br>
            Risk Reasons: {', '.join(risk_assessment.get('risk_reasons', ['none']))}
        """
    })
    
    session_risk = get_current_session_risk()
    
    return render_template(
        'login.html',
        messages=messages,
        session_risk=session_risk
    )


@bp.route('/logout')
@login_required
def logout():
    """Logout the current user and clear session risk."""
    from app.msal_auth import clear_msal_session
    clear_session_risk()
    clear_msal_session()
    logout_user()
    return redirect(url_for('main.login_demo'))


@bp.route('/auth/login')
def auth_login():
    """
    Initiate Microsoft/Entra ID authentication flow.
    """
    from app.msal_auth import get_auth_url
    
    auth_data = get_auth_url()
    return redirect(auth_data['auth_url'])


@bp.route('/auth/callback')
def auth_callback():
    """
    OAuth 2.0 callback handler for Microsoft authentication.
    Called by Microsoft after user completes sign-in.
    """
    from app.msal_auth import complete_auth_flow
    
    # Get the authorization response from query parameters
    auth_response = request.args.to_dict()
    
    # Complete the authentication flow
    user_claims = complete_auth_flow(auth_response)
    
    if not user_claims:
        messages = [{'type': 'alert-danger', 'text': 'Microsoft authentication failed. Please try again.'}]
        return render_template('login.html', 
                             messages=messages, 
                             locations=create_sample_locations(),
                             session_risk=get_current_session_risk())
    
    # Get or create user from Microsoft claims
    email = user_claims.get('preferred_username') or user_claims.get('email')
    name = user_claims.get('name', email)
    entra_user_id = user_claims.get('oid')  # Object ID from Entra ID
    
    # Find or create user
    user = User.query.filter_by(email=email).first()
    if not user:
        user = User(
            email=email, 
            role='user',
            entra_user_id=entra_user_id,
            auth_method='msal'
        )
        user.set_password('msal-auth-no-password')  # Not used for MSAL users
        db.session.add(user)
        db.session.commit()
    else:
        # Update existing user with Entra ID
        if not user.entra_user_id:
            user.entra_user_id = entra_user_id
            user.auth_method = 'msal' if user.auth_method == 'local' else 'both'
            db.session.commit()
    
    # Store Entra ID info in session
    session['entra_user_id'] = entra_user_id
    session['entra_user_name'] = name
    
    # Log the user in
    login_user(user, remember=True)
    
    # Run post-login security checks (risk analysis)
    risk_assessment = after_login_attempt(user, success=True)
    
    # Redirect to main page
    return redirect(url_for('main.login_demo'))


@bp.route('/mfa/add', methods=['GET', 'POST'])
@login_required
def mfa_add():
    """
    Attempt to add a new MFA method.
    Demonstrates MFA protection - blocks if session is risky.
    """
    content = ''
    
    if request.method == 'POST':
        method_type = request.form.get('method_type', 'totp')
        
        # Check if session is trusted enough for MFA change
        check_result = require_trusted_session_for_mfa_change(current_user)
        
        if not check_result['allowed']:
            # Blocked!
            content += f"""
            <div class="alert alert-danger">
                <h3><i class="fas fa-ban me-2"></i>MFA Creation Blocked</h3>
                <p><strong>Reason:</strong> {check_result['reason']}</p>
                <p>This attempt has been logged and a security alert has been created.</p>
            </div>
            """
        else:
            # Allowed - create pending MFA method
            ip_address = get_ip_address(request)
            device_fingerprint = get_device_fingerprint(request)
            
            mfa_method = create_pending_mfa_method(
                user=current_user,
                method_type=method_type,
                ip_address=ip_address,
                device_fingerprint=device_fingerprint
            )
            
            content += f"""
            <div class="alert alert-success">
                <h3><i class="fas fa-check-circle me-2"></i>MFA Method Created</h3>
                <p><strong>Type:</strong> {method_type}</p>
                <p><strong>Status:</strong> {mfa_method.status}</p>
                <p><strong>Trusted After:</strong> {mfa_method.trusted_after}</p>
                <p>This MFA method will be fully trusted in 24 hours.</p>
            </div>
            """
    
    # Show current session risk
    session_risk = get_current_session_risk()
    content += f"""
    <div class="alert alert-info">
        <p><strong>Current Session Risk:</strong> {session_risk['risk_score']} ({session_risk['risk_level']})</p>
        <p>MFA creation is blocked if risk score is 60 or higher, or if there are active security alerts.</p>
    </div>
    """
    
    # MFA creation form
    content += """
    <form method="POST">
        <div class="mb-3">
            <label class="form-label fw-bold">MFA Method Type:</label>
            <select name="method_type" class="form-select">
                <option value="totp">TOTP (Authenticator App)</option>
                <option value="sms">SMS</option>
                <option value="hardware_key">Hardware Key</option>
                <option value="backup_codes">Backup Codes</option>
            </select>
        </div>
        <button type="submit" class="btn btn-primary"><i class="fas fa-plus me-2"></i>Add MFA Method</button>
    </form>
    """
    
    # Show user's existing MFA methods
    mfa_methods = MfaMethod.query.filter_by(user_id=current_user.id).all()
    if mfa_methods:
        content += '<h3 class="mt-4">Your MFA Methods</h3><table class="table table-striped">'
        content += '<thead><tr><th>Type</th><th>Status</th><th>Created</th><th>Trusted After</th><th>Actions</th></tr></thead><tbody>'
        for mfa in mfa_methods:
            trusted = '✅ Yes' if mfa.is_fully_trusted() else '⏳ Pending'
            content += f"""
            <tr>
                <td>{mfa.method_type}</td>
                <td><span class="badge badge-info">{mfa.status}</span></td>
                <td>{mfa.created_at.strftime('%Y-%m-%d %H:%M')}</td>
                <td>{mfa.trusted_after.strftime('%Y-%m-%d %H:%M') if mfa.trusted_after else 'N/A'} {trusted}</td>
                <td><a href="{url_for('main.mfa_remove', mfa_id=mfa.id)}"><button class="btn btn-sm btn-danger">Remove</button></a></td>
            </tr>
            """
        content += '</tbody></table>'
    
    return render_template('mfa_add.html', title='Add MFA', content=content, session_risk=get_current_session_risk())


@bp.route('/mfa/remove/<int:mfa_id>')
@login_required
def mfa_remove(mfa_id):
    """
    Attempt to remove an MFA method.
    Demonstrates MFA protection - blocks if session is risky or method is not trusted.
    """
    mfa_method = MfaMethod.query.get_or_404(mfa_id)
    
    # Verify ownership
    if mfa_method.user_id != current_user.id:
        content = '<div class="alert alert-danger">Access denied.</div>'
    else:
        # Attempt removal
        result = remove_mfa_method(current_user, mfa_method)
        
        if result['success']:
            content = f"""
            <div class="alert alert-success">
                <h3><i class="fas fa-check-circle me-2"></i>MFA Method Removed</h3>
                <p>{result['message']}</p>
            </div>
            """
        else:
            content = f"""
            <div class="alert alert-danger">
                <h3><i class="fas fa-ban me-2"></i>MFA Removal Blocked</h3>
                <p><strong>Reason:</strong> {result['message']}</p>
                <p>This attempt has been logged.</p>
            </div>
            """
    
    content += '<p><a href="' + url_for('main.mfa_add') + '"><button class="btn btn-primary">Back to MFA Management</button></a></p>'
    
    return render_template('dashboard.html', title='Remove MFA', content=content, session_risk=get_current_session_risk())


@bp.route('/alerts')
@login_required
def alerts():
    """Display security alerts for the current user."""
    security_alerts = SecurityAlert.query.filter_by(
        user_id=current_user.id
    ).order_by(SecurityAlert.created_at.desc()).limit(50).all()
    
    content = '<div class="card"><div class="card-header"><i class="fas fa-exclamation-triangle me-2"></i>Security Alerts</div><div class="card-body">'
    
    if not security_alerts:
        content += '<p>No security alerts found.</p>'
    else:
        content += '<table class="table table-striped">'
        content += '<thead><tr><th>Type</th><th>Severity</th><th>Reason</th><th>Status</th><th>Created</th></tr></thead><tbody>'
        
        for alert in security_alerts:
            severity_class = {
                'low': 'badge-info',
                'medium': 'badge-warning',
                'high': 'badge-danger',
                'critical': 'badge-danger'
            }.get(alert.severity, 'badge-info')
            
            status_class = {
                'active': 'badge-danger',
                'acknowledged': 'badge-warning',
                'resolved': 'badge-success',
                'false_positive': 'badge-info'
            }.get(alert.status, 'badge-info')
            
            content += f"""
            <tr>
                <td>{alert.alert_type}</td>
                <td><span class="badge {severity_class}">{alert.severity}</span></td>
                <td>{alert.reason}</td>
                <td><span class="badge {status_class}">{alert.status}</span></td>
                <td>{alert.created_at.strftime('%Y-%m-%d %H:%M:%S')}</td>
            </tr>
            """
        
        content += '</tbody></table>'
    
    content += '</div></div>'
    
    return render_template('dashboard.html', title='Security Alerts', content=content, session_risk=get_current_session_risk())


@bp.route('/login-events')
@login_required
def login_events():
    """Display login events for the current user."""
    events = LoginEvent.query.filter_by(
        user_id=current_user.id
    ).order_by(LoginEvent.timestamp.desc()).limit(50).all()
    
    content = '<div class="card"><div class="card-header"><i class="fas fa-history me-2"></i>Login Events</div><div class="card-body">'
    
    if not events:
        content += '<p>No login events found.</p>'
    else:
        content += '<table class="table table-striped">'
        content += '<thead><tr><th>Time</th><th>Success</th><th>Location</th><th>IP</th><th>Risk Score</th><th>Risk Reasons</th></tr></thead><tbody>'
        
        for event in events:
            success_badge = '<span class="badge badge-success">✓</span>' if event.success else '<span class="badge badge-danger">✗</span>'
            location = f"{event.city}, {event.country}" if event.city and event.country else 'Unknown'
            
            risk_class = 'badge-success'
            if event.risk_score >= 60:
                risk_class = 'badge-danger'
            elif event.risk_score >= 30:
                risk_class = 'badge-warning'
            
            content += f"""
            <tr>
                <td>{event.timestamp.strftime('%Y-%m-%d %H:%M:%S')}</td>
                <td>{success_badge}</td>
                <td>{location}</td>
                <td>{event.ip_address}</td>
                <td><span class="badge {risk_class}">{event.risk_score}</span></td>
                <td>{event.risk_reason or 'none'}</td>
            </tr>
            """
        
        content += '</tbody></table>'
    
    content += '</div></div>'
    
    return render_template('dashboard.html', title='Login Events', content=content, session_risk=get_current_session_risk())


@bp.route('/mfa-events')
@login_required
def mfa_events():
    """Display MFA events for the current user."""
    events = MfaEvent.query.filter_by(
        user_id=current_user.id
    ).order_by(MfaEvent.timestamp.desc()).limit(50).all()
    
    content = '<div class="card"><div class="card-header"><i class="fas fa-list me-2"></i>MFA Events</div><div class="card-body">'
    
    if not events:
        content += '<p>No MFA events found.</p>'
    else:
        content += '<table class="table table-striped">'
        content += '<thead><tr><th>Time</th><th>Type</th><th>Blocked</th><th>Location</th><th>Risk Score</th><th>Reason</th></tr></thead><tbody>'
        
        for event in events:
            blocked_badge = '<span class="badge badge-danger">BLOCKED</span>' if event.blocked else '<span class="badge badge-success">ALLOWED</span>'
            location = f"{event.city}, {event.country}" if event.city and event.country else 'Unknown'
            
            content += f"""
            <tr>
                <td>{event.timestamp.strftime('%Y-%m-%d %H:%M:%S')}</td>
                <td>{event.event_type}</td>
                <td>{blocked_badge}</td>
                <td>{location}</td>
                <td>{event.session_risk_score}</td>
                <td>{event.reason}</td>
            </tr>
            """
        
        content += '</tbody></table>'
    
    content += '</div></div>'
    
    return render_template('dashboard.html', title='MFA Events', content=content, session_risk=get_current_session_risk())


@bp.route('/breach-detection')
@login_required
def breach_detection():
    """
    Dashboard showing breach detection patterns:
    - Cross-user impossible travel patterns
    - Risky logins followed by MFA creation
    - Account takeover indicators
    """
    from app.risk import detect_cross_user_breach_patterns, get_all_users_with_risky_mfa_correlation
    
    content = '<h2><i class="fas fa-shield-virus me-2"></i>Breach Detection Dashboard</h2>'
    
    # Cross-user breach patterns
    breach_analysis = detect_cross_user_breach_patterns(hours=24)
    
    severity_class = {
        'low': 'alert-info',
        'medium': 'alert-warning',
        'high': 'alert-danger',
        'critical': 'alert-danger'
    }.get(breach_analysis['severity'], 'alert-info')
    
    content += f"""
    <div class="card mb-4">
        <div class="card-header bg-danger text-white">
            <h5 class="mb-0"><i class="fas fa-users-slash me-2"></i>Cross-User Impossible Travel Detection</h5>
        </div>
        <div class="card-body">
            <div class="alert {severity_class}">
                <h5><strong>{breach_analysis['reason']}</strong></h5>
                <p><strong>Affected Users:</strong> {breach_analysis['affected_users_count']}</p>
                <p><strong>Time Window:</strong> Last {breach_analysis['time_window_hours']} hours</p>
                <p><strong>Breach Likely:</strong> {"🚨 YES" if breach_analysis['is_breach_likely'] else "✅ No"}</p>
            </div>
    """
    
    if breach_analysis['affected_user_ids']:
        from app.models import User
        content += '<h6>Affected Users:</h6><ul>'
        for user_id in breach_analysis['affected_user_ids']:
            user = User.query.get(user_id)
            content += f'<li>User ID {user_id}: {user.email if user else "Unknown"}</li>'
        content += '</ul>'
    
    content += '</div></div>'
    
    # MFA creation after risky login correlation
    correlations = get_all_users_with_risky_mfa_correlation(hours=24)
    
    content += f"""
    <div class="card mb-4">
        <div class="card-header bg-warning text-dark">
            <h5 class="mb-0"><i class="fas fa-user-lock me-2"></i>Risky Login → MFA Creation Correlation</h5>
        </div>
        <div class="card-body">
            <p class="text-muted">Detects when users create MFA methods shortly after impossible travel - a key indicator of account takeover.</p>
    """
    
    if not correlations:
        content += '<div class="alert alert-success">✅ No suspicious MFA creation patterns detected in last 24 hours.</div>'
    else:
        content += f'<div class="alert alert-danger">🚨 Found {len(correlations)} suspicious MFA creation(s) after risky logins!</div>'
        content += '<table class="table table-striped">'
        content += '<thead><tr><th>User</th><th>Risk Score</th><th>Login Location</th><th>Login Time</th><th>MFA Created</th><th>Time Gap</th></tr></thead><tbody>'
        
        for corr in correlations:
            login = corr['risky_login']
            location = f"{login.city}, {login.country}" if login.city else 'Unknown'
            mfa_count = len(corr['mfa_events'])
            
            content += f"""
            <tr class="table-danger">
                <td><strong>{corr['user_email']}</strong></td>
                <td><span class="badge badge-danger">{corr['risk_score']}</span></td>
                <td>{location}</td>
                <td>{login.timestamp.strftime('%Y-%m-%d %H:%M:%S')}</td>
                <td>{mfa_count} MFA method(s)</td>
                <td><strong>{corr['time_between_minutes']:.1f} min</strong></td>
            </tr>
            """
        
        content += '</tbody></table>'
    
    content += '</div></div>'
    
    # Current user's risk analysis
    from app.risk import get_mfa_creation_after_risky_login
    user_correlation = get_mfa_creation_after_risky_login(current_user.id, hours=1)
    
    content += f"""
    <div class="card">
        <div class="card-header bg-info text-white">
            <h5 class="mb-0"><i class="fas fa-user-shield me-2"></i>Your Account Analysis</h5>
        </div>
        <div class="card-body">
    """
    
    if user_correlation['correlation_found']:
        suspicious_text = '🚨 SUSPICIOUS' if user_correlation['is_suspicious'] else '⚠️ Flagged'
        content += f"""
        <div class="alert alert-{'danger' if user_correlation['is_suspicious'] else 'warning'}">
            <h5>{suspicious_text}: Risky login followed by MFA creation</h5>
            <p><strong>Risky Login:</strong> {user_correlation['risky_login'].timestamp.strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>MFA Created:</strong> {len(user_correlation['mfa_events'])} method(s)</p>
            <p><strong>Time Between:</strong> {user_correlation['time_between_minutes']:.1f} minutes</p>
        </div>
        """
    else:
        content += '<div class="alert alert-success">✅ No suspicious patterns detected for your account.</div>'
    
    content += '</div></div>'
    
    return render_template('dashboard.html', title='Breach Detection', content=content, session_risk=get_current_session_risk())


@bp.route('/mfa-test-lab', methods=['GET'])
@login_required
def mfa_test_lab():
    """
    MFA Detection Test Lab - Interface for testing different MFA scenarios.
    """
    return render_template('mfa_test_lab.html', title='MFA Test Lab', test_results=None)


@bp.route('/test/normal-mfa', methods=['POST'])
@login_required
def test_normal_mfa():
    """Test Scenario 1: Normal MFA addition (should create LOW alert)."""
    from app.models_new import UserIdentity, EntraSignInEvent, EntraMfaEvent
    from app.ingest import process_mfa_events_for_alerts
    from datetime import timedelta
    
    email = request.form.get('email', 'testuser@example.com')
    mfa_type = request.form.get('mfa_type', 'totp')
    
    test_results = {
        'success': True,
        'scenario': 'Normal MFA Addition',
        'steps': [],
        'alerts': []
    }
    
    try:
        # Step 1: Get or create user
        user = UserIdentity.query.filter_by(user_principal_name=email).first()
        if not user:
            user = UserIdentity(
                entra_user_id=f"test-{email}",
                user_principal_name=email,
                display_name=email.split('@')[0].title()
            )
            db.session.add(user)
            db.session.commit()
        
        test_results['steps'].append({
            'icon': 'user',
            'description': f'Created/found test user: {email}'
        })
        
        # Step 2: Create normal sign-in from safe location (2 hours ago)
        signin_time = datetime.utcnow() - timedelta(hours=2)
        signin = EntraSignInEvent(
            microsoft_event_id=f"signin-normal-{datetime.utcnow().timestamp()}",
            entra_user_id=user.entra_user_id,
            user_principal_name=email,
            created_at=signin_time,
            ip_address="203.0.113.10",
            country="United States",
            city="New York",
            latitude=40.7128,
            longitude=-74.0060,
            status="success",
            local_risk_score=10,
            local_risk_level="low"
        )
        db.session.add(signin)
        db.session.commit()
        
        test_results['steps'].append({
            'icon': 'sign-in-alt',
            'description': f'Created normal sign-in from New York (2 hours ago, risk score: 10)'
        })
        
        # Step 3: Create MFA registration event (now)
        mfa_event = EntraMfaEvent(
            microsoft_event_id=f"mfa-normal-{datetime.utcnow().timestamp()}",
            entra_user_id=user.entra_user_id,
            user_principal_name=email,
            created_at=datetime.utcnow(),
            activity_name="User registered security info",
            operation_type="Add",
            method_type="PhoneAppNotification" if mfa_type == 'totp' else mfa_type,
            initiated_by=email,
            ip_address="203.0.113.10"
        )
        db.session.add(mfa_event)
        db.session.commit()
        
        test_results['steps'].append({
            'icon': 'mobile-alt',
            'description': f'Added {mfa_type.upper()} MFA method'
        })
        
        # Step 4: Process MFA events for alerts
        stats = process_mfa_events_for_alerts(lookback_hours=24)
        
        test_results['steps'].append({
            'icon': 'bell',
            'description': f'Analyzed MFA events: {stats["alerts_created"]} alerts created'
        })
        
        # Get alerts created
        from app.models_new import EntraSecurityAlert
        alerts = EntraSecurityAlert.query.filter_by(
            entra_user_id=user.entra_user_id
        ).order_by(EntraSecurityAlert.created_at.desc()).limit(3).all()
        
        test_results['alerts'] = alerts
        
    except Exception as e:
        test_results['success'] = False
        test_results['error'] = str(e)
        current_app.logger.error(f"Test failed: {e}")
    
    return render_template('mfa_test_lab.html', title='MFA Test Lab', test_results=test_results)


@bp.route('/test/risky-mfa', methods=['POST'])
@login_required
def test_risky_mfa():
    """Test Scenario 2: MFA addition after risky sign-in (should create CRITICAL alert)."""
    from app.models_new import UserIdentity, EntraSignInEvent, EntraMfaEvent
    from app.ingest import process_mfa_events_for_alerts
    from datetime import timedelta
    
    email = request.form.get('email', 'testuser@example.com')
    location = request.form.get('location', 'moscow')
    mfa_type = request.form.get('mfa_type', 'totp')
    
    # Location details
    locations = {
        'moscow': {'city': 'Moscow', 'country': 'Russia', 'lat': 55.7558, 'lon': 37.6173},
        'beijing': {'city': 'Beijing', 'country': 'China', 'lat': 39.9042, 'lon': 116.4074},
        'lagos': {'city': 'Lagos', 'country': 'Nigeria', 'lat': 6.5244, 'lon': 3.3792},
        'sydney': {'city': 'Sydney', 'country': 'Australia', 'lat': -33.8688, 'lon': 151.2093}
    }
    loc = locations.get(location, locations['moscow'])
    
    test_results = {
        'success': True,
        'scenario': 'MFA After Risky Sign-in',
        'steps': [],
        'alerts': []
    }
    
    try:
        # Step 1: Get or create user
        user = UserIdentity.query.filter_by(user_principal_name=email).first()
        if not user:
            user = UserIdentity(
                entra_user_id=f"test-{email}",
                user_principal_name=email,
                display_name=email.split('@')[0].title()
            )
            db.session.add(user)
            db.session.commit()
        
        test_results['steps'].append({
            'icon': 'user',
            'description': f'Created/found test user: {email}'
        })
        
        # Step 2: Create risky sign-in with impossible travel (1 hour ago)
        signin_time = datetime.utcnow() - timedelta(hours=1)
        signin = EntraSignInEvent(
            microsoft_event_id=f"signin-risky-{datetime.utcnow().timestamp()}",
            entra_user_id=user.entra_user_id,
            user_principal_name=email,
            created_at=signin_time,
            ip_address="45.142.212.100",
            country=loc['country'],
            city=loc['city'],
            latitude=loc['lat'],
            longitude=loc['lon'],
            status="success",
            impossible_travel_detected=True,
            required_travel_speed_mph=8500,
            local_risk_score=85,
            local_risk_level="high",
            local_risk_reasons='["Impossible travel detected", "High-risk location"]'
        )
        db.session.add(signin)
        db.session.commit()
        
        test_results['steps'].append({
            'icon': 'plane',
            'description': f'Created risky sign-in from {loc["city"]}, {loc["country"]} (impossible travel: 8500 mph, risk score: 85)'
        })
        
        # Step 3: Create MFA registration 15 minutes after risky sign-in
        mfa_time = signin_time + timedelta(minutes=15)
        mfa_event = EntraMfaEvent(
            microsoft_event_id=f"mfa-risky-{datetime.utcnow().timestamp()}",
            entra_user_id=user.entra_user_id,
            user_principal_name=email,
            created_at=mfa_time,
            activity_name="User registered security info",
            operation_type="Add",
            method_type="PhoneAppNotification" if mfa_type == 'totp' else mfa_type,
            initiated_by=email,
            ip_address="45.142.212.100"
        )
        db.session.add(mfa_event)
        db.session.commit()
        
        test_results['steps'].append({
            'icon': 'mobile-alt',
            'description': f'Added {mfa_type.upper()} MFA method 15 minutes after risky sign-in'
        })
        
        # Step 4: Process MFA events for alerts
        stats = process_mfa_events_for_alerts(lookback_hours=24)
        
        test_results['steps'].append({
            'icon': 'exclamation-triangle',
            'description': f'Detection system analyzed events: {stats["alerts_created"]} CRITICAL alerts expected'
        })
        
        # Get alerts created
        from app.models_new import EntraSecurityAlert
        alerts = EntraSecurityAlert.query.filter_by(
            entra_user_id=user.entra_user_id
        ).order_by(EntraSecurityAlert.created_at.desc()).limit(5).all()
        
        test_results['alerts'] = alerts
        
    except Exception as e:
        test_results['success'] = False
        test_results['error'] = str(e)
        current_app.logger.error(f"Test failed: {e}")
    
    return render_template('mfa_test_lab.html', title='MFA Test Lab', test_results=test_results)


@bp.route('/test/takeover-pattern', methods=['POST'])
@login_required
def test_takeover_pattern():
    """Test Scenario 3: MFA takeover pattern (add then remove)."""
    from app.models_new import UserIdentity, EntraSignInEvent, EntraMfaEvent
    from app.ingest import process_mfa_events_for_alerts
    from datetime import timedelta
    
    email = request.form.get('email', 'testuser@example.com')
    location = request.form.get('location', 'moscow')
    
    locations = {
        'moscow': {'city': 'Moscow', 'country': 'Russia', 'lat': 55.7558, 'lon': 37.6173},
        'beijing': {'city': 'Beijing', 'country': 'China', 'lat': 39.9042, 'lon': 116.4074},
        'lagos': {'city': 'Lagos', 'country': 'Nigeria', 'lat': 6.5244, 'lon': 3.3792}
    }
    loc = locations.get(location, locations['moscow'])
    
    test_results = {
        'success': True,
        'scenario': 'MFA Takeover Pattern',
        'steps': [],
        'alerts': []
    }
    
    try:
        # Step 1: Get or create user
        user = UserIdentity.query.filter_by(user_principal_name=email).first()
        if not user:
            user = UserIdentity(
                entra_user_id=f"test-{email}",
                user_principal_name=email,
                display_name=email.split('@')[0].title()
            )
            db.session.add(user)
            db.session.commit()
        
        test_results['steps'].append({
            'icon': 'user',
            'description': f'Created/found test user: {email}'
        })
        
        # Step 2: Risky sign-in
        signin_time = datetime.utcnow() - timedelta(minutes=30)
        signin = EntraSignInEvent(
            microsoft_event_id=f"signin-takeover-{datetime.utcnow().timestamp()}",
            entra_user_id=user.entra_user_id,
            user_principal_name=email,
            created_at=signin_time,
            ip_address="45.142.212.100",
            country=loc['country'],
            city=loc['city'],
            latitude=loc['lat'],
            longitude=loc['lon'],
            status="success",
            impossible_travel_detected=True,
            required_travel_speed_mph=9000,
            local_risk_score=90,
            local_risk_level="critical",
            local_risk_reasons='["Impossible travel detected", "Extreme speed required"]'
        )
        db.session.add(signin)
        db.session.commit()
        
        test_results['steps'].append({
            'icon': 'plane',
            'description': f'Attacker sign-in from {loc["city"]} (impossible travel)'
        })
        
        # Step 3: Attacker adds their MFA
        mfa_add_time = signin_time + timedelta(minutes=10)
        mfa_add = EntraMfaEvent(
            microsoft_event_id=f"mfa-add-{datetime.utcnow().timestamp()}",
            entra_user_id=user.entra_user_id,
            user_principal_name=email,
            created_at=mfa_add_time,
            activity_name="User registered security info",
            operation_type="Add",
            method_type="PhoneAppNotification",
            initiated_by=email,
            ip_address="45.142.212.100"
        )
        db.session.add(mfa_add)
        db.session.commit()
        
        test_results['steps'].append({
            'icon': 'plus-circle',
            'description': 'Attacker adds their MFA method'
        })
        
        # Step 4: Attacker removes victim's MFA
        mfa_remove_time = mfa_add_time + timedelta(minutes=5)
        mfa_remove = EntraMfaEvent(
            microsoft_event_id=f"mfa-remove-{datetime.utcnow().timestamp()}",
            entra_user_id=user.entra_user_id,
            user_principal_name=email,
            created_at=mfa_remove_time,
            activity_name="User deleted security info",
            operation_type="Delete",
            method_type="PhoneAppNotification",
            initiated_by=email,
            ip_address="45.142.212.100"
        )
        db.session.add(mfa_remove)
        db.session.commit()
        
        test_results['steps'].append({
            'icon': 'minus-circle',
            'description': 'Attacker removes victim\'s original MFA method'
        })
        
        # Step 5: Process for alerts
        stats = process_mfa_events_for_alerts(lookback_hours=24)
        
        test_results['steps'].append({
            'icon': 'user-secret',
            'description': f'Takeover pattern detected: {stats["alerts_created"]} CRITICAL alerts'
        })
        
        # Get alerts
        from app.models_new import EntraSecurityAlert
        alerts = EntraSecurityAlert.query.filter_by(
            entra_user_id=user.entra_user_id
        ).order_by(EntraSecurityAlert.created_at.desc()).limit(5).all()
        
        test_results['alerts'] = alerts
        
    except Exception as e:
        test_results['success'] = False
        test_results['error'] = str(e)
        current_app.logger.error(f"Test failed: {e}")
    
    return render_template('mfa_test_lab.html', title='MFA Test Lab', test_results=test_results)


@bp.route('/test/clear-data', methods=['POST'])
@login_required
def clear_test_data():
    """Clear all test data from the database."""
    from app.models_new import UserIdentity, EntraSignInEvent, EntraMfaEvent, EntraSecurityAlert
    
    try:
        # Delete test data for testuser@example.com
        test_users = UserIdentity.query.filter(
            UserIdentity.user_principal_name.like('%testuser%')
        ).all()
        
        for user in test_users:
            EntraSecurityAlert.query.filter_by(entra_user_id=user.entra_user_id).delete()
            EntraMfaEvent.query.filter_by(entra_user_id=user.entra_user_id).delete()
            EntraSignInEvent.query.filter_by(entra_user_id=user.entra_user_id).delete()
            db.session.delete(user)
        
        db.session.commit()
        current_app.logger.info("Test data cleared successfully")
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Failed to clear test data: {e}")
    
    return redirect(url_for('main.mfa_test_lab'))


# Override geolocation in utils when simulated location is set
from app import utils
_original_get_geolocation = utils.get_geolocation

def patched_get_geolocation(ip_address):
    """Use simulated location if set in session, otherwise use original function."""
    simulated = session.get('simulated_location')
    if simulated:
        return simulated
    return _original_get_geolocation(ip_address)

utils.get_geolocation = patched_get_geolocation
