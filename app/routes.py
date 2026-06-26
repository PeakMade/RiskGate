"""
Application routes for demonstration and testing.
Includes login simulation, MFA management, and security event viewing.
"""
from flask import Blueprint, render_template, request, session, redirect, url_for, abort
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


@bp.route('/', methods=['GET', 'POST'])
@bp.route('/login-demo', methods=['GET', 'POST'])
def login_demo():
    """
    Demonstration login route.
    Simulates login from different locations to trigger risk detection.
    """
    messages = []
    locations = create_sample_locations()
    
    if request.method == 'POST':
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
                <strong>Login Successful!</strong><br>
                Location: {selected_location['name']}<br>
                Risk Score: {risk_assessment['risk_score']} ({risk_assessment['risk_level']})<br>
                Risk Reasons: {', '.join(risk_assessment.get('risk_reasons', ['none']))}
            """
        })
    
    session_risk = get_current_session_risk()
    
    return render_template(
        'login.html',
        messages=messages,
        locations=locations,
        session_risk=session_risk
    )


@bp.route('/logout')
@login_required
def logout():
    """Logout the current user and clear session risk."""
    clear_session_risk()
    logout_user()
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
