"""
Database models for RiskGate - Microsoft Entra Identity Monitoring.

RiskGate ingests and correlates Microsoft Entra sign-in logs, audit logs,
and authentication method data to detect account takeover patterns.

Microsoft Entra is the source of truth for authentication.
RiskGate is a monitoring and alerting layer.
"""
from datetime import datetime
from app import db


class UserIdentity(db.Model):
    """
    Represents a user from Microsoft Entra ID.
    Maps to Azure AD users for tracking and correlation.
    """
    __tablename__ = 'user_identity'
    
    id = db.Column(db.Integer, primary_key=True)
    entra_user_id = db.Column(db.String(100), unique=True, nullable=False, index=True)  # Azure AD object ID
    user_principal_name = db.Column(db.String(255), nullable=False, index=True)  # user@domain.com
    display_name = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    sign_in_events = db.relationship('EntraSignInEvent', backref='user', lazy='dynamic')
    mfa_events = db.relationship('EntraMfaEvent', backref='user', lazy='dynamic')
    security_alerts = db.relationship('EntraSecurityAlert', backref='user', lazy='dynamic')
    auth_methods = db.relationship('UserAuthMethodSnapshot', backref='user', lazy='dynamic')
    risk_state = db.relationship('UserRiskState', backref='user', uselist=False)
    
    def __repr__(self):
        return f'<UserIdentity {self.user_principal_name}>'


class EntraSignInEvent(db.Model):
    """
    Represents a sign-in event from Microsoft Entra ID sign-in logs.
    Ingested from Microsoft Graph API.
    
    Includes both Microsoft's risk assessment and local risk analysis.
    """
    __tablename__ = 'entra_signin_event'
    
    id = db.Column(db.Integer, primary_key=True)
    microsoft_event_id = db.Column(db.String(100), unique=True, nullable=False, index=True)  # Prevents duplicates
    entra_user_id = db.Column(db.String(100), db.ForeignKey('user_identity.entra_user_id'), nullable=False, index=True)
    user_principal_name = db.Column(db.String(255), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    # Location data
    ip_address = db.Column(db.String(50))
    country = db.Column(db.String(100), index=True)
    city = db.Column(db.String(100))
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    
    # Device/client data
    browser = db.Column(db.String(100))
    operating_system = db.Column(db.String(100))
    device_id = db.Column(db.String(100), index=True)
    app_display_name = db.Column(db.String(255))
    
    # Microsoft authentication status
    status = db.Column(db.String(50))  # success, failure, interrupted
    mfa_required = db.Column(db.Boolean)
    mfa_satisfied = db.Column(db.Boolean)
    
    # Microsoft risk assessment
    risk_level_aggregated = db.Column(db.String(50))  # none, low, medium, high
    risk_detail = db.Column(db.String(50))  # anonymizedIPAddress, maliciousIP, impossibleTravel, etc.
    conditional_access_status = db.Column(db.String(50))
    
    # Local RiskGate analysis
    local_risk_score = db.Column(db.Integer, default=0, index=True)
    local_risk_level = db.Column(db.String(50), default='low')  # low, medium, high, critical
    local_risk_reasons = db.Column(db.Text)  # JSON array of reasons
    
    # Impossible travel detection
    impossible_travel_detected = db.Column(db.Boolean, default=False, index=True)
    required_travel_speed_mph = db.Column(db.Float)  # Speed required to travel between locations
    
    # Raw data for investigation
    raw_json = db.Column(db.Text)  # Full Microsoft Graph response
    
    def __repr__(self):
        return f'<EntraSignInEvent {self.user_principal_name} at {self.created_at}>'


class EntraMfaEvent(db.Model):
    """
    Represents an MFA/authentication method change from Microsoft Entra audit logs.
    
    These events are critical for detecting account takeover persistence.
    An attacker who successfully logs in often adds their own MFA method.
    """
    __tablename__ = 'entra_mfa_event'
    
    id = db.Column(db.Integer, primary_key=True)
    microsoft_event_id = db.Column(db.String(100), unique=True, nullable=False, index=True)
    entra_user_id = db.Column(db.String(100), db.ForeignKey('user_identity.entra_user_id'), nullable=False, index=True)
    user_principal_name = db.Column(db.String(255), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    # Event details from Microsoft audit log
    activity_name = db.Column(db.String(255), index=True)  # "User registered security info", etc.
    category = db.Column(db.String(100))  # UserManagement, AuthenticationMethod, etc.
    operation_type = db.Column(db.String(100))  # Add, Delete, Update
    method_type = db.Column(db.String(100))  # microsoftAuthenticator, phoneNumber, fido2, etc.
    
    # Who initiated the change
    initiated_by = db.Column(db.String(255))  # User UPN or admin UPN
    target_user = db.Column(db.String(255))  # Usually same as user_principal_name
    
    # Location if available
    ip_address = db.Column(db.String(50))
    country = db.Column(db.String(100))
    city = db.Column(db.String(100))
    device_id = db.Column(db.String(100))
    
    # Risk context at time of event
    risk_score_at_time = db.Column(db.Integer)  # User's risk score when this happened
    related_recent_signin_id = db.Column(db.Integer, db.ForeignKey('entra_signin_event.id'))  # Most recent sign-in
    
    # Raw data
    raw_json = db.Column(db.Text)
    
    def __repr__(self):
        return f'<EntraMfaEvent {self.activity_name} for {self.user_principal_name}>'


class UserAuthMethodSnapshot(db.Model):
    """
    Represents the current authentication methods registered for a user.
    Fetched from Microsoft Graph /users/{id}/authentication/methods.
    
    Helps track which methods exist and when they were added.
    """
    __tablename__ = 'user_auth_method_snapshot'
    
    id = db.Column(db.Integer, primary_key=True)
    entra_user_id = db.Column(db.String(100), db.ForeignKey('user_identity.entra_user_id'), nullable=False, index=True)
    user_principal_name = db.Column(db.String(255), nullable=False)
    
    method_id = db.Column(db.String(100), unique=True, index=True)  # Microsoft's method ID
    method_type = db.Column(db.String(100))  # microsoftAuthenticator, phoneNumber, email, fido2, etc.
    display_name = db.Column(db.String(255))  # e.g., "Microsoft Authenticator (iOS)"
    
    first_seen_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50))  # active, inactive
    
    raw_json = db.Column(db.Text)
    
    def __repr__(self):
        return f'<UserAuthMethodSnapshot {self.method_type} for {self.user_principal_name}>'


class UserRiskState(db.Model):
    """
    Aggregated risk state for a user.
    Updated after each sign-in or MFA event analysis.
    
    This is RiskGate's current assessment of the user's risk.
    """
    __tablename__ = 'user_risk_state'
    
    id = db.Column(db.Integer, primary_key=True)
    entra_user_id = db.Column(db.String(100), db.ForeignKey('user_identity.entra_user_id'), unique=True, nullable=False, index=True)
    user_principal_name = db.Column(db.String(255), nullable=False)
    
    current_risk_score = db.Column(db.Integer, default=0, index=True)
    current_risk_level = db.Column(db.String(50), default='low', index=True)  # low, medium, high, critical
    reasons = db.Column(db.Text)  # JSON array of active risk reasons
    
    # Timestamps of significant events
    last_risky_signin_at = db.Column(db.DateTime)
    last_impossible_login_at = db.Column(db.DateTime)
    last_mfa_change_at = db.Column(db.DateTime)
    
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f'<UserRiskState {self.user_principal_name}: {self.current_risk_score}>'


class EntraSecurityAlert(db.Model):
    """
    Security alerts generated by RiskGate correlation logic for Entra ID events.
    
    Critical alerts are created when:
    - Impossible login detected
    - MFA changed after risky login
    - Suspicious MFA takeover pattern
    - Temporary Access Pass created after risk
    """
    __tablename__ = 'entra_security_alert'
    
    id = db.Column(db.Integer, primary_key=True)
    entra_user_id = db.Column(db.String(100), db.ForeignKey('user_identity.entra_user_id'), nullable=False, index=True)
    user_principal_name = db.Column(db.String(255), nullable=False, index=True)
    
    alert_type = db.Column(db.String(100), nullable=False, index=True)
    # Types: impossible_login, mfa_change_after_risky_login, possible_mfa_takeover, tap_created_after_risk
    
    severity = db.Column(db.String(50), nullable=False, index=True)  # low, medium, high, critical
    reason = db.Column(db.Text, nullable=False)  # Human-readable explanation
    status = db.Column(db.String(50), default='open', index=True)  # open, investigating, resolved, false_positive
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    # Related events for correlation
    related_signin_event_id = db.Column(db.Integer, db.ForeignKey('entra_signin_event.id'))
    related_mfa_event_id = db.Column(db.Integer, db.ForeignKey('entra_mfa_event.id'))
    
    # Relationships
    related_signin = db.relationship('EntraSignInEvent', foreign_keys=[related_signin_event_id])
    related_mfa_event = db.relationship('EntraMfaEvent', foreign_keys=[related_mfa_event_id])
    
    def __repr__(self):
        return f'<SecurityAlert {self.alert_type} for {self.user_principal_name}>'
