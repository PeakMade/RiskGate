"""
Database models for the RiskGate security application.
"""
from datetime import datetime, timedelta
from app import db, login_manager
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash


@login_manager.user_loader
def load_user(user_id):
    """Flask-Login user loader callback."""
    return User.query.get(int(user_id))


class User(UserMixin, db.Model):
    """
    User model representing application users.
    Includes basic authentication fields and role-based access control.
    """
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), default='user')  # user, admin, finance, security
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    login_events = db.relationship('LoginEvent', backref='user', lazy='dynamic', 
                                   cascade='all, delete-orphan')
    mfa_methods = db.relationship('MfaMethod', backref='user', lazy='dynamic',
                                 cascade='all, delete-orphan')
    mfa_events = db.relationship('MfaEvent', backref='user', lazy='dynamic',
                                cascade='all, delete-orphan')
    security_alerts = db.relationship('SecurityAlert', backref='user', lazy='dynamic',
                                     cascade='all, delete-orphan')
    trusted_devices = db.relationship('TrustedDevice', backref='user', lazy='dynamic',
                                     cascade='all, delete-orphan')
    
    def set_password(self, password):
        """Hash and set the user's password."""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Verify the user's password."""
        return check_password_hash(self.password_hash, password)
    
    def is_high_privilege(self):
        """Check if user has a high-privilege role requiring stricter security."""
        from flask import current_app
        return self.role in current_app.config['HIGH_PRIVILEGE_ROLES']
    
    def __repr__(self):
        return f'<User {self.email}>'


class LoginEvent(db.Model):
    """
    Records every login attempt (successful or failed).
    Captures location, device, and risk information.
    """
    __tablename__ = 'login_events'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    success = db.Column(db.Boolean, default=False)
    
    # Location information
    ip_address = db.Column(db.String(45))  # IPv6 can be up to 45 chars
    country = db.Column(db.String(100))
    city = db.Column(db.String(100))
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    
    # Device information
    user_agent = db.Column(db.String(500))
    browser = db.Column(db.String(100))
    operating_system = db.Column(db.String(100))
    device_fingerprint = db.Column(db.String(255), index=True)
    
    # MFA information
    mfa_required = db.Column(db.Boolean, default=False)
    mfa_success = db.Column(db.Boolean, default=None, nullable=True)
    
    # Risk assessment
    risk_score = db.Column(db.Integer, default=0)
    risk_reason = db.Column(db.Text)  # JSON or comma-separated reasons
    
    def __repr__(self):
        return f'<LoginEvent user={self.user_id} success={self.success} risk={self.risk_score}>'


class MfaMethod(db.Model):
    """
    Represents a multi-factor authentication method configured by a user.
    Examples: TOTP app, SMS, hardware key, backup codes.
    """
    __tablename__ = 'mfa_methods'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    method_type = db.Column(db.String(50), nullable=False)  # totp, sms, hardware_key, backup_codes
    status = db.Column(db.String(50), default='pending')  # pending, restricted, active, disabled, removed
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    activated_at = db.Column(db.DateTime, nullable=True)
    trusted_after = db.Column(db.DateTime, nullable=True)  # When this method becomes fully trusted
    
    # Security tracking
    created_from_ip = db.Column(db.String(45))
    created_from_device = db.Column(db.String(255))
    
    # Relationships
    mfa_events = db.relationship('MfaEvent', backref='mfa_method', lazy='dynamic',
                                cascade='all, delete-orphan')
    
    def is_fully_trusted(self):
        """
        Check if this MFA method has passed its trust period.
        New MFA methods must wait 24 hours before becoming fully trusted.
        """
        if self.trusted_after is None:
            return False
        return datetime.utcnow() >= self.trusted_after
    
    def is_active(self):
        """Check if this MFA method is currently active."""
        return self.status == 'active'
    
    def __repr__(self):
        return f'<MfaMethod user={self.user_id} type={self.method_type} status={self.status}>'


class MfaEvent(db.Model):
    """
    Logs all MFA-related events: creation, removal, verification attempts, blocks.
    Critical for audit trails and fraud detection.
    """
    __tablename__ = 'mfa_events'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    mfa_method_id = db.Column(db.Integer, db.ForeignKey('mfa_methods.id'), nullable=True)
    event_type = db.Column(db.String(50), nullable=False)  # create, remove, verify, block, reset
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    # Location and device at time of event
    ip_address = db.Column(db.String(45))
    country = db.Column(db.String(100))
    city = db.Column(db.String(100))
    device_fingerprint = db.Column(db.String(255))
    
    # Risk and blocking information
    session_risk_score = db.Column(db.Integer, default=0)
    blocked = db.Column(db.Boolean, default=False)
    reason = db.Column(db.Text)  # Why was this blocked or flagged?
    
    def __repr__(self):
        return f'<MfaEvent user={self.user_id} type={self.event_type} blocked={self.blocked}>'


class SecurityAlert(db.Model):
    """
    High-level security alerts that require attention.
    Created for impossible travel, blocked MFA changes, and other suspicious activity.
    """
    __tablename__ = 'security_alerts'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    alert_type = db.Column(db.String(100), nullable=False)  # impossible_travel, blocked_mfa_creation, etc.
    severity = db.Column(db.String(50), nullable=False)  # low, medium, high, critical
    reason = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    status = db.Column(db.String(50), default='active')  # active, acknowledged, resolved, false_positive
    
    def is_high_severity(self):
        """Check if this is a high or critical severity alert."""
        return self.severity in ['high', 'critical']
    
    def __repr__(self):
        return f'<SecurityAlert user={self.user_id} type={self.alert_type} severity={self.severity}>'


class TrustedDevice(db.Model):
    """
    Tracks devices that have been explicitly trusted by the user.
    Used to reduce false positives for known devices.
    """
    __tablename__ = 'trusted_devices'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    device_fingerprint = db.Column(db.String(255), nullable=False, index=True)
    first_seen_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen_at = db.Column(db.DateTime, default=datetime.utcnow)
    trusted = db.Column(db.Boolean, default=False)
    
    def __repr__(self):
        return f'<TrustedDevice user={self.user_id} trusted={self.trusted}>'
