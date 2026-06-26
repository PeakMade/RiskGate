"""
Configuration settings for RiskGate - Microsoft Entra Identity Monitoring.

Environment variables for Microsoft Graph API:
- AZURE_TENANT_ID: Your Azure AD tenant ID
- AZURE_CLIENT_ID: App registration client ID  
- AZURE_CLIENT_SECRET: App registration client secret

Required Microsoft Graph API permissions:
- AuditLog.Read.All (sign-in logs and audit logs)
- UserAuthenticationMethod.Read.All (authentication methods)
- User.Read.All (user details)
"""
import os
from datetime import timedelta

# Base directory of the application
basedir = os.path.abspath(os.path.dirname(__file__))


class Config:
    """Base configuration class with default settings."""
    
    # Secret key for session management and CSRF protection
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    
    # Database configuration - using SQLite for local development
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'riskgate.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Session configuration
    PERMANENT_SESSION_LIFETIME = timedelta(hours=2)
    SESSION_COOKIE_SECURE = False  # Set to True in production with HTTPS
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # Microsoft Graph API configuration
    AZURE_TENANT_ID = os.environ.get('AZURE_TENANT_ID')
    AZURE_CLIENT_ID = os.environ.get('AZURE_CLIENT_ID')
    AZURE_CLIENT_SECRET = os.environ.get('AZURE_CLIENT_SECRET')
    
    # Data ingestion settings
    SIGNIN_LOGS_HOURS_BACK = 24  # How many hours of sign-in logs to fetch
    AUDIT_LOGS_HOURS_BACK = 24  # How many hours of audit logs to fetch
    
    # Risk score thresholds
    RISK_THRESHOLD_LOW = 29
    RISK_THRESHOLD_MEDIUM = 30
    RISK_THRESHOLD_HIGH = 60
    RISK_THRESHOLD_CRITICAL = 90
    RISK_THRESHOLD_CRITICAL_BLOCK = 90  # Block app access at this level
    
    # Risk score values for different events
    RISK_SCORE_NEW_DEVICE = 20
    RISK_SCORE_NEW_COUNTRY = 20
    RISK_SCORE_IMPOSSIBLE_TRAVEL = 40  # Standard impossible travel (500-1000 mph)
    RISK_SCORE_EXTREME_TRAVEL = 70     # Extreme impossible travel (>1000 mph)
    RISK_SCORE_MICROSOFT_MEDIUM = 30   # Microsoft risk level: medium
    RISK_SCORE_MICROSOFT_HIGH = 50     # Microsoft risk level: high
    
    # Travel speed thresholds (in mph)
    TRAVEL_SPEED_IMPOSSIBLE = 500  # Faster than commercial flight
    TRAVEL_SPEED_EXTREME = 1000    # Faster than supersonic flight
    
    # MFA correlation settings
    MFA_CORRELATION_LOOKBACK_MINUTES = 60  # Correlate MFA changes within this window after risky sign-in
    MFA_TAKEOVER_DETECTION_HOURS = 24      # Look for add-then-remove patterns within this window
    HIGH_PRIVILEGE_RISK_THRESHOLD = 30
