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
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Base directory of the application
basedir = os.path.abspath(os.path.dirname(__file__))


class Config:
    """Base configuration class with default settings."""
    
    # Secret key for session management and CSRF protection
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    
    # Database configuration
    database_url = os.environ.get('DATABASE_URL')
    if database_url:
        # Azure PostgreSQL fix: postgres:// -> postgresql://
        if database_url.startswith('postgres://'):
            database_url = database_url.replace('postgres://', 'postgresql://', 1)
        SQLALCHEMY_DATABASE_URI = database_url
    else:
        # Use SQLite for local development
        SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'riskgate.db')
    
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Session configuration
    PERMANENT_SESSION_LIFETIME = timedelta(hours=2)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    # SESSION_COOKIE_SECURE set dynamically below based on environment
    
    # Microsoft Graph API configuration
    AZURE_TENANT_ID = os.environ.get('AZURE_TENANT_ID', 'ea0cd29c-45e6-4ad1-94ff-2e9f36fb84b5')
    AZURE_CLIENT_ID = os.environ.get('AZURE_CLIENT_ID', '99b0438f-6b8c-41ff-86ee-0116481883ea')
    AZURE_CLIENT_SECRET = os.environ.get('AZURE_CLIENT_SECRET')
    
    # Application URL (auto-detect local vs production)
    WEBSITE_HOSTNAME = os.environ.get('WEBSITE_HOSTNAME')  # Azure App Service sets this
    if WEBSITE_HOSTNAME:
        APP_URL = f"https://{WEBSITE_HOSTNAME}"
        SESSION_COOKIE_SECURE = True  # Require HTTPS for cookies in production
    else:
        APP_URL = 'https://127.0.0.1:5003'  # Local development with self-signed cert
        SESSION_COOKIE_SECURE = True
    
    PRODUCTION_URL = 'https://riskgate-e6f4c2gac0a3bjfr.eastus-01.azurewebsites.net'
    
    # MSAL Authentication configuration
    MSAL_AUTHORITY = f"https://login.microsoftonline.com/{AZURE_TENANT_ID}"
    MSAL_REDIRECT_PATH = "/auth/callback"  # Must match Azure App Registration
    MSAL_SCOPE = ["User.Read"]  # Basic user profile scope
    
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
    RISK_SCORE_NEW_ACCOUNT = 15        # Account created recently
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
    MFA_TRUST_PERIOD_HOURS = 24            # Trust device after MFA validation for this period
    HIGH_PRIVILEGE_RISK_THRESHOLD = 30
    HIGH_PRIVILEGE_ROLES = ['admin', 'finance', 'security']  # Roles requiring stricter security
    
    # New account protection
    NEW_ACCOUNT_THRESHOLD_DAYS = 7         # Accounts newer than this are flagged
    NEW_ACCOUNT_MFA_RESTRICTION_DAYS = 3   # Can't change MFA for first N days
    NEW_ACCOUNT_WITH_RISK_ALERT = True     # Alert if new account has any risk factors
