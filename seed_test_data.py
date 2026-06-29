"""
Seed test data for RiskGate MFA detection testing.
Creates sample EntraSignInEvent and EntraMfaEvent records to demonstrate:
1. Normal MFA creation (should create low-severity informational alert)
2. MFA creation after risky sign-in (should create critical alert)
3. MFA takeover pattern (add then remove)

Run this with: python seed_test_data.py
"""
from datetime import datetime, timedelta
import uuid
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app, db

# Import only the new Entra models to avoid conflicts with old models
from app.models_new import UserIdentity, EntraSignInEvent, EntraMfaEvent


def clear_test_data():
    """Clear all test data using raw SQL to avoid model conflicts."""
    print("Clearing existing test data...")
    try:
        # Use raw SQL to avoid model relationship issues
        db.session.execute(db.text("DELETE FROM entra_mfa_event"))
        db.session.execute(db.text("DELETE FROM entra_signin_event"))
        db.session.execute(db.text("DELETE FROM user_identity WHERE entra_user_id = 'test-user-123'"))
        db.session.commit()
        print("Test data cleared.")
    except Exception as e:
        print(f"Note: Could not clear all data (this is OK if tables don't exist): {e}")
        db.session.rollback()


def create_test_user():
    """Create a test user identity."""
    user = UserIdentity(
        entra_user_id='test-user-123',
        user_principal_name='testuser@example.com',
        display_name='Test User'
    )
    db.session.add(user)
    db.session.commit()
    print(f"Created test user: {user.user_principal_name}")
    return user


def create_normal_signin(user, hours_ago=2):
    """Create a normal, low-risk sign-in event."""
    signin = EntraSignInEvent(
        microsoft_event_id=str(uuid.uuid4()),
        entra_user_id=user.entra_user_id,
        user_principal_name=user.user_principal_name,
        created_at=datetime.utcnow() - timedelta(hours=hours_ago),
        ip_address='192.168.1.100',
        country='United States',
        city='New York',
        latitude=40.7128,
        longitude=-74.0060,
        browser='Chrome',
        operating_system='Windows 10',
        status='success',
        mfa_required=True,
        mfa_satisfied=True,
        risk_level_aggregated='none',
        local_risk_score=10,
        local_risk_level='low',
        local_risk_reasons='[]',
        impossible_travel_detected=False
    )
    db.session.add(signin)
    db.session.commit()
    print(f"Created normal sign-in event at {signin.created_at}")
    return signin


def create_risky_signin(user, hours_ago=1):
    """Create a risky sign-in with impossible travel."""
    signin = EntraSignInEvent(
        microsoft_event_id=str(uuid.uuid4()),
        entra_user_id=user.entra_user_id,
        user_principal_name=user.user_principal_name,
        created_at=datetime.utcnow() - timedelta(hours=hours_ago),
        ip_address='203.0.113.50',
        country='Russia',
        city='Moscow',
        latitude=55.7558,
        longitude=37.6173,
        browser='Chrome',
        operating_system='Windows 10',
        status='success',
        mfa_required=True,
        mfa_satisfied=True,
        risk_level_aggregated='high',
        local_risk_score=85,
        local_risk_level='high',
        local_risk_reasons='["impossible_travel", "new_country", "new_device"]',
        impossible_travel_detected=True,
        required_travel_speed_mph=8500.0
    )
    db.session.add(signin)
    db.session.commit()
    print(f"Created RISKY sign-in event at {signin.created_at} (impossible travel from Moscow)")
    return signin


def create_normal_mfa_event(user, minutes_ago=30):
    """Create a normal MFA registration event (should trigger low-severity alert)."""
    mfa_event = EntraMfaEvent(
        microsoft_event_id=str(uuid.uuid4()),
        entra_user_id=user.entra_user_id,
        user_principal_name=user.user_principal_name,
        created_at=datetime.utcnow() - timedelta(minutes=minutes_ago),
        activity_name='User registered security info',
        category='UserManagement',
        operation_type='Add',
        method_type='PhoneAppNotification',
        initiated_by=user.user_principal_name,
        target_user=user.user_principal_name,
        ip_address='192.168.1.100'
    )
    db.session.add(mfa_event)
    db.session.commit()
    print(f"Created NORMAL MFA registration at {mfa_event.created_at}")
    return mfa_event


def create_suspicious_mfa_event(user, minutes_after_risky_signin=15):
    """Create MFA event shortly after risky sign-in (should trigger critical alert)."""
    mfa_event = EntraMfaEvent(
        microsoft_event_id=str(uuid.uuid4()),
        entra_user_id=user.entra_user_id,
        user_principal_name=user.user_principal_name,
        created_at=datetime.utcnow() - timedelta(minutes=45-minutes_after_risky_signin),
        activity_name='User registered security info',
        category='UserManagement',
        operation_type='Add',
        method_type='PhoneAppNotification',
        initiated_by=user.user_principal_name,
        target_user=user.user_principal_name,
        ip_address='203.0.113.50'  # Same IP as risky sign-in
    )
    db.session.add(mfa_event)
    db.session.commit()
    print(f"Created SUSPICIOUS MFA registration at {mfa_event.created_at} (15 min after risky signin)")
    return mfa_event


def create_mfa_removal_event(user, minutes_ago=10):
    """Create MFA removal event."""
    mfa_event = EntraMfaEvent(
        microsoft_event_id=str(uuid.uuid4()),
        entra_user_id=user.entra_user_id,
        user_principal_name=user.user_principal_name,
        created_at=datetime.utcnow() - timedelta(minutes=minutes_ago),
        activity_name='User deleted security info',
        category='UserManagement',
        operation_type='Delete',
        method_type='PhoneAppNotification',
        initiated_by=user.user_principal_name,
        target_user=user.user_principal_name,
        ip_address='203.0.113.50'
    )
    db.session.add(mfa_event)
    db.session.commit()
    print(f"Created MFA REMOVAL at {mfa_event.created_at}")
    return mfa_event


def seed_all():
    """Seed all test data."""
    print("\n" + "="*60)
    print("SEEDING TEST DATA FOR MFA DETECTION")
    print("="*60 + "\n")
    
    # Clear existing test data
    clear_test_data()
    
    # Create test user
    user = create_test_user()
    
    print("\n--- Scenario 1: Normal MFA creation ---")
    # Normal sign-in, then normal MFA creation (2 hours later)
    create_normal_signin(user, hours_ago=2)
    create_normal_mfa_event(user, minutes_ago=30)
    
    print("\n--- Scenario 2: Suspicious MFA after risky sign-in ---")
    # Risky sign-in with impossible travel
    create_risky_signin(user, hours_ago=1)
    # Suspicious MFA creation 15 minutes later
    create_suspicious_mfa_event(user, minutes_after_risky_signin=15)
    
    print("\n--- Scenario 3: MFA takeover pattern ---")
    # Another risky signin
    create_risky_signin(user, hours_ago=0.5)
    # Add new MFA
    create_suspicious_mfa_event(user, minutes_after_risky_signin=10)
    # Remove MFA shortly after
    create_mfa_removal_event(user, minutes_ago=5)
    
    print("\n" + "="*60)
    print("PROCESSING MFA EVENTS FOR ALERTS")
    from app.ingest import process_mfa_events_for_alerts
    print("="*60 + "\n")
    
    # Process all MFA events to create alerts
    stats = process_mfa_events_for_alerts(lookback_hours=24)
    
    print("\n" + "="*60)
    print("TEST DATA SEEDING COMPLETE")
    print("="*60)
    print(f"Events analyzed: {stats['events_analyzed']}")
    print(f"Alerts created: {stats['alerts_created']}")
    print(f"Errors: {stats['errors']}")
    print("\nYou can now:")
    print("1. Go to https://127.0.0.1:5003")
    print("2. Click the 'Alerts' button to see generated security alerts")
    print("3. Click 'MFA Events' to see all MFA events")
    print("\nExpected alerts:")
    print("  - LOW: Normal MFA registration (informational)")
    print("  - CRITICAL: MFA change after risky sign-in")
    print("  - CRITICAL: Possible MFA takeover pattern")
    print("="*60 + "\n")


if __name__ == '__main__':
    app = create_app()
    with app.app_context():
        seed_all()
