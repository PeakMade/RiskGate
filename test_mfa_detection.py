"""
Test script to verify MFA detection is working.
Shows all MFA events and alerts in the database.
"""
from app import create_app, db
from app.models_new import UserIdentity, EntraSignInEvent, EntraMfaEvent, EntraSecurityAlert

app = create_app()

with app.app_context():
    print("\n" + "="*60)
    print("MFA DETECTION VERIFICATION")
    print("="*60)
    
    # Check test user exists
    user = UserIdentity.query.filter_by(user_principal_name='testuser@example.com').first()
    if not user:
        print("❌ No test user found. Run: python seed_test_data.py")
        exit(1)
    
    print(f"\n✅ Test User: {user.user_principal_name} (ID: {user.entra_user_id})")
    
    # Show all MFA events
    print("\n" + "-"*60)
    print("📱 MFA EVENTS IN DATABASE")
    print("-"*60)
    
    mfa_events = EntraMfaEvent.query.filter_by(entra_user_id=user.entra_user_id).order_by(EntraMfaEvent.created_at).all()
    
    if not mfa_events:
        print("❌ No MFA events found")
    else:
        for i, event in enumerate(mfa_events, 1):
            print(f"\n{i}. {event.operation_type} - {event.method_type}")
            print(f"   Activity: {event.activity_name}")
            print(f"   Time: {event.created_at}")
            print(f"   IP: {event.ip_address or 'N/A'}")
    
    # Show all security alerts
    print("\n" + "-"*60)
    print("🚨 SECURITY ALERTS GENERATED")
    print("-"*60)
    
    alerts = EntraSecurityAlert.query.filter_by(entra_user_id=user.entra_user_id).order_by(EntraSecurityAlert.created_at).all()
    
    if not alerts:
        print("❌ No alerts found - detection may not be working!")
        print("\n💡 Try running: python seed_test_data.py")
    else:
        print(f"\nTotal Alerts: {len(alerts)}")
        
        # Group by severity
        by_severity = {}
        for alert in alerts:
            by_severity.setdefault(alert.severity, []).append(alert)
        
        for severity in ['critical', 'high', 'medium', 'low']:
            if severity in by_severity:
                print(f"\n{severity.upper()} ({len(by_severity[severity])} alerts):")
                for alert in by_severity[severity]:
                    print(f"  • {alert.alert_type}")
                    print(f"    Reason: {alert.reason[:80]}...")
                    print(f"    Status: {alert.status}")
                    print(f"    Created: {alert.created_at}")
    
    # Show sign-in events for context
    print("\n" + "-"*60)
    print("🔐 SIGN-IN EVENTS")
    print("-"*60)
    
    signins = EntraSignInEvent.query.filter_by(entra_user_id=user.entra_user_id).order_by(EntraSignInEvent.created_at).all()
    
    if signins:
        for i, signin in enumerate(signins, 1):
            risk_flag = "⚠️ RISKY" if signin.local_risk_score and signin.local_risk_score > 50 else "✅ Safe"
            location = f"{signin.city}, {signin.country}" if signin.city and signin.country else (signin.country or "Unknown")
            print(f"\n{i}. {risk_flag} - {location}")
            print(f"   Time: {signin.created_at}")
            print(f"   IP: {signin.ip_address or 'N/A'}")
            print(f"   Risk Score: {signin.local_risk_score}")
            if signin.impossible_travel_detected:
                speed = signin.required_travel_speed_mph or 0
                print(f"   🚨 IMPOSSIBLE TRAVEL: {speed:.0f} mph detected")
    
    # Verification summary
    print("\n" + "="*60)
    print("DETECTION STATUS SUMMARY")
    print("="*60)
    
    critical_alerts = [a for a in alerts if a.severity == 'critical']
    low_alerts = [a for a in alerts if a.severity == 'low']
    
    print(f"\n✅ MFA Events Detected: {len(mfa_events)}")
    print(f"✅ Critical Alerts (suspicious): {len(critical_alerts)}")
    print(f"✅ Low Alerts (normal audit): {len(low_alerts)}")
    
    if critical_alerts:
        print("\n🎯 CRITICAL DETECTION WORKING:")
        print("   - System is catching suspicious MFA changes!")
    
    if low_alerts:
        print("\n🎯 COMPREHENSIVE DETECTION WORKING:")
        print("   - System is logging ALL MFA registrations!")
    
    if not alerts:
        print("\n❌ NO DETECTION - Something is wrong!")
        print("   Check that process_mfa_events_for_alerts() is being called")
    
    print("\n" + "="*60 + "\n")
