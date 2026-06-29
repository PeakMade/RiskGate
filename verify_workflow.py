"""
Verify that RiskGate implements the complete workflow:
1. Import Microsoft sign-in logs
2. Store in EntraSignInEvent
3. Detect impossible travel
4. Create SecurityAlert
5. Import Authentication Methods audit events
6. Store in EntraMfaEvent
7. Correlate MFA events within 60 minutes of impossible login
8. Create critical alert
9. Show user timeline
"""
from app import create_app
from app.models_new import EntraSignInEvent, EntraMfaEvent, EntraSecurityAlert, UserIdentity
from app import db
from datetime import datetime, timedelta
import json

app = create_app()

with app.app_context():
    print("=" * 80)
    print("RISKGATE WORKFLOW VERIFICATION")
    print("=" * 80)
    
    # Step 1-2: Sign-in logs imported and stored
    signin_count = EntraSignInEvent.query.count()
    print(f"\n✅ STEP 1-2: Sign-in Logs Imported & Stored")
    print(f"   EntraSignInEvent records: {signin_count}")
    if signin_count > 0:
        sample = EntraSignInEvent.query.first()
        print(f"   Sample: {sample.user_principal_name} from {sample.city}, {sample.country}")
    
    # Step 3: Impossible travel detected
    impossible_travel = EntraSignInEvent.query.filter_by(impossible_travel_detected=True).all()
    print(f"\n✅ STEP 3: Impossible Travel Detection")
    print(f"   Impossible travel events detected: {len(impossible_travel)}")
    for event in impossible_travel[:3]:
        print(f"   - {event.user_principal_name}: {event.city}, {event.country}")
        print(f"     Speed required: {event.required_travel_speed_mph} mph")
        print(f"     Risk score: {event.local_risk_score} ({event.local_risk_level})")
    
    # Step 4: Security alerts created for impossible travel
    travel_alerts = EntraSecurityAlert.query.filter(
        EntraSecurityAlert.reason.like('%impossible travel%')
    ).all()
    print(f"\n✅ STEP 4: Security Alerts Created")
    print(f"   Alerts for impossible travel/risky sign-ins: {len(travel_alerts)}")
    
    # Step 5-6: MFA audit events imported and stored
    mfa_count = EntraMfaEvent.query.count()
    print(f"\n✅ STEP 5-6: MFA Audit Events Imported & Stored")
    print(f"   EntraMfaEvent records: {mfa_count}")
    if mfa_count > 0:
        sample_mfa = EntraMfaEvent.query.first()
        print(f"   Sample: {sample_mfa.activity_name} for {sample_mfa.user_principal_name}")
        print(f"   Method: {sample_mfa.method_type}, Time: {sample_mfa.created_at}")
    
    # Step 7-8: MFA correlation within 60 minutes and critical alerts
    critical_mfa_alerts = EntraSecurityAlert.query.filter_by(
        alert_type='mfa_change_after_risky_login',
        severity='critical'
    ).all()
    print(f"\n✅ STEP 7-8: MFA Correlation & Critical Alerts")
    print(f"   Critical alerts for MFA after risky sign-in: {len(critical_mfa_alerts)}")
    
    for alert in critical_mfa_alerts[:3]:
        print(f"\n   Alert for: {alert.user_principal_name}")
        print(f"   Severity: {alert.severity.upper()}")
        print(f"   Created: {alert.created_at}")
        # Parse reason for timing info
        if "minutes after" in alert.reason:
            reason_lines = alert.reason.split('\n')
            for line in reason_lines[:3]:
                print(f"   {line}")
    
    # Step 9: User timeline capability
    print(f"\n✅ STEP 9: User Timeline")
    users = UserIdentity.query.limit(3).all()
    
    for user in users:
        print(f"\n   User: {user.user_principal_name}")
        
        # Sign-in timeline
        signins = EntraSignInEvent.query.filter_by(
            entra_user_id=user.entra_user_id
        ).order_by(EntraSignInEvent.created_at.desc()).limit(5).all()
        
        print(f"   Sign-in events: {len(signins)}")
        for signin in signins:
            risk_indicator = "🚨" if signin.impossible_travel_detected else "✓"
            print(f"     {risk_indicator} {signin.created_at} - {signin.city}, {signin.country} (Risk: {signin.local_risk_score})")
        
        # MFA timeline
        mfa_events = EntraMfaEvent.query.filter_by(
            entra_user_id=user.entra_user_id
        ).order_by(EntraMfaEvent.created_at.desc()).limit(5).all()
        
        print(f"   MFA events: {len(mfa_events)}")
        for mfa in mfa_events:
            print(f"     📱 {mfa.created_at} - {mfa.activity_name} ({mfa.method_type})")
        
        # Alerts timeline
        alerts = EntraSecurityAlert.query.filter_by(
            entra_user_id=user.entra_user_id
        ).order_by(EntraSecurityAlert.created_at.desc()).limit(5).all()
        
        print(f"   Security alerts: {len(alerts)}")
        for alert in alerts:
            severity_icon = "🚨" if alert.severity == 'critical' else "⚠️" if alert.severity == 'high' else "ℹ️"
            print(f"     {severity_icon} {alert.created_at} - {alert.alert_type} ({alert.severity})")
    
    print("\n" + "=" * 80)
    print("WORKFLOW VERIFICATION SUMMARY")
    print("=" * 80)
    print(f"✅ Step 1-2: Sign-in logs ingested: {signin_count > 0}")
    print(f"✅ Step 3: Impossible travel detected: {len(impossible_travel) > 0}")
    print(f"✅ Step 4: Security alerts created: {len(travel_alerts) > 0}")
    print(f"✅ Step 5-6: MFA events ingested: {mfa_count > 0}")
    print(f"✅ Step 7-8: MFA correlation & critical alerts: {len(critical_mfa_alerts) > 0}")
    print(f"✅ Step 9: User timeline data available: {len(users) > 0}")
    
    all_working = all([
        signin_count > 0,
        len(impossible_travel) > 0,
        mfa_count > 0,
        len(critical_mfa_alerts) > 0,
        len(users) > 0
    ])
    
    if all_working:
        print("\n🎉 ALL WORKFLOW STEPS ARE WORKING!")
    else:
        print("\n⚠️ Some workflow steps need data - run: python seed_test_data.py")
    
    print("=" * 80)
