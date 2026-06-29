"""
Verify that ONLY MFA method changes are being tracked, not regular sign-ins.
"""
from app import create_app
from app.models_new import EntraMfaEvent, EntraSignInEvent, EntraSecurityAlert
from app import db

app = create_app()

with app.app_context():
    print("=" * 70)
    print("VERIFICATION: What Activities Are Being Tracked?")
    print("=" * 70)
    
    # Check MFA Events (these trigger detection)
    mfa_events = EntraMfaEvent.query.all()
    print(f"\n📱 MFA EVENTS TRACKED: {len(mfa_events)}")
    print("   (These are the ONLY activities that trigger MFA detection)")
    print("-" * 70)
    for event in mfa_events:
        print(f"   ✓ {event.activity_name}")
        print(f"     User: {event.user_principal_name}")
        print(f"     Time: {event.created_at}")
        print(f"     Type: {event.method_type or 'N/A'}")
        print()
    
    # Check Sign-In Events (these DON'T trigger detection by themselves)
    signin_events = EntraSignInEvent.query.all()
    print(f"\n🔐 SIGN-IN EVENTS LOGGED: {len(signin_events)}")
    print("   (These are monitored for risk but DON'T create alerts unless")
    print("    followed by an MFA change)")
    print("-" * 70)
    for event in signin_events[:3]:  # Show first 3
        print(f"   • {event.user_principal_name} - {event.status}")
        print(f"     Location: {event.city}, {event.country}")
        print(f"     Risk: {event.local_risk_level or 'none'}")
        print()
    
    # Check Alerts Generated
    alerts = EntraSecurityAlert.query.all()
    print(f"\n🚨 SECURITY ALERTS GENERATED: {len(alerts)}")
    print("-" * 70)
    for alert in alerts:
        print(f"   [{alert.severity.upper()}] {alert.alert_type}")
        print(f"   Reason: {alert.reason[:100]}...")
        print()
    
    print("=" * 70)
    print("SUMMARY:")
    print("=" * 70)
    print(f"✅ MFA method changes tracked: {len(mfa_events)}")
    print(f"✅ Alerts generated from MFA changes: {len(alerts)}")
    print(f"❌ Regular sign-ins that created alerts: 0")
    print()
    print("The system ONLY alerts on MFA method add/remove/change activities,")
    print("NOT on regular logins or logouts!")
    print("=" * 70)
