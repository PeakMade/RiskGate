"""
Data ingestion for RiskGate.

Normalizes Microsoft Graph API responses into RiskGate database models.
Handles:
- Sign-in log ingestion
- Audit log ingestion (MFA/authentication method changes)
- Authentication method snapshots
- User identity creation/updates

Prevents duplicate ingestion using microsoft_event_id.
"""
import json
from datetime import datetime
from flask import current_app
from app import db
from app.models_new import (
    UserIdentity, EntraSignInEvent, EntraMfaEvent,
    UserAuthMethodSnapshot, UserRiskState, EntraSecurityAlert
)


def get_or_create_user_identity(entra_user_id, user_principal_name, display_name=None):
    """
    Get existing UserIdentity or create new one.
    Updates last_seen_at on each call.
    
    Args:
        entra_user_id: Azure AD object ID
        user_principal_name: user@domain.com
        display_name: User's display name
    
    Returns:
        UserIdentity object
    """
    user = UserIdentity.query.filter_by(entra_user_id=entra_user_id).first()
    
    if not user:
        user = UserIdentity(
            entra_user_id=entra_user_id,
            user_principal_name=user_principal_name,
            display_name=display_name or user_principal_name
        )
        db.session.add(user)
        current_app.logger.info(f"Created new UserIdentity: {user_principal_name}")
    else:
        # Update last seen
        user.last_seen_at = datetime.utcnow()
        if display_name and not user.display_name:
            user.display_name = display_name
    
    return user


def ingest_signin_event(signin_record):
    """
    Normalize a Microsoft Graph sign-in log record into EntraSignInEvent.
    
    Args:
        signin_record: Dict from Microsoft Graph signIns API
    
    Returns:
        EntraSignInEvent object or None if duplicate/error
    """
    try:
        # Extract Microsoft event ID to prevent duplicates
        microsoft_event_id = signin_record.get('id')
        if not microsoft_event_id:
            current_app.logger.warning("Sign-in record missing ID, skipping")
            return None
        
        # Check for duplicate
        existing = EntraSignInEvent.query.filter_by(microsoft_event_id=microsoft_event_id).first()
        if existing:
            current_app.logger.debug(f"Sign-in event {microsoft_event_id} already ingested, skipping")
            return None
        
        # Extract user info
        entra_user_id = signin_record.get('userId')
        user_principal_name = signin_record.get('userPrincipalName')
        display_name = signin_record.get('userDisplayName')
        
        if not entra_user_id or not user_principal_name:
            current_app.logger.warning("Sign-in record missing user info, skipping")
            return None
        
        # Get or create user
        user = get_or_create_user_identity(entra_user_id, user_principal_name, display_name)
        
        # Extract timestamp
        created_datetime = signin_record.get('createdDateTime')
        if created_datetime:
            created_at = datetime.fromisoformat(created_datetime.replace('Z', '+00:00'))
        else:
            created_at = datetime.utcnow()
        
        # Extract location
        location = signin_record.get('location', {}) or {}
        city = location.get('city')
        country = location.get('countryOrRegion')
        geo_coordinates = location.get('geoCoordinates', {}) or {}
        latitude = geo_coordinates.get('latitude')
        longitude = geo_coordinates.get('longitude')
        
        # Extract device/client info
        device_detail = signin_record.get('deviceDetail', {}) or {}
        browser = device_detail.get('browser')
        operating_system = device_detail.get('operatingSystem')
        device_id = device_detail.get('deviceId')
        
        # Extract IP address
        ip_address = signin_record.get('ipAddress')
        
        # Extract app info
        app_display_name = signin_record.get('appDisplayName')
        
        # Extract authentication status
        status_obj = signin_record.get('status', {}) or {}
        status = 'success' if status_obj.get('errorCode') == 0 else 'failure'
        
        # Extract MFA info
        authentication_details = signin_record.get('authenticationDetails', []) or []
        mfa_required = signin_record.get('mfaDetail', {}).get('authMethod') is not None
        mfa_satisfied = any(detail.get('succeeded') for detail in authentication_details if detail.get('authenticationMethod'))
        
        # Extract Microsoft risk assessment
        risk_level = signin_record.get('riskLevelAggregated', 'none')
        risk_detail = signin_record.get('riskDetail')
        
        # Extract conditional access status
        conditional_access = signin_record.get('conditionalAccessStatus')
        
        # Create EntraSignInEvent
        signin_event = EntraSignInEvent(
            microsoft_event_id=microsoft_event_id,
            entra_user_id=entra_user_id,
            user_principal_name=user_principal_name,
            created_at=created_at,
            ip_address=ip_address,
            country=country,
            city=city,
            latitude=latitude,
            longitude=longitude,
            browser=browser,
            operating_system=operating_system,
            device_id=device_id,
            app_display_name=app_display_name,
            status=status,
            mfa_required=mfa_required,
            mfa_satisfied=mfa_satisfied,
            risk_level_aggregated=risk_level,
            risk_detail=risk_detail,
            conditional_access_status=conditional_access,
            raw_json=json.dumps(signin_record)
        )
        
        db.session.add(signin_event)
        current_app.logger.info(f"Ingested sign-in event: {user_principal_name} at {created_at}")
        
        return signin_event
        
    except Exception as e:
        current_app.logger.error(f"Error ingesting sign-in event: {e}")
        return None


def ingest_audit_event(audit_record):
    """
    Normalize a Microsoft Graph audit log record into EntraMfaEvent.
    
    Focuses on authentication method changes:
    - User registered security info
    - Authentication method added/removed
    - Admin updated authentication method
    - Temporary Access Pass created
    
    Args:
        audit_record: Dict from Microsoft Graph directoryAudits API
    
    Returns:
        EntraMfaEvent object or None if not relevant/duplicate/error
    """
    try:
        # Extract Microsoft event ID
        microsoft_event_id = audit_record.get('id')
        if not microsoft_event_id:
            current_app.logger.warning("Audit record missing ID, skipping")
            return None
        
        # Check for duplicate
        existing = EntraMfaEvent.query.filter_by(microsoft_event_id=microsoft_event_id).first()
        if existing:
            current_app.logger.debug(f"Audit event {microsoft_event_id} already ingested, skipping")
            return None
        
        # Extract activity name
        activity_name = audit_record.get('activityDisplayName', '')
        
        # Filter for authentication method related activities
        auth_method_keywords = [
            'security info', 'authentication method', 'authenticator',
            'phone', 'fido', 'temporary access pass', 'passkey',
            'registered', 'deleted', 'updated', 'reset'
        ]
        
        if not any(keyword in activity_name.lower() for keyword in auth_method_keywords):
            # Not an authentication method event, skip
            return None
        
        # Extract target user
        target_resources = audit_record.get('targetResources', []) or []
        if not target_resources:
            current_app.logger.debug(f"Audit event {microsoft_event_id} has no target resources, skipping")
            return None
        
        target_user_obj = target_resources[0]
        entra_user_id = target_user_obj.get('id')
        user_principal_name = target_user_obj.get('userPrincipalName')
        
        if not entra_user_id or not user_principal_name:
            current_app.logger.warning("Audit event missing target user info, skipping")
            return None
        
        # Get or create user
        user = get_or_create_user_identity(entra_user_id, user_principal_name)
        
        # Extract timestamp
        activity_datetime = audit_record.get('activityDateTime')
        if activity_datetime:
            created_at = datetime.fromisoformat(activity_datetime.replace('Z', '+00:00'))
        else:
            created_at = datetime.utcnow()
        
        # Extract category and operation type
        category = audit_record.get('category', 'UserManagement')
        operation_type = audit_record.get('operationType')
        
        # Extract who initiated
        initiated_by = audit_record.get('initiatedBy', {}) or {}
        user_initiated = initiated_by.get('user', {}) or {}
        app_initiated = initiated_by.get('app', {}) or {}
        
        if user_initiated:
            initiated_by_upn = user_initiated.get('userPrincipalName', 'Unknown User')
        elif app_initiated:
            initiated_by_upn = f"App: {app_initiated.get('displayName', 'Unknown App')}"
        else:
            initiated_by_upn = 'Unknown'
        
        # Extract method type from activity or modified properties
        method_type = None
        modified_properties = target_user_obj.get('modifiedProperties', []) or []
        for prop in modified_properties:
            if 'authenticationMethod' in prop.get('displayName', '').lower():
                method_type = prop.get('newValue', '')
                break
        
        # Extract location if available
        ip_address = None
        if user_initiated:
            ip_address = user_initiated.get('ipAddress')
        
        # Create EntraMfaEvent
        mfa_event = EntraMfaEvent(
            microsoft_event_id=microsoft_event_id,
            entra_user_id=entra_user_id,
            user_principal_name=user_principal_name,
            created_at=created_at,
            activity_name=activity_name,
            category=category,
            operation_type=operation_type,
            method_type=method_type,
            initiated_by=initiated_by_upn,
            target_user=user_principal_name,
            ip_address=ip_address,
            raw_json=json.dumps(audit_record)
        )
        
        db.session.add(mfa_event)
        current_app.logger.info(f"Ingested MFA event: {activity_name} for {user_principal_name} at {created_at}")
        
        return mfa_event
        
    except Exception as e:
        current_app.logger.error(f"Error ingesting audit event: {e}")
        return None


def ingest_auth_method_snapshot(user_id, method_records):
    """
    Ingest authentication method snapshots for a user.
    Updates UserAuthMethodSnapshot table.
    
    Args:
        user_id: Entra user ID
        method_records: List of authentication method dicts from Graph API
    
    Returns:
        List of UserAuthMethodSnapshot objects
    """
    snapshots = []
    
    for method_record in method_records:
        try:
            method_id = method_record.get('id')
            method_type = method_record.get('@odata.type', '').split('.')[-1]
            
            if not method_id:
                continue
            
            # Get or create snapshot
            snapshot = UserAuthMethodSnapshot.query.filter_by(method_id=method_id).first()
            
            if not snapshot:
                # Get user identity
                user = UserIdentity.query.filter_by(entra_user_id=user_id).first()
                if not user:
                    continue
                
                snapshot = UserAuthMethodSnapshot(
                    entra_user_id=user_id,
                    user_principal_name=user.user_principal_name,
                    method_id=method_id,
                    method_type=method_type,
                    display_name=method_record.get('displayName'),
                    status='active',
                    raw_json=json.dumps(method_record)
                )
                db.session.add(snapshot)
                current_app.logger.info(f"Created auth method snapshot: {method_type} for {user.user_principal_name}")
            else:
                # Update last seen
                snapshot.last_seen_at = datetime.utcnow()
                snapshot.raw_json = json.dumps(method_record)
            
            snapshots.append(snapshot)
            
        except Exception as e:
            current_app.logger.error(f"Error ingesting auth method snapshot: {e}")
    
    return snapshots


def ingest_signin_logs_batch(signin_records):
    """
    Ingest a batch of sign-in log records.
    
    Args:
        signin_records: List of sign-in log dicts from Microsoft Graph
    
    Returns:
        Dict with ingestion stats
    """
    stats = {
        'total': len(signin_records),
        'ingested': 0,
        'duplicates': 0,
        'errors': 0
    }
    
    for record in signin_records:
        result = ingest_signin_event(record)
        if result:
            stats['ingested'] += 1
        elif EntraSignInEvent.query.filter_by(microsoft_event_id=record.get('id')).first():
            stats['duplicates'] += 1
        else:
            stats['errors'] += 1
    
    try:
        db.session.commit()
        current_app.logger.info(f"Sign-in ingestion: {stats['ingested']} new, {stats['duplicates']} duplicates, {stats['errors']} errors")
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Failed to commit sign-in ingestion: {e}")
    
    return stats


def ingest_audit_logs_batch(audit_records):
    """
    Ingest a batch of audit log records.
    
    Args:
        audit_records: List of audit log dicts from Microsoft Graph
    
    Returns:
        Dict with ingestion stats
    """
    stats = {
        'total': len(audit_records),
        'ingested': 0,
        'duplicates': 0,
        'skipped': 0,
        'errors': 0
    }
    
    for record in audit_records:
        result = ingest_audit_event(record)
        if result:
            stats['ingested'] += 1
        elif EntraMfaEvent.query.filter_by(microsoft_event_id=record.get('id')).first():
            stats['duplicates'] += 1
        elif not result:
            stats['skipped'] += 1
    
    try:
        db.session.commit()
        current_app.logger.info(f"Audit ingestion: {stats['ingested']} new, {stats['duplicates']} duplicates, {stats['skipped']} skipped")
        
        # After successful ingestion, analyze new MFA events for correlation patterns
        if stats['ingested'] > 0:
            process_mfa_events_for_alerts()
            
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Failed to commit audit ingestion: {e}")
    
    return stats


def process_mfa_events_for_alerts(lookback_hours=24):
    """
    Process recent MFA events and create security alerts based on correlation patterns.
    
    This function analyzes MFA events for:
    - MFA changes after risky sign-ins
    - MFA takeover patterns (add then remove)
    - Temporary Access Pass creation after risk
    - New MFA method creation (informational)
    
    Should be called after MFA event ingestion or on a schedule.
    
    Args:
        lookback_hours: How many hours of MFA events to analyze (default 24)
    
    Returns:
        Dict with processing stats
    """
    from datetime import timedelta
    from app.mfa_detection import analyze_mfa_event_for_correlation
    from app.alerts import create_security_alert
    
    stats = {
        'events_analyzed': 0,
        'alerts_created': 0,
        'errors': 0
    }
    
    try:
        # Get recent MFA events that haven't been analyzed yet
        cutoff_time = datetime.utcnow() - timedelta(hours=lookback_hours)
        
        recent_mfa_events = EntraMfaEvent.query.filter(
            EntraMfaEvent.created_at >= cutoff_time
        ).order_by(EntraMfaEvent.created_at.desc()).all()
        
        for mfa_event in recent_mfa_events:
            stats['events_analyzed'] += 1
            
            try:
                # Analyze the event for all correlation patterns
                analysis_result = analyze_mfa_event_for_correlation(mfa_event)
                
                # Create alerts for each detected pattern
                for alert_data in analysis_result.get('alerts', []):
                    # Check if alert already exists for this event
                    existing_alert = EntraSecurityAlert.query.filter_by(
                        related_mfa_event_id=alert_data['related_mfa_event_id'],
                        alert_type=alert_data['alert_type']
                    ).first()
                    
                    if not existing_alert:
                        create_security_alert(
                            entra_user_id=mfa_event.entra_user_id,
                            user_principal_name=mfa_event.user_principal_name,
                            alert_type=alert_data['alert_type'],
                            severity=alert_data['severity'],
                            reason=alert_data['reason'],
                            related_signin_event_id=alert_data.get('related_signin_event_id'),
                            related_mfa_event_id=alert_data.get('related_mfa_event_id')
                        )
                        stats['alerts_created'] += 1
                        current_app.logger.info(
                            f"Created {alert_data['alert_type']} alert for {mfa_event.user_principal_name}"
                        )
                    
            except Exception as e:
                stats['errors'] += 1
                current_app.logger.error(f"Error analyzing MFA event {mfa_event.id}: {e}")
        
        db.session.commit()
        current_app.logger.info(
            f"MFA event analysis: {stats['events_analyzed']} analyzed, "
            f"{stats['alerts_created']} alerts created, {stats['errors']} errors"
        )
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Failed to process MFA events for alerts: {e}")
        stats['errors'] += 1
    
    return stats
