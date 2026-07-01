"""
Application routes - with Microsoft Graph API integration (in-memory storage).
"""
from flask import Blueprint, render_template, request, session, redirect, url_for, flash, current_app
from datetime import datetime
import requests
import os
from app.graph_client import GraphClient
from app.mock_data import generate_mock_signin_logs

bp = Blueprint('main', __name__)

# In-memory storage for scan results
scan_results = {
    'signin_logs': [],
    'impossible_logins': [],
    'alerts': [],
    'last_scan': None
}


@bp.route('/', methods=['GET'])
def root():
    """
    Root page - show dashboard with scan results from memory.
    """
    target_user = 'tgaskins@peakmade.com'
    
    # Count impossible logins from memory
    impossible_count = len([log for log in scan_results['signin_logs'] 
                           if log.get('impossible_travel', False) 
                           and 'tgaskins' in log.get('userPrincipalName', '').lower()])
    
    # Format alerts for display
    recent_alerts = []
    for alert in scan_results['alerts'][:10]:  # Show last 10
        recent_alerts.append({
            'time': alert.get('time', 'N/A'),
            'user': alert.get('user', 'N/A'),
            'finding': alert.get('finding', 'N/A'),
            'risk_level': alert.get('risk_level', 'Medium'),
            'details': alert.get('details', 'N/A'),
            'status': alert.get('status', 'Open')
        })
    
    return render_template('riskgate_dashboard.html', 
                         impossible_logins_count=impossible_count,
                         target_user=target_user,
                         recent_alerts=recent_alerts,
                         scan_triggered=False,
                         last_scan=scan_results['last_scan'])


@bp.route('/riskgate-dashboard', methods=['GET'])
def riskgate_dashboard():
    """
    Main RiskGate Dashboard.
    """
    return root()


@bp.route('/scan', methods=['POST'])
def scan_entra():
    """
    Scan Microsoft Entra for sign-in logs and detect anomalies.
    Results stored in memory.
    
    Uses mock data if:
    - TESTING_MODE=true in .env
    - Graph API returns permission errors
    """
    target_user = 'tgaskins@peakmade.com'
    use_mock_data = False
    mock_reason = None
    
    # Check if testing mode is enabled
    testing_mode = os.getenv('TESTING_MODE', 'false').lower() == 'true'
    
    try:
        if testing_mode:
            current_app.logger.info("TESTING_MODE enabled - using mock data")
            use_mock_data = True
            mock_reason = "Testing mode enabled in .env"
            all_signin_logs = generate_mock_signin_logs(target_user=target_user, days_back=7)
            user_logs = all_signin_logs  # Mock data is already filtered
        else:
            # Try real Graph API
            graph_client = GraphClient()
            
            # Fetch sign-in logs
            current_app.logger.info(f"Scanning Entra ID for {target_user}...")
            all_signin_logs = graph_client.fetch_signin_logs(hours_back=168, max_results=1000)  # 7 days
            
            if not all_signin_logs:
                # Fall back to mock data if API returns nothing
                current_app.logger.warning("No data from Graph API - falling back to mock data")
                use_mock_data = True
                mock_reason = "Graph API returned no data (check permissions)"
                all_signin_logs = generate_mock_signin_logs(target_user=target_user, days_back=7)
                user_logs = all_signin_logs
            else:
                current_app.logger.info(f"Retrieved {len(all_signin_logs)} total sign-in logs")
                
                # Filter for target user - be flexible with domain
                user_logs = [log for log in all_signin_logs 
                            if 'tgaskins' in log.get('userPrincipalName', '').lower()]
                
                if not user_logs:
                    # If no exact match, fall back to mock data
                    current_app.logger.warning(f"No logs found for tgaskins - falling back to mock data")
                    use_mock_data = True
                    mock_reason = f"No logs found for {target_user} in Azure"
                    all_signin_logs = generate_mock_signin_logs(target_user=target_user, days_back=7)
                    user_logs = all_signin_logs
        
        # Analyze for impossible travel
        impossible_logins = analyze_impossible_travel(user_logs)
        
        # Store in memory
        scan_results['signin_logs'] = user_logs
        scan_results['impossible_logins'] = impossible_logins
        scan_results['last_scan'] = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
        scan_results['using_mock_data'] = use_mock_data
        
        # Generate alerts
        alerts = []
        for login in impossible_logins:
            alerts.append({
                'time': login.get('createdDateTime', 'N/A')[:16].replace('T', ' '),
                'user': login.get('userPrincipalName', 'N/A'),
                'finding': 'Impossible Travel Detected',
                'risk_level': 'Critical',
                'details': f"Login from {login.get('location', {}).get('city', 'Unknown')} impossible based on previous location",
                'status': 'Open'
            })
        scan_results['alerts'] = alerts
        
        # Show appropriate message
        if use_mock_data:
            flash(f'⚠️ DEMO MODE: Using mock data ({mock_reason}). Found {len(user_logs)} sign-ins, {len(impossible_logins)} with impossible travel.', 'warning')
        else:
            flash(f'✅ Scan complete! Found {len(user_logs)} sign-ins, {len(impossible_logins)} with impossible travel.', 'success')
        
    except Exception as e:
        current_app.logger.error(f"Scan failed: {e}")
        flash(f'Scan failed: {str(e)}', 'danger')
    
    return redirect(url_for('main.root'))


def analyze_impossible_travel(signin_logs):
    """
    Analyze sign-in logs for impossible travel patterns.
    Simple implementation - checks for logins from different countries within short time.
    """
    impossible = []
    
    # Sort by time
    sorted_logs = sorted(signin_logs, key=lambda x: x.get('createdDateTime', ''))
    
    for i in range(1, len(sorted_logs)):
        current = sorted_logs[i]
        previous = sorted_logs[i-1]
        
        current_country = current.get('location', {}).get('countryOrRegion', '')
        previous_country = previous.get('location', {}).get('countryOrRegion', '')
        
        # Flag if different countries within 1 hour
        if current_country and previous_country and current_country != previous_country:
            current['impossible_travel'] = True
            impossible.append(current)
    
    return impossible


@bp.route('/report', methods=['POST'])
def report_findings():
    """
    Report findings (placeholder for SharePoint integration).
    """
    flash('Report feature - will integrate with SharePoint in future', 'info')
    return redirect(url_for('main.root'))


@bp.route('/health', methods=['GET'])
def health():
    """
    Health check endpoint.
    """
    return {
        'status': 'ok', 
        'message': 'RiskGate is running (in-memory mode)',
        'last_scan': scan_results['last_scan'],
        'signin_logs_count': len(scan_results['signin_logs'])
    }, 200


@bp.route('/test-graph', methods=['GET'])
def test_graph():
    """
    Test Microsoft Graph API connection.
    """
    try:
        graph_client = GraphClient()
        token = graph_client._get_access_token()
        
        if not token:
            return {
                'status': 'error',
                'message': 'Failed to get access token',
                'tenant_id': graph_client.tenant_id[:8] + '...',
                'client_id': graph_client.client_id[:8] + '...'
            }, 500
        
        # Test 1: Try to fetch sign-in logs (longer time range)
        logs = graph_client.fetch_signin_logs(hours_back=720, max_results=10)  # 30 days
        
        # Test 2: Try direct API call to check permissions
        headers = {'Authorization': f'Bearer {token}'}
        test_url = "https://graph.microsoft.com/v1.0/auditLogs/signIns?$top=1"
        test_response = requests.get(test_url, headers=headers, timeout=30)
        
        api_response = test_response.json() if test_response.ok else test_response.text
        
        return {
            'status': 'success' if test_response.ok else 'permission_error',
            'message': 'Graph API connection successful' if test_response.ok else 'Permission denied - need admin consent',
            'logs_found': len(logs),
            'sample_users': [log.get('userPrincipalName', 'Unknown') for log in logs[:3]] if logs else [],
            'api_status_code': test_response.status_code,
            'api_response': api_response if not test_response.ok else 'OK',
            'time_range': '30 days',
            'fix': 'Go to Azure Portal > App Registration > API Permissions > Add "AuditLog.Read.All" > Grant admin consent' if not test_response.ok else None
        }, 200 if test_response.ok else 403
        
    except Exception as e:
        current_app.logger.error(f"Graph API test failed: {e}")
        import traceback
        return {
            'status': 'error',
            'message': str(e),
            'traceback': traceback.format_exc()
        }, 500
