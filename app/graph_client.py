"""
Microsoft Graph API client for RiskGate.

Authenticates to Microsoft Graph and fetches:
- Sign-in logs
- Directory audit logs (authentication method changes)
- Current authentication methods for users

Environment variables required:
- AZURE_TENANT_ID: Your Azure AD tenant ID
- AZURE_CLIENT_ID: App registration client ID
- AZURE_CLIENT_SECRET: App registration client secret

Required Microsoft Graph permissions:
- AuditLog.Read.All (sign-in logs and audit logs)
- UserAuthenticationMethod.Read.All (authentication methods)
- User.Read.All (user details)
"""
import os
import requests
from datetime import datetime, timedelta
from flask import current_app


class GraphClient:
    """Microsoft Graph API client with authentication."""
    
    def __init__(self):
        self.tenant_id = os.environ.get('AZURE_TENANT_ID')
        self.client_id = os.environ.get('AZURE_CLIENT_ID')
        self.client_secret = os.environ.get('AZURE_CLIENT_SECRET')
        self.access_token = None
        self.token_expires_at = None
        
    def _get_access_token(self):
        """
        Obtain access token using client credentials flow.
        Caches token until expiration.
        """
        # Check if we have a valid cached token
        if self.access_token and self.token_expires_at:
            if datetime.utcnow() < self.token_expires_at:
                return self.access_token
        
        # Check configuration
        if not all([self.tenant_id, self.client_id, self.client_secret]):
            current_app.logger.warning(
                "Microsoft Graph credentials not configured. "
                "Set AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET."
            )
            return None
        
        # Request new token
        token_url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
        data = {
            'grant_type': 'client_credentials',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'scope': 'https://graph.microsoft.com/.default'
        }
        
        try:
            response = requests.post(token_url, data=data, timeout=30)
            response.raise_for_status()
            token_data = response.json()
            
            self.access_token = token_data['access_token']
            expires_in = token_data.get('expires_in', 3600)
            self.token_expires_at = datetime.utcnow() + timedelta(seconds=expires_in - 60)
            
            current_app.logger.info("Successfully obtained Microsoft Graph access token")
            return self.access_token
            
        except Exception as e:
            current_app.logger.error(f"Failed to obtain access token: {e}")
            return None
    
    def _make_request(self, url, params=None):
        """
        Make authenticated request to Microsoft Graph.
        
        Args:
            url: Full Graph API URL
            params: Optional query parameters
        
        Returns:
            Response JSON or None if error
        """
        token = self._get_access_token()
        if not token:
            return None
        
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        
        try:
            response = requests.get(url, headers=headers, params=params, timeout=60)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            current_app.logger.error(f"Graph API request failed for {url}: {e}")
            return None
    
    def fetch_signin_logs(self, hours_back=24, max_results=1000):
        """
        Fetch sign-in logs from Microsoft Graph.
        
        Args:
            hours_back: How many hours of history to fetch (default 24)
            max_results: Maximum number of results (default 1000)
        
        Returns:
            List of sign-in log records
        """
        # Calculate filter timestamp
        filter_time = datetime.utcnow() - timedelta(hours=hours_back)
        filter_time_str = filter_time.strftime('%Y-%m-%dT%H:%M:%SZ')
        
        url = "https://graph.microsoft.com/v1.0/auditLogs/signIns"
        params = {
            '$filter': f"createdDateTime ge {filter_time_str}",
            '$top': max_results,
            '$orderby': 'createdDateTime desc'
        }
        
        current_app.logger.info(f"Fetching sign-in logs from last {hours_back} hours...")
        
        result = self._make_request(url, params)
        if result and 'value' in result:
            signin_logs = result['value']
            current_app.logger.info(f"Fetched {len(signin_logs)} sign-in log entries")
            return signin_logs
        
        current_app.logger.warning("No sign-in logs retrieved")
        return []
    
    def fetch_audit_logs(self, hours_back=24, category='UserManagement', max_results=1000):
        """
        Fetch directory audit logs from Microsoft Graph.
        
        Focus on authentication method changes:
        - User registered security info
        - Authentication method added/removed
        - Admin updated authentication method
        - Temporary Access Pass created
        
        Args:
            hours_back: How many hours of history to fetch (default 24)
            category: Audit log category (default 'UserManagement')
            max_results: Maximum number of results
        
        Returns:
            List of audit log records
        """
        filter_time = datetime.utcnow() - timedelta(hours=hours_back)
        filter_time_str = filter_time.strftime('%Y-%m-%dT%H:%M:%SZ')
        
        url = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits"
        params = {
            '$filter': f"activityDateTime ge {filter_time_str} and category eq '{category}'",
            '$top': max_results,
            '$orderby': 'activityDateTime desc'
        }
        
        current_app.logger.info(f"Fetching audit logs from last {hours_back} hours...")
        
        result = self._make_request(url, params)
        if result and 'value' in result:
            audit_logs = result['value']
            current_app.logger.info(f"Fetched {len(audit_logs)} audit log entries")
            return audit_logs
        
        current_app.logger.warning("No audit logs retrieved")
        return []
    
    def fetch_user_authentication_methods(self, user_id):
        """
        Fetch current authentication methods for a specific user.
        
        Args:
            user_id: Entra user ID (object ID) or user principal name
        
        Returns:
            List of authentication method objects
        """
        url = f"https://graph.microsoft.com/v1.0/users/{user_id}/authentication/methods"
        
        current_app.logger.info(f"Fetching authentication methods for user {user_id}...")
        
        result = self._make_request(url)
        if result and 'value' in result:
            methods = result['value']
            current_app.logger.info(f"User {user_id} has {len(methods)} authentication methods")
            return methods
        
        current_app.logger.warning(f"Could not fetch authentication methods for {user_id}")
        return []
    
    def fetch_user_details(self, user_id):
        """
        Fetch user details from Microsoft Graph.
        
        Args:
            user_id: Entra user ID or user principal name
        
        Returns:
            User object or None
        """
        url = f"https://graph.microsoft.com/v1.0/users/{user_id}"
        
        result = self._make_request(url)
        if result:
            current_app.logger.info(f"Fetched details for user {user_id}")
            return result
        
        return None


# Global instance
graph_client = GraphClient()
