"""
Mock data generator for local testing without Azure Graph API.
Generates realistic sign-in logs with impossible travel scenarios.
"""
from datetime import datetime, timedelta
import random

def generate_mock_signin_logs(target_user='tgaskins@peakmade.com', days_back=7):
    """
    Generate realistic mock sign-in logs for testing.
    Includes some impossible travel scenarios.
    """
    locations = [
        {'city': 'Seattle', 'state': 'Washington', 'countryOrRegion': 'US', 'lat': 47.6062, 'lon': -122.3321},
        {'city': 'New York', 'state': 'New York', 'countryOrRegion': 'US', 'lat': 40.7128, 'lon': -74.0060},
        {'city': 'London', 'state': None, 'countryOrRegion': 'GB', 'lat': 51.5074, 'lon': -0.1278},
        {'city': 'Tokyo', 'state': None, 'countryOrRegion': 'JP', 'lat': 35.6762, 'lon': 139.6503},
        {'city': 'Sydney', 'state': 'New South Wales', 'countryOrRegion': 'AU', 'lat': -33.8688, 'lon': 151.2093},
        {'city': 'Paris', 'state': None, 'countryOrRegion': 'FR', 'lat': 48.8566, 'lon': 2.3522},
        {'city': 'Dubai', 'state': None, 'countryOrRegion': 'AE', 'lat': 25.2048, 'lon': 55.2708},
    ]
    
    apps = [
        'Microsoft Teams',
        'Office 365',
        'Azure Portal',
        'Outlook Web App',
        'SharePoint',
        'Power BI',
        'Microsoft Graph'
    ]
    
    browsers = [
        'Edge 120.0',
        'Chrome 119.0',
        'Firefox 121.0',
        'Safari 17.1'
    ]
    
    logs = []
    current_time = datetime.utcnow()
    
    # Generate normal sign-ins
    for i in range(15):
        timestamp = current_time - timedelta(hours=random.randint(1, days_back * 24))
        location = random.choice(locations[:3])  # Mostly US locations
        
        log = {
            'id': f'mock-signin-{i}',
            'createdDateTime': timestamp.strftime('%Y-%m-%dT%H:%M:%SZ'),
            'userPrincipalName': target_user,
            'userId': 'mock-user-id-12345',
            'appDisplayName': random.choice(apps),
            'clientAppUsed': 'Browser',
            'deviceDetail': {
                'browser': random.choice(browsers),
                'operatingSystem': 'Windows 11'
            },
            'location': {
                'city': location['city'],
                'state': location['state'],
                'countryOrRegion': location['countryOrRegion'],
                'geoCoordinates': {
                    'latitude': location['lat'],
                    'longitude': location['lon']
                }
            },
            'ipAddress': f'192.168.{random.randint(1, 255)}.{random.randint(1, 255)}',
            'status': {
                'errorCode': 0,
                'failureReason': None
            },
            'riskDetail': 'none',
            'riskLevelAggregated': 'none',
            'riskLevelDuringSignIn': 'none',
            'riskState': 'none'
        }
        logs.append(log)
    
    # Add IMPOSSIBLE TRAVEL scenarios (different countries within 2 hours)
    # Scenario 1: Seattle -> Tokyo (1 hour apart - impossible!)
    impossible_time_1 = current_time - timedelta(hours=5)
    logs.append({
        'id': 'mock-signin-impossible-1',
        'createdDateTime': impossible_time_1.strftime('%Y-%m-%dT%H:%M:%SZ'),
        'userPrincipalName': target_user,
        'userId': 'mock-user-id-12345',
        'appDisplayName': 'Office 365',
        'clientAppUsed': 'Browser',
        'deviceDetail': {
            'browser': 'Chrome 119.0',
            'operatingSystem': 'Windows 11'
        },
        'location': locations[0],  # Seattle
        'ipAddress': '192.168.1.100',
        'status': {'errorCode': 0, 'failureReason': None},
        'riskDetail': 'none',
        'riskLevelAggregated': 'none',
        'riskLevelDuringSignIn': 'none',
        'riskState': 'none'
    })
    
    logs.append({
        'id': 'mock-signin-impossible-2',
        'createdDateTime': (impossible_time_1 + timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'userPrincipalName': target_user,
        'userId': 'mock-user-id-12345',
        'appDisplayName': 'Azure Portal',
        'clientAppUsed': 'Browser',
        'deviceDetail': {
            'browser': 'Chrome 119.0',
            'operatingSystem': 'Windows 11'
        },
        'location': locations[3],  # Tokyo
        'ipAddress': '103.45.67.89',
        'status': {'errorCode': 0, 'failureReason': None},
        'riskDetail': 'none',
        'riskLevelAggregated': 'none',
        'riskLevelDuringSignIn': 'none',
        'riskState': 'none'
    })
    
    # Scenario 2: London -> Sydney (2 hours apart - impossible!)
    impossible_time_2 = current_time - timedelta(hours=12)
    logs.append({
        'id': 'mock-signin-impossible-3',
        'createdDateTime': impossible_time_2.strftime('%Y-%m-%dT%H:%M:%SZ'),
        'userPrincipalName': target_user,
        'userId': 'mock-user-id-12345',
        'appDisplayName': 'Microsoft Teams',
        'clientAppUsed': 'Browser',
        'deviceDetail': {
            'browser': 'Edge 120.0',
            'operatingSystem': 'Windows 11'
        },
        'location': locations[2],  # London
        'ipAddress': '81.2.69.142',
        'status': {'errorCode': 0, 'failureReason': None},
        'riskDetail': 'none',
        'riskLevelAggregated': 'none',
        'riskLevelDuringSignIn': 'none',
        'riskState': 'none'
    })
    
    logs.append({
        'id': 'mock-signin-impossible-4',
        'createdDateTime': (impossible_time_2 + timedelta(hours=2)).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'userPrincipalName': target_user,
        'userId': 'mock-user-id-12345',
        'appDisplayName': 'SharePoint',
        'clientAppUsed': 'Browser',
        'deviceDetail': {
            'browser': 'Edge 120.0',
            'operatingSystem': 'Windows 11'
        },
        'location': locations[4],  # Sydney
        'ipAddress': '1.129.88.15',
        'status': {'errorCode': 0, 'failureReason': None},
        'riskDetail': 'none',
        'riskLevelAggregated': 'none',
        'riskLevelDuringSignIn': 'none',
        'riskState': 'none'
    })
    
    # Sort by time (newest first)
    logs.sort(key=lambda x: x['createdDateTime'], reverse=True)
    
    return logs


def generate_mock_user_info(email='tgaskins@peakmade.com'):
    """Generate mock user information."""
    return {
        'id': 'mock-user-id-12345',
        'userPrincipalName': email,
        'displayName': 'Test User',
        'mail': email,
        'accountEnabled': True
    }
