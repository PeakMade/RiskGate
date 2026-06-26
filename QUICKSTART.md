# RiskGate - Quick Start Guide

## First Time Setup

Follow these steps to get RiskGate up and running:

### 1. Install Dependencies
```powershell
pip install -r requirements.txt
```

### 2. Initialize Database
```powershell
# Initialize Flask-Migrate
flask db init

# Create initial migration
flask db migrate -m "Initial migration"

# Apply migration to database
flask db upgrade
```

### 3. Run the Application
```powershell
python run.py
```

The application will start on http://localhost:5000

### 4. Test the Security Features

#### Create a Test User
1. Go to http://localhost:5000/login-demo
2. Enter an email (e.g., test@example.com)
3. Select a location and click "Simulate Login"
4. The system will create a test user and log you in

#### Test Impossible Travel Detection
1. Login from "New York, USA"
2. Immediately login again from "Tokyo, Japan"
3. Check the risk score - it should be 60+ (high risk)
4. Go to "Security Alerts" to see the impossible travel alert

#### Test MFA Protection
1. After the impossible travel login, try to add MFA
2. The system should block the attempt with a clear error message
3. Check "MFA Events" to see the blocked attempt logged

#### Test Normal Login
1. Logout and login from the same location twice
2. Risk score should be low
3. Adding MFA should be allowed

## Troubleshooting

### Database Errors
If you get database errors, delete the existing database and migrations:
```powershell
# Remove database file
Remove-Item riskgate.db -ErrorAction SilentlyContinue

# Remove migrations folder
Remove-Item -Recurse -Force migrations -ErrorAction SilentlyContinue

# Re-run initialization
flask db init
flask db migrate -m "Initial migration"
flask db upgrade
```

### Import Errors
Make sure you're in the project root directory and your virtual environment is activated:
```powershell
# Check current directory
Get-Location

# Activate virtual environment (if created)
.\venv\Scripts\Activate.ps1
```

### Port Already in Use
If port 5000 is already in use, you can change it in run.py:
```python
app.run(debug=True, host='0.0.0.0', port=5001)  # Use port 5001 instead
```

## Quick Test Script

Here's a quick test to verify everything is working:

```powershell
# 1. Start Python
python

# 2. Run these commands in Python shell:
from app import create_app, db
from app.models import User

app = create_app()
with app.app_context():
    # Check if database is accessible
    print(f"Users in database: {User.query.count()}")
    
    # Create a test user if none exist
    if User.query.count() == 0:
        user = User(email='admin@example.com', role='admin')
        user.set_password('password123')
        db.session.add(user)
        db.session.commit()
        print("Created admin user")

# 3. Exit Python
exit()

# 4. Start the app
python run.py
```

## Next Steps

1. Read the full README.md for detailed documentation
2. Explore the code in the app/ directory
3. Test different security scenarios
4. Customize configuration in config.py
5. Implement production-ready features (real geolocation, notifications, etc.)

## Production Deployment

For production use, you'll need to:
- Set SECRET_KEY environment variable
- Use PostgreSQL or MySQL instead of SQLite
- Implement real IP geolocation service
- Add proper MFA implementation
- Set up email/SMS notifications
- Enable HTTPS
- Add rate limiting
- Set up monitoring and logging

See README.md for complete production checklist.
