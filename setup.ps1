# RiskGate Setup Script
# Automates the initial setup process

Write-Host "🛡️ RiskGate - Automated Setup" -ForegroundColor Cyan
Write-Host "==============================`n" -ForegroundColor Cyan

# Check if Python is installed
Write-Host "Checking Python installation..." -ForegroundColor Yellow
try {
    $pythonVersion = python --version 2>&1
    Write-Host "✓ Found: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "✗ Python not found. Please install Python 3.8 or higher." -ForegroundColor Red
    exit 1
}

# Check if pip is installed
Write-Host "`nChecking pip installation..." -ForegroundColor Yellow
try {
    $pipVersion = pip --version 2>&1
    Write-Host "✓ Found: $pipVersion" -ForegroundColor Green
} catch {
    Write-Host "✗ pip not found. Please install pip." -ForegroundColor Red
    exit 1
}

# Install dependencies
Write-Host "`nInstalling Python dependencies..." -ForegroundColor Yellow
pip install -r requirements.txt
if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ Dependencies installed successfully" -ForegroundColor Green
} else {
    Write-Host "✗ Failed to install dependencies" -ForegroundColor Red
    exit 1
}

# Initialize database
Write-Host "`nInitializing database..." -ForegroundColor Yellow

# Check if migrations folder exists
if (Test-Path "migrations") {
    Write-Host "⚠️  Migrations folder already exists. Skipping flask db init." -ForegroundColor Yellow
} else {
    flask db init
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✓ Database initialized" -ForegroundColor Green
    } else {
        Write-Host "✗ Failed to initialize database" -ForegroundColor Red
        exit 1
    }
}

# Create migration
Write-Host "`nCreating database migration..." -ForegroundColor Yellow
flask db migrate -m "Initial migration"
if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ Migration created" -ForegroundColor Green
} else {
    Write-Host "✗ Failed to create migration" -ForegroundColor Red
    exit 1
}

# Apply migration
Write-Host "`nApplying database migration..." -ForegroundColor Yellow
flask db upgrade
if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ Migration applied" -ForegroundColor Green
} else {
    Write-Host "✗ Failed to apply migration" -ForegroundColor Red
    exit 1
}

# Create test data
Write-Host "`nCreating test user..." -ForegroundColor Yellow
python -c @"
from app import create_app, db
from app.models import User

app = create_app()
with app.app_context():
    # Check if test user exists
    existing = User.query.filter_by(email='test@example.com').first()
    if not existing:
        user = User(email='test@example.com', role='user')
        user.set_password('password123')
        db.session.add(user)
        
        admin = User(email='admin@example.com', role='admin')
        admin.set_password('admin123')
        db.session.add(admin)
        
        db.session.commit()
        print('✓ Created test users')
    else:
        print('⚠️  Test users already exist')
"@

# Success message
Write-Host "`n==============================" -ForegroundColor Cyan
Write-Host "✅ Setup Complete!" -ForegroundColor Green
Write-Host "==============================`n" -ForegroundColor Cyan

Write-Host "Test Users Created:" -ForegroundColor Yellow
Write-Host "  • test@example.com (password: password123)" -ForegroundColor White
Write-Host "  • admin@example.com (password: admin123)" -ForegroundColor White

Write-Host "`nTo start the application, run:" -ForegroundColor Yellow
Write-Host "  python run.py" -ForegroundColor White

Write-Host "`nThen open your browser to:" -ForegroundColor Yellow
Write-Host "  http://localhost:5000" -ForegroundColor White

Write-Host "`nFor testing scenarios, see:" -ForegroundColor Yellow
Write-Host "  README.md - Full documentation" -ForegroundColor White
Write-Host "  QUICKSTART.md - Quick testing guide" -ForegroundColor White

Write-Host "`n🛡️ Happy Testing!" -ForegroundColor Cyan
