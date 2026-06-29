#!/bin/bash
# Startup script for Azure App Service

echo "Starting RiskGate application..."

# Check if we're in Azure (WEBSITE_HOSTNAME is set by Azure)
if [ -n "$WEBSITE_HOSTNAME" ]; then
    echo "Running in Azure App Service"
    
    # Install dependencies if not already installed
    if [ ! -d "antenv" ]; then
        echo "Creating virtual environment and installing dependencies..."
        python -m venv antenv
        source antenv/bin/activate
        pip install --upgrade pip
        pip install -r requirements.txt
    else
        echo "Activating existing virtual environment..."
        source antenv/bin/activate
    fi
    
    # Ensure database URL is properly formatted
    if [ -n "$DATABASE_URL" ]; then
        # Azure PostgreSQL URLs sometimes need adjustment
        export DATABASE_URL=$(echo $DATABASE_URL | sed 's/postgres:/postgresql:/')
        echo "Database URL configured"
    else
        echo "WARNING: DATABASE_URL not set, using SQLite"
    fi
    
    # Run database migrations
    echo "Running database migrations..."
    python -m flask db upgrade || {
        echo "WARNING: Database migration failed or no migrations to run"
    }
    
    echo "Starting Gunicorn..."
    gunicorn --bind=0.0.0.0 --timeout 600 --access-logfile '-' --error-logfile '-' run:app
else
    echo "Running locally..."
    python run.py
fi
