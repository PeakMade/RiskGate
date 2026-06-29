"""
Application factory and initialization.
"""
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate
from config import Config

# Initialize Flask extensions
db = SQLAlchemy()
login_manager = LoginManager()
migrate = Migrate()


def create_app(config_class=Config):
    """
    Application factory pattern.
    Creates and configures the Flask application instance.
    """
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    # Initialize extensions with app
    db.init_app(app)
    login_manager.init_app(app)
    migrate.init_app(app, db)
    
    # Configure Flask-Login
    login_manager.login_view = 'main.login_demo'
    login_manager.login_message = 'Please log in to access this page.'
    
    # Register blueprints
    from app.routes import bp as main_bp
    app.register_blueprint(main_bp)
    
    # Log startup info
    with app.app_context():
        app.logger.info(f"RiskGate starting with database: {app.config['SQLALCHEMY_DATABASE_URI'][:50]}...")
        app.logger.info(f"Azure Client ID configured: {'Yes' if app.config.get('AZURE_CLIENT_ID') else 'No'}")
        app.logger.info(f"Azure Client Secret configured: {'Yes' if app.config.get('AZURE_CLIENT_SECRET') else 'No'}")
    
    return app


# Import models so they are registered with SQLAlchemy
try:
    from app import models, models_new
except Exception as e:
    import logging
    logging.error(f"Error importing models: {e}")
    # Still import at least the base models
    try:
        from app import models
    except Exception as e2:
        logging.error(f"Critical error importing base models: {e2}")
        raise
