"""
Application factory and initialization.
"""
from flask import Flask
from config import Config


def create_app(config_class=Config):
    """
    Application factory pattern.
    Creates and configures the Flask application instance.
    """
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    # Register context processor to make config available in templates
    @app.context_processor
    def inject_config():
        return {'config': app.config}
    
    # Register blueprints
    from app.routes import bp as main_bp
    app.register_blueprint(main_bp)
    
    # Log startup info
    with app.app_context():
        app.logger.info("RiskGate starting (simplified version - no database)...")
        app.logger.info(f"Azure Client ID configured: {'Yes' if app.config.get('AZURE_CLIENT_ID') else 'No'}")
        app.logger.info(f"Azure Client Secret configured: {'Yes' if app.config.get('AZURE_CLIENT_SECRET') else 'No'}")
    
    return app

