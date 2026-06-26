"""
Application entry point.
Run this file to start the Flask development server.
"""
from app import create_app, db
from app.models import User, LoginEvent, MfaMethod, MfaEvent, SecurityAlert, TrustedDevice

# Create the Flask application instance
app = create_app()


# Shell context processor - makes these objects available in Flask shell
@app.shell_context_processor
def make_shell_context():
    """Add database models to the Flask shell context for easier testing."""
    return {
        'db': db,
        'User': User,
        'LoginEvent': LoginEvent,
        'MfaMethod': MfaMethod,
        'MfaEvent': MfaEvent,
        'SecurityAlert': SecurityAlert,
        'TrustedDevice': TrustedDevice
    }


if __name__ == '__main__':
    # Run the development server
    # debug=True enables auto-reload and detailed error pages
    # host='0.0.0.0' makes the server accessible from other devices on the network
    app.run(debug=True, host='0.0.0.0', port=5003)
