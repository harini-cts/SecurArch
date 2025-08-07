"""
SecureArch Portal Application Factory
Creates and configures the Flask application with security best practices
"""

import os
import logging
from flask import Flask
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from flask_talisman import Talisman
from flask_session import Session
import redis

from config import get_config

def create_app(config_name=None):
    """Application factory pattern with security configurations"""
    
    # Create Flask application
    app = Flask(__name__)
    
    # Load configuration
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'development')
    
    config_class = get_config()
    app.config.from_object(config_class)
    
    # Initialize security extensions
    init_security(app)
    
    # Initialize database
    init_database(app)
    
    # Initialize Redis for sessions and caching
    init_redis(app)
    
    # Register blueprints
    register_blueprints(app)
    
    # Configure logging
    configure_logging(app)
    
    # Register error handlers
    register_error_handlers(app)
    
    return app

def init_security(app):
    """Initialize security extensions and configurations"""
    
    # CSRF Protection
    csrf = CSRFProtect(app)
    
    # Security Headers with Talisman
    talisman_config = {
        'force_https': app.config.get('PREFERRED_URL_SCHEME') == 'https',
        'strict_transport_security': True,
        'strict_transport_security_max_age': 31536000,  # 1 year
        'content_security_policy': {
            'default-src': "'self'",
            'script-src': "'self' 'unsafe-inline' 'unsafe-eval'",  # TODO: Remove unsafe-* for production
            'style-src': "'self' 'unsafe-inline' https://fonts.googleapis.com",
            'font-src': "'self' https://fonts.gstatic.com",
            'img-src': "'self' data: https:",
            'connect-src': "'self'",
            'frame-ancestors': "'none'",
            'base-uri': "'self'",
            'form-action': "'self'"
        },
        'referrer_policy': 'strict-origin-when-cross-origin',
        'feature_policy': {
            'geolocation': "'none'",
            'microphone': "'none'",
            'camera': "'none'"
        }
    }
    
    Talisman(app, **talisman_config)
    
    # CORS Configuration
    CORS(app, origins=app.config['CORS_ORIGINS'], supports_credentials=True)
    
    # Rate Limiting
    limiter = Limiter(
        app,
        key_func=get_remote_address,
        default_limits=[app.config['RATELIMIT_DEFAULT']],
        storage_uri=app.config['RATELIMIT_STORAGE_URL']
    )
    
    # Session Configuration with Redis
    app.config['SESSION_REDIS'] = redis.from_url(app.config['REDIS_URL'])
    Session(app)
    
    return app

def init_database(app):
    """Initialize database connection with proper configuration"""
    
    # For now, we'll keep the existing SQLite setup but prepare for PostgreSQL migration
    # This will be replaced with SQLAlchemy in the next phase
    
    from app.database import init_db, migrate_database
    
    with app.app_context():
        init_db()
        migrate_database()

def init_redis(app):
    """Initialize Redis connections for caching and sessions"""
    
    try:
        redis_client = redis.from_url(app.config['REDIS_URL'])
        redis_client.ping()  # Test connection
        app.redis = redis_client
        app.logger.info("Redis connection established")
    except Exception as e:
        app.logger.warning(f"Redis connection failed: {e}")
        app.redis = None

def register_blueprints(app):
    """Register application blueprints"""
    
    # Import and register blueprints
    from app.auth.routes import auth_bp
    from app.main.routes import main_bp
    from app.api.routes import api_bp
    from app.admin.routes import admin_bp
    
    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(api_bp, url_prefix='/api/v1')
    app.register_blueprint(admin_bp, url_prefix='/admin')

def configure_logging(app):
    """Configure application logging"""
    
    if not app.debug and not app.testing:
        # Production logging configuration
        logging.basicConfig(
            level=getattr(logging, app.config['LOG_LEVEL']),
            format='%(asctime)s %(levelname)s %(name)s %(message)s'
        )
        
        # Log to stdout if configured (useful for containers)
        if app.config.get('LOG_TO_STDOUT'):
            stream_handler = logging.StreamHandler()
            stream_handler.setLevel(logging.INFO)
            app.logger.addHandler(stream_handler)
    
    app.logger.setLevel(getattr(logging, app.config.get('LOG_LEVEL', 'INFO')))

def register_error_handlers(app):
    """Register error handlers with secure error responses"""
    
    @app.errorhandler(400)
    def bad_request(error):
        return {'error': 'Bad request', 'code': 400}, 400
    
    @app.errorhandler(401)
    def unauthorized(error):
        return {'error': 'Unauthorized', 'code': 401}, 401
    
    @app.errorhandler(403)
    def forbidden(error):
        return {'error': 'Forbidden', 'code': 403}, 403
    
    @app.errorhandler(404)
    def not_found(error):
        return {'error': 'Not found', 'code': 404}, 404
    
    @app.errorhandler(429)
    def ratelimit_handler(error):
        return {'error': 'Rate limit exceeded', 'code': 429}, 429
    
    @app.errorhandler(500)
    def internal_error(error):
        app.logger.error(f'Server Error: {error}')
        return {'error': 'Internal server error', 'code': 500}, 500
    
    @app.errorhandler(CSRFError)
    def handle_csrf_error(e):
        return {'error': 'CSRF token missing or invalid', 'code': 400}, 400

# Import for CSRF error handling
from flask_wtf.csrf import CSRFError 