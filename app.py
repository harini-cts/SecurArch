#!/usr/bin/env python3
"""
SecureArch Portal - Main Flask Application
Enterprise-grade Security Architecture Review Platform
"""

import os
from datetime import datetime, timedelta, timezone
from flask import Flask, jsonify, request, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv
import structlog

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)

# Configuration
class Config:
    # Flask Settings
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    
    # Database Configuration
    DB_HOST = os.environ.get('DB_HOST', 'localhost')
    DB_PORT = os.environ.get('DB_PORT', '5432')
    DB_NAME = os.environ.get('DB_NAME', 'securearch_portal')
    DB_USER = os.environ.get('DB_USER', 'securearch_user')
    DB_PASSWORD = os.environ.get('DB_PASSWORD', '')
    
    # For development - use SQLite (no PostgreSQL setup needed)
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///securearch_portal.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
        'pool_timeout': 20,
        'max_overflow': 0
    }
    
    # JWT Configuration
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET', 'jwt-secret-change-in-production')
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=8)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=7)
    
    # Security Settings
    BCRYPT_LOG_ROUNDS = int(os.environ.get('BCRYPT_ROUNDS', '12'))
    
    # Rate Limiting
    RATELIMIT_STORAGE_URL = os.environ.get('REDIS_URL', 'memory://')
    
    # CORS Settings
    CORS_ORIGINS = os.environ.get('CORS_ORIGINS', 'http://localhost:3000,http://localhost:5000').split(',')

app.config.from_object(Config)

# Import db from models and initialize with app
from models import db
db.init_app(app)

# Initialize Extensions
migrate = Migrate(app, db)
cors = CORS(app, origins=Config.CORS_ORIGINS)
jwt = JWTManager(app)
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["100 per hour", "20 per minute"]
)
limiter.init_app(app)

# Configure Logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger(__name__)

# Import models after app initialization
from models import User, Organization, Application, Review, Finding
from routes.auth import auth_bp
from routes.applications import applications_bp
from routes.reviews import reviews_bp
from routes.dashboard import dashboard_bp

# Register Blueprints
app.register_blueprint(auth_bp, url_prefix='/api/v1/auth')
app.register_blueprint(applications_bp, url_prefix='/api/v1/applications')
app.register_blueprint(reviews_bp, url_prefix='/api/v1/reviews')
app.register_blueprint(dashboard_bp, url_prefix='/api/v1/dashboard')

# Home Route
@app.route('/')
def home():
    """Home page with API information"""
    # Check if request wants JSON (API client)
    if request.headers.get('Accept') == 'application/json' or request.args.get('format') == 'json':
        return jsonify({
            'message': 'Welcome to SecureArch Portal',
            'description': 'Enterprise-grade Security Architecture Review Platform',
            'version': '1.0.0',
            'status': 'running',
            'api_endpoints': {
                'authentication': '/api/v1/auth',
                'applications': '/api/v1/applications',
                'reviews': '/api/v1/reviews',
                'dashboard': '/api/v1/dashboard',
                'health': '/health'
            },
            'documentation': {
                'swagger': '/api/docs',
                'redoc': '/api/redoc'
            }
        })
    
    # Render HTML template for browser users
    try:
        return render_template('home.html')
    except:
        # Fallback if template not found
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>SecureArch Portal</title>
            <style>
                body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
                .header { text-align: center; color: #2c3e50; }
                .api-info { background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0; }
                .endpoint { background: #e9ecef; padding: 10px; margin: 5px 0; border-radius: 4px; }
                .status { color: #28a745; font-weight: bold; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🔐 SecureArch Portal</h1>
                <p>Enterprise-grade Security Architecture Review Platform</p>
                <p class="status">✅ Status: Running</p>
            </div>
            
            <div class="api-info">
                <h2>API Endpoints</h2>
                <div class="endpoint"><strong>Authentication:</strong> /api/v1/auth</div>
                <div class="endpoint"><strong>Applications:</strong> /api/v1/applications</div>
                <div class="endpoint"><strong>Reviews:</strong> /api/v1/reviews</div>
                <div class="endpoint"><strong>Dashboard:</strong> /api/v1/dashboard</div>
                <div class="endpoint"><strong>Health Check:</strong> /health</div>
            </div>
            
            <div class="api-info">
                <h2>Documentation</h2>
                <div class="endpoint"><strong>Swagger UI:</strong> /api/docs</div>
                <div class="endpoint"><strong>ReDoc:</strong> /api/redoc</div>
            </div>
            
            <p style="text-align: center; color: #6c757d; margin-top: 40px;">
                Version 1.0.0 | 
                <a href="?format=json">View as JSON</a>
            </p>
        </body>
        </html>
        """

# Health Check Endpoint
@app.route('/health')
def health_check():
    """Application health check endpoint"""
    try:
        # Test database connection
        from sqlalchemy import text
        db.session.execute(text('SELECT 1'))
        db_status = 'healthy'
    except Exception as e:
        db_status = f'unhealthy: {str(e)}'
        logger.error("Database health check failed", error=str(e))
    
    health_data = {
        'status': 'healthy' if db_status == 'healthy' else 'unhealthy',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'version': '1.0.0',
        'environment': os.environ.get('FLASK_ENV', 'development'),
        'database': {
            'status': db_status,
            'type': 'PostgreSQL'
        },
        'services': {
            'authentication': 'active',
            'authorization': 'active',
            'owasp_engine': 'ready'
        }
    }
    
    status_code = 200 if health_data['status'] == 'healthy' else 503
    return jsonify(health_data), status_code

# Application Info Endpoint
@app.route('/api/v1/info')
def app_info():
    """Application information endpoint"""
    return jsonify({
        'name': 'SecureArch Portal',
        'description': 'Enterprise Security Architecture Review Platform',
        'version': '1.0.0',
        'api_version': 'v1',
        'owasp_standards': ['ASVS', 'Top 10', 'Proactive Controls', 'SAMM'],
        'features': [
            'JWT Authentication',
            'Role-based Access Control',
            'Security Architecture Review',
            'OWASP Standards Assessment',
            'Expert Review Workflow',
            'Compliance Reporting'
        ],
        'endpoints': {
            'health': '/health',
            'auth': '/api/v1/auth/*',
            'applications': '/api/v1/applications/*',
            'reviews': '/api/v1/reviews/*',
            'dashboard': '/api/v1/dashboard/*'
        }
    })

# Error Handlers
@app.errorhandler(400)
def bad_request(error):
    logger.warning("Bad request", error=str(error))
    return jsonify({
        'error': 'Bad Request',
        'message': 'The request could not be understood by the server',
        'code': 'BAD_REQUEST'
    }), 400

@app.errorhandler(401)
def unauthorized(error):
    logger.warning("Unauthorized access attempt", error=str(error))
    return jsonify({
        'error': 'Unauthorized',
        'message': 'Authentication is required to access this resource',
        'code': 'UNAUTHORIZED'
    }), 401

@app.errorhandler(403)
def forbidden(error):
    logger.warning("Forbidden access attempt", error=str(error))
    return jsonify({
        'error': 'Forbidden',
        'message': 'You do not have permission to access this resource',
        'code': 'FORBIDDEN'
    }), 403

@app.errorhandler(404)
def not_found(error):
    return jsonify({
        'error': 'Not Found',
        'message': 'The requested resource was not found',
        'code': 'NOT_FOUND'
    }), 404

@app.errorhandler(429)
def ratelimit_handler(e):
    logger.warning("Rate limit exceeded", 
                  limit=str(e.limit), 
                  ip=get_remote_address())
    return jsonify({
        'error': 'Rate Limit Exceeded',
        'message': f'Rate limit exceeded: {e.description}',
        'code': 'RATE_LIMIT_EXCEEDED'
    }), 429

@app.errorhandler(500)
def internal_error(error):
    logger.error("Internal server error", error=str(error))
    db.session.rollback()
    return jsonify({
        'error': 'Internal Server Error',
        'message': 'An unexpected error occurred',
        'code': 'INTERNAL_ERROR'
    }), 500

# JWT Error Handlers
@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    logger.warning("Expired token used", user_id=jwt_payload.get('sub'))
    return jsonify({
        'error': 'Token Expired',
        'message': 'The JWT token has expired',
        'code': 'TOKEN_EXPIRED'
    }), 401

@jwt.invalid_token_loader
def invalid_token_callback(error):
    logger.warning("Invalid token used", error=str(error))
    return jsonify({
        'error': 'Invalid Token',
        'message': 'The JWT token is invalid',
        'code': 'TOKEN_INVALID'
    }), 401

@jwt.unauthorized_loader
def missing_token_callback(error):
    logger.warning("Missing token", error=str(error))
    return jsonify({
        'error': 'Authorization Required',
        'message': 'Request does not contain an access token',
        'code': 'TOKEN_MISSING'
    }), 401

# Request/Response Logging
@app.before_request
def log_request_info():
    if request.endpoint != 'health_check':
        logger.info("Request received",
                   method=request.method,
                   path=request.path,
                   ip=get_remote_address(),
                   user_agent=request.headers.get('User-Agent'))

@app.after_request
def log_response_info(response):
    if request.endpoint != 'health_check':
        logger.info("Response sent",
                   method=request.method,
                   path=request.path,
                   status_code=response.status_code,
                   ip=get_remote_address())
    return response

# Database Creation
with app.app_context():
    """Create database tables"""
    try:
        db.create_all()
        logger.info("Database tables created successfully")
    except Exception as e:
        logger.error("Failed to create database tables", error=str(e))

if __name__ == '__main__':
    # Development server
    host = os.environ.get('HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') == 'development'
    
    logger.info("Starting SecureArch Portal",
               host=host,
               port=port,
               debug=debug,
               environment=os.environ.get('FLASK_ENV', 'development'))
    
    app.run(host=host, port=port, debug=debug) 