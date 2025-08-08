import os
from datetime import timedelta

class Config:
    """Base configuration class"""
    
    # Security Keys - MUST be set via environment variables
    SECRET_KEY = os.environ.get('SECRET_KEY') or os.urandom(32)
    JWT_SECRET = os.environ.get('JWT_SECRET') or os.urandom(32)
    
    # Database Configuration
    DATABASE_URL = os.environ.get('DATABASE_URL') or 'postgresql://localhost/securearch_portal'
    SQLALCHEMY_DATABASE_URI = DATABASE_URL
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_size': 20,
        'pool_timeout': 20,
        'pool_recycle': -1,
        'max_overflow': 0
    }
    
    # File Upload Settings
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER') or 'uploads'
    MAX_CONTENT_LENGTH = int(os.environ.get('MAX_FILE_SIZE') or 10 * 1024 * 1024)  # 10MB
    ALLOWED_EXTENSIONS = {
        'architecture': {'pdf', 'png', 'jpg', 'jpeg', 'svg', 'vsdx', 'drawio'},
        'document': {'pdf', 'doc', 'docx', 'txt', 'md'}
    }
    
    # Security Settings
    BCRYPT_LOG_ROUNDS = int(os.environ.get('BCRYPT_LOG_ROUNDS') or 12)
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=int(os.environ.get('JWT_ACCESS_TOKEN_HOURS') or 1))
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=int(os.environ.get('JWT_REFRESH_TOKEN_DAYS') or 30))
    
    # Session Configuration
    SESSION_TYPE = 'redis'
    SESSION_REDIS = None  # Will be set in app factory
    SESSION_PERMANENT = False
    SESSION_USE_SIGNER = True
    SESSION_KEY_PREFIX = 'securearch:'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=24)
    
    # CORS Settings
    CORS_ORIGINS = os.environ.get('CORS_ORIGINS', 'http://localhost:3000,http://localhost:5000').split(',')
    
    # Rate Limiting
    RATELIMIT_STORAGE_URL = os.environ.get('REDIS_URL') or 'redis://localhost:6379/1'
    RATELIMIT_DEFAULT = "100 per hour"
    
    # Email Configuration (for notifications)
    MAIL_SERVER = os.environ.get('MAIL_SERVER')
    MAIL_PORT = int(os.environ.get('MAIL_PORT') or 587)
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() in ['true', 'on', '1']
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER') or 'noreply@securearch.com'
    
    # Redis Configuration
    REDIS_URL = os.environ.get('REDIS_URL') or 'redis://localhost:6379/0'
    CACHE_DEFAULT_TIMEOUT = int(os.environ.get('CACHE_DEFAULT_TIMEOUT') or 300)
    
    # Logging
    LOG_LEVEL = os.environ.get('LOG_LEVEL') or 'INFO'
    LOG_TO_STDOUT = os.environ.get('LOG_TO_STDOUT', 'false').lower() in ['true', 'on', '1']

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TESTING = False
    # Use SQLite for development if no PostgreSQL available
    SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URL') or 'sqlite:///securearch_dev.db'

class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False
    BCRYPT_LOG_ROUNDS = 4  # Faster for tests

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    TESTING = False
    
    # Force HTTPS in production
    PREFERRED_URL_SCHEME = 'https'
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # Additional security for production
    WTF_CSRF_TIME_LIMIT = 3600
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)

# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}

def get_config():
    """Get configuration based on environment"""
    env = os.environ.get('FLASK_ENV') or 'default'
    return config.get(env, config['default']) 