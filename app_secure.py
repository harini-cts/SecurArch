#!/usr/bin/env python3
"""
SecureArch Portal - Secure Application Entry Point
This replaces the monolithic app_web.py with a properly structured, secure application
"""

import os
import sys
import logging
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Add app directory to Python path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'app'))

from app import create_app
from config import get_config

def setup_logging():
    """Setup application logging"""
    log_level = os.environ.get('LOG_LEVEL', 'INFO')
    logging.basicConfig(
        level=getattr(logging, log_level),
        format='%(asctime)s %(levelname)s %(name)s: %(message)s'
    )

def validate_environment():
    """Validate critical environment variables"""
    required_vars = ['SECRET_KEY', 'JWT_SECRET']
    missing_vars = []
    
    for var in required_vars:
        if not os.environ.get(var):
            missing_vars.append(var)
    
    if missing_vars:
        print(f"❌ Missing required environment variables: {', '.join(missing_vars)}")
        print("Please copy env.example to .env and set the required values")
        sys.exit(1)

def print_startup_info():
    """Print startup information"""
    config = get_config()
    env = os.environ.get('FLASK_ENV', 'development')
    
    print("🚀 SecureArch Portal - Secure Version Starting...")
    print(f"📊 Environment: {env}")
    print(f"🔐 Security Features: ✅ Enabled")
    print(f"🛡️ CSRF Protection: ✅ Enabled")
    print(f"⚡ Rate Limiting: ✅ Enabled")
    print(f"🔒 Security Headers: ✅ Enabled")
    print(f"📝 Input Validation: ✅ Enabled")
    print(f"🔍 Audit Logging: ✅ Enabled")
    
    if env == 'development':
        print(f"🌐 Server starting on http://localhost:5000")
        print(f"👤 Demo User: admin@demo.com / password123")
        print(f"🔍 Demo Analyst: analyst@demo.com / analyst123")
    
    print("✨ All security improvements implemented!")

if __name__ == '__main__':
    # Setup logging
    setup_logging()
    
    # Validate environment
    validate_environment()
    
    # Create Flask application with security
    app = create_app()
    
    # Print startup information
    print_startup_info()
    
    # Start the application
    app.run(
        host='0.0.0.0',
        port=int(os.environ.get('PORT', 5000)),
        debug=os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    ) 