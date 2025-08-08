"""
SecureArch Portal - Restructured Application
Role-based Flask application with blueprints for better organization
"""

import os
import sqlite3
import uuid
from datetime import datetime
from flask import Flask, session, redirect, url_for, send_from_directory, request, flash
from flask_cors import CORS
from werkzeug.security import generate_password_hash
from werkzeug.utils import secure_filename

# Import blueprints
from app.blueprints.auth import auth_bp
from app.blueprints.user import user_bp
from app.blueprints.analyst import analyst_bp
from app.blueprints.admin import admin_bp

# Import shared modules
from app.database import get_db, init_db
from app.workflow import workflow_engine

def create_app():
    """Application factory function"""
    app = Flask(__name__)
    app.secret_key = 'dev-secret-key-change-in-production'
    
    # Configuration
    app.config['SECRET_KEY'] = 'dev-secret-key-change-in-production'
    app.config['JWT_SECRET'] = 'jwt-secret-change-in-production'
    
    # Configure file uploads
    UPLOAD_FOLDER = 'uploads'
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
    ALLOWED_EXTENSIONS = {
        'architecture': {'pdf', 'png', 'jpg', 'jpeg', 'svg', 'vsdx', 'drawio'},
        'document': {'pdf', 'doc', 'docx', 'txt', 'md'}
    }
    
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
    app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE
    app.config['ALLOWED_EXTENSIONS'] = ALLOWED_EXTENSIONS
    
    # Create uploads directory if it doesn't exist
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    os.makedirs(os.path.join(UPLOAD_FOLDER, 'architecture'), exist_ok=True)
    os.makedirs(os.path.join(UPLOAD_FOLDER, 'documents'), exist_ok=True)
    
    # Enable CORS
    CORS(app, origins=['http://localhost:3000', 'http://localhost:5000', 'http://127.0.0.1:5000'])
    
    # Initialize database within application context
    with app.app_context():
        init_db()
    
    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(user_bp)
    app.register_blueprint(analyst_bp)
    app.register_blueprint(admin_bp)
    
    # Health check endpoint
    @app.route('/health')
    def health_check():
        """Health check endpoint"""
        return {'status': 'healthy', 'version': '1.0.0', 'timestamp': datetime.now().isoformat()}
    
    # File download endpoint
    @app.route('/download/<path:filename>')
    def download_file(filename):
        """Download uploaded files (architecture diagrams, documents)"""
        try:
            # Security check: only allow downloading files from uploads directory
            uploads_base = os.path.join(app.root_path, 'uploads')
            
            # Handle both full paths and just filenames
            if filename.startswith('uploads'):
                # Full path stored in database (e.g., uploads\architecture\file.png)
                relative_path = filename.replace('uploads\\', '').replace('uploads/', '')
                file_path = os.path.join(uploads_base, relative_path)
                directory = os.path.dirname(file_path)
                just_filename = os.path.basename(file_path)
            else:
                # Just filename
                file_path = os.path.join(uploads_base, secure_filename(filename))
                directory = uploads_base
                just_filename = secure_filename(filename)
            
            # Verify file exists
            if not os.path.exists(file_path):
                flash('File not found.', 'error')
                return redirect(request.referrer or url_for('auth.home'))
            
            # Additional security: verify the file is within uploads directory (prevent path traversal)
            real_uploads = os.path.realpath(uploads_base)
            real_file = os.path.realpath(file_path)
            if not real_file.startswith(real_uploads):
                flash('Access denied.', 'error')
                return redirect(request.referrer or url_for('auth.home'))
            
            return send_from_directory(directory, just_filename, as_attachment=True)
        
        except Exception as e:
            flash(f'Error downloading file: {str(e)}', 'error')
            return redirect(request.referrer or url_for('auth.home'))
    
    # Legacy route redirects for backward compatibility
    @app.route('/dashboard')
    def legacy_dashboard():
        """Redirect to appropriate dashboard based on role"""
        if 'user_id' not in session:
            return redirect(url_for('auth.login'))
        
        user_role = session.get('user_role', 'user')
        if user_role == 'admin':
            return redirect(url_for('admin.dashboard'))
        elif user_role == 'security_analyst':
            return redirect(url_for('analyst.dashboard'))
        else:
            return redirect(url_for('user.dashboard'))
    
    @app.route('/applications')
    def legacy_applications():
        """Redirect to user applications"""
        return redirect(url_for('user.applications'))
    
    @app.route('/login')
    def legacy_login():
        """Redirect to auth login"""
        return redirect(url_for('auth.login'))
    
    @app.route('/logout')
    def legacy_logout():
        """Redirect to auth logout"""
        return redirect(url_for('auth.logout'))
    
    @app.route('/register')
    def legacy_register():
        """Redirect to auth register"""
        return redirect(url_for('auth.register'))
    
    @app.route('/onboarding')
    def legacy_onboarding():
        """Redirect to auth onboarding"""
        return redirect(url_for('auth.onboarding'))
    
    @app.route('/profile')
    def legacy_profile():
        """Redirect to user profile"""
        return redirect(url_for('user.profile'))
    
    # Additional legacy redirects for analyst and admin
    @app.route('/analyst/dashboard')
    def legacy_analyst_dashboard():
        """Redirect to analyst dashboard"""
        return redirect(url_for('analyst.dashboard'))
    
    @app.route('/admin/dashboard')
    def legacy_admin_dashboard():
        """Redirect to admin dashboard"""
        return redirect(url_for('admin.dashboard'))
    
    return app

if __name__ == '__main__':
    # Create and run Flask app
    app = create_app()
    
    print("🚀 SecureArch Portal (Restructured) starting...")
    print("📊 Database initialized with demo users")
    print("🔐 Role-based authentication system ready")
    print("📋 Security questionnaires loaded")
    print("🛡️ STRIDE threat modeling ready")
    print("🌐 Server starting on http://localhost:5000")
    print("👤 Demo User: admin@demo.com / password123")
    print("🔍 Demo Analyst: analyst@demo.com / analyst123")
    print()
    print("🎯 Role-based Structure:")
    print("   • Users: Application creation and management")
    print("   • Analysts: Security reviews and STRIDE analysis")
    print("   • Admins: System administration and oversight")
    
    app.run(host='0.0.0.0', port=5000, debug=True) 