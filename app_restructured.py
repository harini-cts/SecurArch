"""
SecureArch Portal - Restructured Application
Role-based Flask application with blueprints for better organization
"""

from flask import Flask, session, redirect, url_for
from werkzeug.security import generate_password_hash
import sqlite3
import uuid
from datetime import datetime

# Import blueprints
from app.blueprints.auth import auth_bp
from app.blueprints.user import user_bp
from app.blueprints.analyst import analyst_bp
from app.blueprints.admin import admin_bp

def create_app():
    """Application factory function"""
    app = Flask(__name__)
    app.secret_key = 'dev-secret-key-change-in-production'
    
    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(user_bp)
    app.register_blueprint(analyst_bp)
    app.register_blueprint(admin_bp)
    
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
    
    @app.route('/analyst/dashboard')
    def legacy_analyst_dashboard():
        """Redirect to new analyst dashboard"""
        return redirect(url_for('analyst.dashboard'))
    
    # API routes for notifications (keeping for compatibility)
    @app.route('/api/notifications')
    def api_notifications():
        """Get notifications for current user"""
        from flask import request, jsonify
        
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        
        limit = int(request.args.get('limit', 15))
        user_role = session.get('user_role', 'user')
        
        # Mock notifications for now
        notifications = [
            {
                'id': str(uuid.uuid4()),
                'message': 'Welcome to SecureArch Portal!',
                'read': False,
                'created_at': datetime.now().isoformat()
            }
        ]
        
        return jsonify({'notifications': notifications})
    
    @app.route('/api/notifications/unread-count')
    def api_notification_count():
        """Get unread notification count"""
        from flask import jsonify
        
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        
        # Mock count for now
        return jsonify({'count': 0})
    
    @app.route('/api/notifications/<notification_id>/read', methods=['POST'])
    def api_mark_notification_read(notification_id):
        """Mark notification as read"""
        from flask import jsonify
        
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        
        return jsonify({'success': True})
    
    @app.route('/api/notifications/mark-all-read', methods=['POST'])
    def api_mark_all_read():
        """Mark all notifications as read"""
        from flask import jsonify
        
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        
        return jsonify({'success': True})
    
    return app

def get_db():
    """Get database connection"""
    conn = sqlite3.connect('securearch_portal.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize database with tables"""
    conn = get_db()
    
    # Users table with additional fields
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            organization_name TEXT,
            job_title TEXT,
            experience_level TEXT,
            interests TEXT,
            onboarding_completed BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login_at TIMESTAMP,
            is_active BOOLEAN DEFAULT 1
        )
    ''')
    
    # Applications table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS applications (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT,
            technology_stack TEXT,
            deployment_environment TEXT,
            business_criticality TEXT,
            data_classification TEXT,
            author_id TEXT,
            status TEXT DEFAULT 'draft',
            logical_architecture_file TEXT,
            physical_architecture_file TEXT,
            overview_document_file TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (author_id) REFERENCES users (id)
        )
    ''')
    
    # Security Reviews table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS security_reviews (
            id TEXT PRIMARY KEY,
            application_id TEXT,
            field_type TEXT,
            answers TEXT,
            status TEXT DEFAULT 'draft',
            analyst_id TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (application_id) REFERENCES applications (id),
            FOREIGN KEY (analyst_id) REFERENCES users (id)
        )
    ''')
    
    # STRIDE Analysis table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS stride_analysis (
            id TEXT PRIMARY KEY,
            review_id TEXT,
            threat_category TEXT,
            threat_description TEXT,
            risk_level TEXT,
            mitigation_strategy TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (review_id) REFERENCES security_reviews (id)
        )
    ''')
    
    # Notifications table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS notifications (
            id TEXT PRIMARY KEY,
            user_id TEXT,
            application_id TEXT,
            message TEXT,
            read BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (application_id) REFERENCES applications (id)
        )
    ''')
    
    # Audit logs table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id TEXT PRIMARY KEY,
            user_id TEXT,
            action TEXT,
            details TEXT,
            ip_address TEXT,
            user_agent TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Create demo users if not exists
    existing_demo = conn.execute('SELECT id FROM users WHERE email = ?', ('user@demo.com',)).fetchone()
    if not existing_demo:
        demo_user_id = str(uuid.uuid4())
        demo_password_hash = generate_password_hash('password123')
        conn.execute('''
            INSERT INTO users (id, email, password_hash, first_name, last_name, role, organization_name, onboarding_completed)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (demo_user_id, 'user@demo.com', demo_password_hash, 'John', 'User', 'user', 'SecureArch Corp', 1))
    
    # Create demo Security Analyst if not exists
    existing_analyst = conn.execute('SELECT id FROM users WHERE email = ?', ('analyst@demo.com',)).fetchone()
    if not existing_analyst:
        analyst_user_id = str(uuid.uuid4())
        analyst_password_hash = generate_password_hash('analyst123')
        conn.execute('''
            INSERT INTO users (id, email, password_hash, first_name, last_name, role, organization_name, job_title, onboarding_completed)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (analyst_user_id, 'analyst@demo.com', analyst_password_hash, 'Security', 'Analyst', 'security_analyst', 'SecureArch Corp', 'Senior Security Analyst', 1))
    
    # Create demo Admin if not exists
    existing_admin = conn.execute('SELECT id FROM users WHERE email = ?', ('superadmin@demo.com',)).fetchone()
    if not existing_admin:
        admin_user_id = str(uuid.uuid4())
        admin_password_hash = generate_password_hash('admin123')
        conn.execute('''
            INSERT INTO users (id, email, password_hash, first_name, last_name, role, organization_name, job_title, onboarding_completed)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (admin_user_id, 'superadmin@demo.com', admin_password_hash, 'System', 'Administrator', 'admin', 'SecureArch Corp', 'System Administrator', 1))
    
    conn.commit()
    conn.close()

if __name__ == '__main__':
    # Initialize database
    init_db()
    print("🚀 SecureArch Portal (Restructured) starting...")
    print("📊 Database initialized with demo users")
    print("🔐 Role-based authentication system ready")
    print("📋 Security questionnaires loaded")
    print("🛡️ STRIDE threat modeling ready")
    print("🌐 Server starting on http://localhost:5000")
    print("👤 Demo User: user@demo.com / password123")
    print("🔍 Demo Analyst: analyst@demo.com / analyst123")
    print("🛡️ Demo Admin: superadmin@demo.com / admin123")
    print()
    print("🎯 Role-based Structure:")
    print("   • Users: Application creation and management")
    print("   • Analysts: Security reviews and STRIDE analysis")
    print("   • Admins: System administration and oversight")
    
    # Create and run Flask app
    app = create_app()
    app.run(host='0.0.0.0', port=5000, debug=True) 