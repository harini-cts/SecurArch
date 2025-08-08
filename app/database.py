"""
Database module with secure connection handling and migration support
"""

import os
import uuid
import sqlite3
import logging
from datetime import datetime, timedelta
from flask import current_app, g
from werkzeug.security import generate_password_hash
from contextlib import contextmanager

logger = logging.getLogger(__name__)

def get_db():
    """Get database connection with proper error handling"""
    if 'db' not in g:
        try:
            # For now using SQLite, but prepared for PostgreSQL migration
            database_path = current_app.config.get('SQLALCHEMY_DATABASE_URI', 'sqlite:///securearch_portal.db')
            
            if database_path.startswith('sqlite:'):
                db_file = database_path.replace('sqlite:///', '')
                g.db = sqlite3.connect(db_file)
                g.db.row_factory = sqlite3.Row
                g.db.execute('PRAGMA foreign_keys = ON')  # Enable foreign key constraints
                g.db.execute('PRAGMA journal_mode = WAL')  # Better concurrency
            else:
                # PostgreSQL connection would go here
                raise NotImplementedError("PostgreSQL migration not yet implemented")
                
        except Exception as e:
            logger.error(f"Database connection failed: {e}")
            raise
    
    return g.db

def close_db(e=None):
    """Close database connection"""
    db = g.pop('db', None)
    if db is not None:
        db.close()

@contextmanager
def get_db_transaction():
    """Context manager for database transactions with automatic rollback on error"""
    conn = get_db()
    try:
        yield conn
        conn.commit()
    except Exception as e:
        conn.rollback()
        logger.error(f"Database transaction failed: {e}")
        raise
    finally:
        close_db()

def init_db():
    """Initialize database with tables and security constraints"""
    conn = get_db()
    
    try:
        # Users table with enhanced security
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                first_name TEXT NOT NULL,
                last_name TEXT NOT NULL,
                role TEXT DEFAULT 'user' CHECK (role IN ('user', 'security_analyst', 'admin')),
                organization_name TEXT,
                job_title TEXT,
                experience_level TEXT CHECK (experience_level IN ('junior', 'intermediate', 'senior')),
                interests TEXT,
                onboarding_completed BOOLEAN DEFAULT 0,
                is_active BOOLEAN DEFAULT 1,
                email_verified BOOLEAN DEFAULT 0,
                two_factor_enabled BOOLEAN DEFAULT 0,
                failed_login_attempts INTEGER DEFAULT 0,
                account_locked_until TIMESTAMP,
                password_changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login_at TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Applications table with enhanced validation
        conn.execute('''
            CREATE TABLE IF NOT EXISTS applications (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL CHECK (length(name) > 0 AND length(name) <= 255),
                description TEXT CHECK (length(description) <= 2000),
                technology_stack TEXT,
                deployment_environment TEXT CHECK (deployment_environment IN ('development', 'staging', 'production', 'hybrid')),
                business_criticality TEXT CHECK (business_criticality IN ('Low', 'Medium', 'High', 'Critical')),
                data_classification TEXT CHECK (data_classification IN ('Public', 'Internal', 'Confidential', 'Restricted')),
                author_id TEXT NOT NULL,
                status TEXT DEFAULT 'draft' CHECK (status IN ('draft', 'submitted', 'in_review', 'completed', 'rejected')),
                logical_architecture_file TEXT,
                physical_architecture_file TEXT,
                overview_document_file TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (author_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')
        
        # Security Reviews table with audit trail
        conn.execute('''
            CREATE TABLE IF NOT EXISTS security_reviews (
                id TEXT PRIMARY KEY,
                application_id TEXT NOT NULL,
                field_type TEXT CHECK (field_type IN ('application_review', 'cloud_review', 'mobile_review')),
                questionnaire_responses TEXT, -- JSON data
                additional_comments TEXT CHECK (length(additional_comments) <= 5000),
                screenshots TEXT, -- JSON array of file paths
                status TEXT DEFAULT 'draft' CHECK (status IN ('draft', 'submitted', 'in_review', 'completed', 'rejected')),
                risk_score REAL CHECK (risk_score >= 0 AND risk_score <= 10),
                author_id TEXT NOT NULL,
                analyst_id TEXT,
                analyst_reviewed_at TIMESTAMP,
                stride_analysis TEXT, -- JSON data
                final_report TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (application_id) REFERENCES applications (id) ON DELETE CASCADE,
                FOREIGN KEY (author_id) REFERENCES users (id),
                FOREIGN KEY (analyst_id) REFERENCES users (id)
            )
        ''')
        
        # Notifications table with expiration
        conn.execute('''
            CREATE TABLE IF NOT EXISTS notifications (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL CHECK (length(title) > 0 AND length(title) <= 255),
                message TEXT NOT NULL CHECK (length(message) > 0 AND length(message) <= 1000),
                type TEXT DEFAULT 'info' CHECK (type IN ('info', 'warning', 'error', 'success')),
                application_id TEXT,
                user_id TEXT,
                target_role TEXT CHECK (target_role IN ('user', 'security_analyst', 'admin') OR target_role IS NULL),
                read_by TEXT DEFAULT '[]', -- JSON array of user IDs
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                FOREIGN KEY (application_id) REFERENCES applications (id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')
        
        # STRIDE Analysis table for threat modeling
        conn.execute('''
            CREATE TABLE IF NOT EXISTS stride_analysis (
                id TEXT PRIMARY KEY,
                review_id TEXT NOT NULL,
                threat_category TEXT CHECK (threat_category IN ('spoofing', 'tampering', 'repudiation', 'information_disclosure', 'denial_of_service', 'elevation_of_privilege')),
                threat_description TEXT NOT NULL CHECK (length(threat_description) > 0),
                risk_level TEXT CHECK (risk_level IN ('Low', 'Medium', 'High', 'Critical')),
                mitigation_status TEXT DEFAULT 'pending' CHECK (mitigation_status IN ('pending', 'in_progress', 'completed', 'not_applicable')),
                question_id TEXT,
                recommendations TEXT CHECK (length(recommendations) <= 2000),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (review_id) REFERENCES security_reviews (id) ON DELETE CASCADE
            )
        ''')
        
        # Audit log table for security monitoring
        conn.execute('''
            CREATE TABLE IF NOT EXISTS audit_logs (
                id TEXT PRIMARY KEY,
                user_id TEXT,
                action TEXT NOT NULL,
                resource_type TEXT,
                resource_id TEXT,
                details TEXT, -- JSON data
                ip_address TEXT,
                user_agent TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Create indexes for performance
        create_indexes(conn)
        
        # Create demo users with secure defaults
        create_demo_users(conn)
        
        conn.commit()
        logger.info("Database initialized successfully")
        
    except Exception as e:
        conn.rollback()
        logger.error(f"Database initialization failed: {e}")
        raise

def create_indexes(conn):
    """Create database indexes for performance"""
    indexes = [
        "CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)",
        "CREATE INDEX IF NOT EXISTS idx_users_role_active ON users(role, is_active)",
        "CREATE INDEX IF NOT EXISTS idx_applications_author_created ON applications(author_id, created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_applications_status ON applications(status)",
        "CREATE INDEX IF NOT EXISTS idx_security_reviews_app_status ON security_reviews(application_id, status)",
        "CREATE INDEX IF NOT EXISTS idx_security_reviews_analyst ON security_reviews(analyst_id)",
        "CREATE INDEX IF NOT EXISTS idx_notifications_user_created ON notifications(user_id, created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_notifications_role_created ON notifications(target_role, created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_stride_analysis_review ON stride_analysis(review_id)",
        "CREATE INDEX IF NOT EXISTS idx_audit_logs_user_created ON audit_logs(user_id, created_at DESC)"
    ]
    
    for index_sql in indexes:
        try:
            conn.execute(index_sql)
        except Exception as e:
            logger.warning(f"Index creation failed: {e}")

def create_demo_users(conn):
    """Create demo users with secure password hashing"""
    
    # Check if demo users already exist
    existing_demo = conn.execute('SELECT id FROM users WHERE email = ?', ('admin@demo.com',)).fetchone()
    if not existing_demo:
        demo_user_id = str(uuid.uuid4())
        # Use strong password hashing
        demo_password_hash = generate_password_hash('password123', method='pbkdf2:sha256', salt_length=16)
        
        conn.execute('''
            INSERT INTO users (
                id, email, password_hash, first_name, last_name, role, 
                organization_name, onboarding_completed
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (demo_user_id, 'admin@demo.com', demo_password_hash, 'Demo', 'User', 
              'user', 'SecureArch Corp', 1))
        
        logger.info("Created demo user: admin@demo.com")
    
    # Create demo Security Analyst
    existing_analyst = conn.execute('SELECT id FROM users WHERE email = ?', ('analyst@demo.com',)).fetchone()
    if not existing_analyst:
        analyst_user_id = str(uuid.uuid4())
        analyst_password_hash = generate_password_hash('analyst123', method='pbkdf2:sha256', salt_length=16)
        
        conn.execute('''
            INSERT INTO users (
                id, email, password_hash, first_name, last_name, role, 
                organization_name, job_title, onboarding_completed
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (analyst_user_id, 'analyst@demo.com', analyst_password_hash, 'Security', 'Analyst', 
              'security_analyst', 'SecureArch Corp', 'Senior Security Analyst', 1))
        
        logger.info("Created demo analyst: analyst@demo.com")

def migrate_database():
    """Handle database migrations with proper error handling"""
    conn = get_db()
    
    try:
        # Check current schema version (could be stored in a migrations table)
        # For now, just check if new columns exist
        
        # Migration 1: Add security columns to users table
        try:
            conn.execute('SELECT email_verified FROM users LIMIT 1')
        except sqlite3.OperationalError:
            migration_add_security_columns(conn)
        
        # Migration 2: Add audit_logs table
        try:
            conn.execute('SELECT id FROM audit_logs LIMIT 1')
        except sqlite3.OperationalError:
            migration_add_audit_logs(conn)
        
        conn.commit()
        logger.info("Database migration completed successfully")
        
    except Exception as e:
        conn.rollback()
        logger.error(f"Database migration failed: {e}")
        raise

def migration_add_security_columns(conn):
    """Add security-related columns to users table"""
    security_columns = [
        'ALTER TABLE users ADD COLUMN email_verified BOOLEAN DEFAULT 0',
        'ALTER TABLE users ADD COLUMN two_factor_enabled BOOLEAN DEFAULT 0',
        'ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER DEFAULT 0',
        'ALTER TABLE users ADD COLUMN account_locked_until TIMESTAMP',
        'ALTER TABLE users ADD COLUMN password_changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP',
        'ALTER TABLE users ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP'
    ]
    
    for column_sql in security_columns:
        try:
            conn.execute(column_sql)
            logger.info(f"Added security column: {column_sql}")
        except sqlite3.OperationalError:
            pass  # Column already exists

def migration_add_audit_logs(conn):
    """Add audit logs table for security monitoring"""
    conn.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id TEXT PRIMARY KEY,
            user_id TEXT,
            action TEXT NOT NULL,
            resource_type TEXT,
            resource_id TEXT,
            details TEXT,
            ip_address TEXT,
            user_agent TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    logger.info("Created audit_logs table")

def log_user_action(user_id, action, resource_type=None, resource_id=None, details=None, ip_address=None, user_agent=None):
    """Log user actions for security auditing"""
    try:
        conn = get_db()
        audit_id = str(uuid.uuid4())
        
        conn.execute('''
            INSERT INTO audit_logs (
                id, user_id, action, resource_type, resource_id, 
                details, ip_address, user_agent
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (audit_id, user_id, action, resource_type, resource_id, 
              details, ip_address, user_agent))
        
        conn.commit()
        
    except Exception as e:
        logger.error(f"Failed to log user action: {e}")

def cleanup_expired_data():
    """Clean up expired notifications and old audit logs"""
    try:
        conn = get_db()
        
        # Remove expired notifications
        expired_count = conn.execute('''
            DELETE FROM notifications 
            WHERE expires_at IS NOT NULL AND expires_at < CURRENT_TIMESTAMP
        ''').rowcount
        
        # Remove old audit logs (keep 90 days)
        old_logs_count = conn.execute('''
            DELETE FROM audit_logs 
            WHERE created_at < datetime('now', '-90 days')
        ''').rowcount
        
        conn.commit()
        
        if expired_count > 0 or old_logs_count > 0:
            logger.info(f"Cleaned up {expired_count} expired notifications and {old_logs_count} old audit logs")
            
    except Exception as e:
        logger.error(f"Data cleanup failed: {e}") 