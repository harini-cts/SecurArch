#!/usr/bin/env python3
"""
SecureArch Portal - Complete Web Application
Enterprise-grade Security Architecture Review Platform with Web Interface
"""

import os
import json
import uuid
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_from_directory, Response
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import jwt
from functools import wraps
from werkzeug.utils import secure_filename
from app.workflow import workflow_engine
import io, csv

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'dev-secret-key-change-in-production'

# Configuration
app.config['SECRET_KEY'] = 'dev-secret-key-change-in-production'
app.config['JWT_SECRET'] = 'jwt-secret-change-in-production'
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0

# Enable CORS
CORS(app, origins=['http://localhost:3000', 'http://localhost:5000', 'http://127.0.0.1:5000'])

# Database setup
DATABASE = 'securearch_portal.db'

# Configure file uploads
UPLOAD_FOLDER = 'uploads'
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
ALLOWED_EXTENSIONS = {
    'architecture': {'pdf', 'png', 'jpg', 'jpeg', 'svg', 'vsdx', 'drawio'},
    'document': {'pdf', 'doc', 'docx', 'txt', 'md'}
}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

# Create uploads directory if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(os.path.join(UPLOAD_FOLDER, 'architecture'), exist_ok=True)
os.makedirs(os.path.join(UPLOAD_FOLDER, 'documents'), exist_ok=True)

def get_db():
    """Get database connection"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def migrate_database():
    """Migrate existing database to support STRIDE analysis"""
    conn = get_db()
    
    try:
        # Check if analyst_id column exists in security_reviews
        conn.execute('SELECT analyst_id FROM security_reviews LIMIT 1')
        # Also check if stride_analysis table has question_id column
        conn.execute('SELECT question_id FROM stride_analysis LIMIT 1')
        print("📊 Database schema is up to date")
    except sqlite3.OperationalError:
        # Add missing columns to security_reviews table
        print("🔧 Migrating database schema for STRIDE analysis...")
        try:
            conn.execute('ALTER TABLE security_reviews ADD COLUMN analyst_id TEXT')
            print("   ✅ Added analyst_id column")
        except sqlite3.OperationalError:
            pass
        try:
            conn.execute('ALTER TABLE security_reviews ADD COLUMN stride_analysis TEXT')
            print("   ✅ Added stride_analysis column")
        except sqlite3.OperationalError:
            pass
        try:
            conn.execute('ALTER TABLE security_reviews ADD COLUMN final_report TEXT')
            print("   ✅ Added final_report column")
        except sqlite3.OperationalError:
            pass
        try:
            conn.execute('ALTER TABLE security_reviews ADD COLUMN analyst_reviewed_at TIMESTAMP')
            print("   ✅ Added analyst_reviewed_at column")
        except sqlite3.OperationalError:
            pass
        try:
            conn.execute('ALTER TABLE security_reviews ADD COLUMN recommendations TEXT')
            print("   ✅ Added recommendations column")
        except sqlite3.OperationalError:
            pass
        
        # Check if stride_analysis table needs updating
        try:
            # Test if question_id column exists
            conn.execute('SELECT question_id FROM stride_analysis LIMIT 1')
            print("   ✅ stride_analysis table is up to date")
        except sqlite3.OperationalError:
            # Drop and recreate stride_analysis table with correct schema
            print("   🔧 Updating stride_analysis table schema...")
            conn.execute('DROP TABLE IF EXISTS stride_analysis')
            conn.execute('''
                CREATE TABLE stride_analysis (
                    id TEXT PRIMARY KEY,
                    review_id TEXT,
                    threat_category TEXT,
                    threat_description TEXT,
                    risk_level TEXT,
                    mitigation_status TEXT,
                    question_id TEXT,
                    recommendations TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (review_id) REFERENCES security_reviews (id)
                )
            ''')
            print("   ✅ Updated stride_analysis table with new schema")
        
        # Check if audit_logs table exists
        try:
            conn.execute('SELECT id FROM audit_logs LIMIT 1')
            print("   ✅ audit_logs table exists")
        except sqlite3.OperationalError:
            print("   🔧 Creating audit_logs table...")
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
            print("   ✅ Created audit_logs table")
        
        print("🎉 Database migration completed successfully!")
    
    conn.commit()
    conn.close()

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
    
    # Add file columns if they don't exist (migration)
    try:
        conn.execute('ALTER TABLE applications ADD COLUMN logical_architecture_file TEXT')
    except:
        pass
    try:
        conn.execute('ALTER TABLE applications ADD COLUMN physical_architecture_file TEXT')
    except:
        pass
    try:
        conn.execute('ALTER TABLE applications ADD COLUMN overview_document_file TEXT')
    except:
        pass
    try:
        conn.execute('ALTER TABLE applications ADD COLUMN cloud_review_required TEXT DEFAULT "no"')
    except:
        pass
    try:
        conn.execute('ALTER TABLE applications ADD COLUMN cloud_providers TEXT')
    except:
        pass
    
    # Add database review columns
    try:
        conn.execute('ALTER TABLE applications ADD COLUMN database_review_required TEXT DEFAULT "no"')
        print("✅ Added database_review_required column")
    except Exception as e:
        print(f"ℹ️ database_review_required column already exists or error: {e}")
    try:
        conn.execute('ALTER TABLE applications ADD COLUMN database_types TEXT DEFAULT ""')
        print("✅ Added database_types column")
    except Exception as e:
        print(f"ℹ️ database_types column already exists or error: {e}")
    
    # Add category preferences columns
    try:
        conn.execute('ALTER TABLE applications ADD COLUMN category_preferences TEXT DEFAULT "{}"')
        print("✅ Added category_preferences column")
    except Exception as e:
        print(f"ℹ️ category_preferences column already exists or error: {e}")
    
    # Security Reviews table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS security_reviews (
            id TEXT PRIMARY KEY,
            application_id TEXT,
            field_type TEXT,
            questionnaire_responses TEXT,
            additional_comments TEXT,
            screenshots TEXT,
            status TEXT DEFAULT 'draft',
            risk_score REAL,
            recommendations TEXT,
            author_id TEXT,
            analyst_id TEXT,
            analyst_reviewed_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (application_id) REFERENCES applications (id),
            FOREIGN KEY (author_id) REFERENCES users (id),
            FOREIGN KEY (analyst_id) REFERENCES users (id)
        )
    ''')
    
    # Add recommendations column if it doesn't exist (migration)
    try:
        conn.execute('ALTER TABLE security_reviews ADD COLUMN recommendations TEXT')
        print("   ✅ Added recommendations column")
    except sqlite3.OperationalError:
        pass
    
    # Notifications table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS notifications (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            type TEXT DEFAULT 'info',
            application_id TEXT,
            user_id TEXT,
            target_role TEXT,
            read_by TEXT DEFAULT '[]',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP,
            FOREIGN KEY (application_id) REFERENCES applications (id),
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # STRIDE Analysis table for threat modeling
    conn.execute('''
        CREATE TABLE IF NOT EXISTS stride_analysis (
            id TEXT PRIMARY KEY,
            review_id TEXT,
            threat_category TEXT,
            threat_description TEXT,
            risk_level TEXT,
            mitigation_status TEXT,
            question_id TEXT,
            recommendations TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (review_id) REFERENCES security_reviews (id)
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

def login_required(f):
    """Decorator to require login for routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('web_login'))
        return f(*args, **kwargs)
    return decorated_function

def analyst_required(f):
    """Decorator to require Security Analyst role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('web_login'))
        
        # Check if user has analyst role
        conn = get_db()
        user = conn.execute('SELECT role FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        conn.close()
        
        if not user or user[0] not in ['security_analyst', 'admin']:
            return redirect(url_for('web_dashboard'))
        
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to require Admin role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('web_login'))
        
        # Check if user has admin role
        conn = get_db()
        user = conn.execute('SELECT role FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        conn.close()
        
        if not user or user[0] != 'admin':
            flash('Access denied. Admin privileges required.', 'error')
            return redirect(url_for('web_dashboard'))
        
        return f(*args, **kwargs)
    return decorated_function

# STRIDE Threat Modeling Categories
STRIDE_CATEGORIES = {
    "spoofing": {
        "name": "Spoofing",
        "description": "Impersonating someone or something else",
        "examples": ["Credential theft", "Identity spoofing", "Session hijacking"],
        "color": "#e74c3c"
    },
    "tampering": {
        "name": "Tampering",
        "description": "Modifying data or code",
        "examples": ["Data manipulation", "Code injection", "Configuration changes"],
        "color": "#f39c12"
    },
    "repudiation": {
        "name": "Repudiation",
        "description": "Claiming to have not performed an action",
        "examples": ["Lack of logging", "Non-repudiation failures", "Audit trail gaps"],
        "color": "#9b59b6"
    },
    "information_disclosure": {
        "name": "Information Disclosure",
        "description": "Exposing information to unauthorized users",
        "examples": ["Data leaks", "Information exposure", "Privacy violations"],
        "color": "#3498db"
    },
    "denial_of_service": {
        "name": "Denial of Service",
        "description": "Denying or degrading service to valid users",
        "examples": ["Resource exhaustion", "Service disruption", "Availability attacks"],
        "color": "#e67e22"
    },
    "elevation_of_privilege": {
        "name": "Elevation of Privilege",
        "description": "Gaining capabilities without proper authorization",
        "examples": ["Privilege escalation", "Authorization bypass", "Access control failures"],
        "color": "#e74c3c"
    }
}

# OWASP to STRIDE Mapping
OWASP_TO_STRIDE_MAPPING = {
    "input_validation": ["tampering", "denial_of_service"],
    "authentication": ["spoofing", "elevation_of_privilege"],
    "authorization": ["elevation_of_privilege", "information_disclosure"],
    "configuration_management": ["tampering", "information_disclosure"],
    "sensitive_data": ["information_disclosure", "tampering"],
    "session_management": ["spoofing", "elevation_of_privilege"],
    "database_security": ["tampering", "information_disclosure"],
    "file_management": ["tampering", "denial_of_service"],
    "exception_management": ["information_disclosure", "denial_of_service"],
    "cryptography": ["information_disclosure", "tampering"],
    "auditing_logging": ["repudiation", "information_disclosure"],
    "data_protection": ["information_disclosure", "tampering"],
    "api_security": ["spoofing", "tampering", "information_disclosure"],
    "ai_security": ["tampering", "information_disclosure", "denial_of_service"]
}

# Restructured OWASP Security Questionnaires - Split into Application Review and Cloud Review
SECURITY_QUESTIONNAIRES = {
    # ===== APPLICATION REVIEW (14 Categories) =====
    "application_review": {
        "name": "Application Security Review",
        "description": "Comprehensive OWASP-based security assessment covering 14 security categories for application development",
        "review_type": "application_review",
        "categories": {
            "input_validation": {
                "title": "Input Validation - OWASP A1, A3, A6",
                "description": "OWASP Top 10 A03 (Injection) - Preventing injection attacks through proper input validation",
                "questions": [
                    {
                        "id": "input_1",
                        "question": "How does your application validate and sanitize user input?",
                        "description": "Input validation prevents injection attacks (SQL, XSS, XXE, NoSQL, LDAP, etc.)",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "input_2", 
                        "question": "Are parameterized queries or prepared statements used for database interactions?",
                        "description": "Prevents SQL injection by separating SQL code from data",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "input_3",
                        "question": "Is output encoding implemented to prevent XSS attacks?",
                        "description": "Proper output encoding prevents Cross-Site Scripting vulnerabilities",
                        "type": "radio", 
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "input_4",
                        "question": "Are file upload functionalities secured against malicious file uploads?",
                        "description": "File upload validation prevents malware and code execution attacks",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "input_5",
                        "question": "Is input length validation implemented to prevent buffer overflow attacks?",
                        "description": "Length validation prevents memory corruption and system crashes",
                        "type": "radio", 
                        "options": ["yes", "na", "no"]
                    }
                ]
            },
            "authentication": {
                "title": "Authentication (Identity & Access Management - IAM) - OWASP A2",
                "description": "OWASP Top 10 A07 (Identification and Authentication Failures) - Secure user authentication",
                "questions": [
                    {
                        "id": "auth_1",
                        "question": "How does your application implement user authentication?",
                        "description": "Strong authentication mechanisms prevent unauthorized access",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "auth_2",
                        "question": "Is multi-factor authentication (MFA) implemented for sensitive accounts?",
                        "description": "MFA provides additional security layer beyond passwords",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "auth_3",
                        "question": "Are password policies enforced (complexity, length, rotation)?",
                        "description": "Strong password policies reduce brute force attack success",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "auth_4",
                        "question": "Is account lockout protection implemented against brute force attacks?",
                        "description": "Account lockout prevents automated password guessing attacks",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "auth_5",
                        "question": "Are authentication tokens securely generated and managed?",
                        "description": "Secure token management prevents session hijacking and replay attacks",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    }
                ]
            },
            "authorization": {
                "title": "Authorization (Access Control) - OWASP A5",
                "description": "OWASP Top 10 A01 (Broken Access Control) - Proper access control implementation",
                "questions": [
                    {
                        "id": "authz_1",
                        "question": "How does your application enforce role-based access control (RBAC)?",
                        "description": "RBAC ensures users only access authorized resources",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "authz_2",
                        "question": "Are authorization checks performed on every request?",
                        "description": "Consistent authorization prevents privilege escalation",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "authz_3",
                        "question": "Is the principle of least privilege applied to user permissions?",
                        "description": "Minimal necessary permissions reduce attack surface",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "authz_4",
                        "question": "Are indirect object references protected against unauthorized access?",
                        "description": "Prevents users from accessing resources through URL manipulation",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "authz_5",
                        "question": "Is privilege escalation prevention implemented in the application?",
                        "description": "Prevents users from gaining higher privileges than authorized",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    }
                ]
            },
            "configuration_management": {
                "title": "Configuration Management - OWASP A6",
                "description": "OWASP Top 10 A05 (Security Misconfiguration) - Secure system configuration",
                "questions": [
                    {
                        "id": "config_1",
                        "question": "How are security configurations managed and hardened?",
                        "description": "Proper configuration prevents common security misconfigurations",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "config_2",
                        "question": "Are default credentials changed and unnecessary services disabled?",
                        "description": "Removing defaults reduces attack surface",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "config_3",
                        "question": "Is security configuration testing automated?",
                        "description": "Automated testing ensures consistent security configuration",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "config_4",
                        "question": "Are security headers properly configured (HSTS, CSP, X-Frame-Options)?",
                        "description": "Security headers provide protection against common web attacks",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "config_5",
                        "question": "Is environment separation properly implemented (dev/test/prod)?",
                        "description": "Environment separation prevents production data exposure in lower environments",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    }
                ]
            },
            "sensitive_data": {
                "title": "Sensitive Data - OWASP A3",
                "description": "OWASP Top 10 A02 (Cryptographic Failures) - Protecting sensitive data throughout its lifecycle",
                "questions": [
                    {
                        "id": "data_1",
                        "question": "How is personally identifiable information (PII) protected?",
                        "description": "PII protection ensures privacy compliance and prevents identity theft",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "data_2",
                        "question": "Is data classification implemented with appropriate controls?",
                        "description": "Data classification ensures appropriate protection levels",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "data_3",
                        "question": "Are secure data deletion procedures implemented?",
                        "description": "Secure deletion prevents data recovery by unauthorized parties",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "data_4",
                        "question": "Is sensitive data masked or tokenized in non-production environments?",
                        "description": "Data masking prevents exposure of sensitive information in development/testing",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "data_5",
                        "question": "Are data retention policies implemented and enforced?",
                        "description": "Data retention policies ensure compliance and minimize data exposure",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    }
                ]
            },
            "session_management": {
                "title": "Session Management - OWASP A5",
                "description": "OWASP Top 10 A07 - Secure session handling and lifecycle management",
                "questions": [
                    {
                        "id": "session_1",
                        "question": "How are user sessions securely managed and validated?",
                        "description": "Secure session management prevents session hijacking",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "session_2",
                        "question": "Are session timeouts implemented for inactive sessions?",
                        "description": "Session timeouts reduce exposure of abandoned sessions",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "session_3",
                        "question": "Is session regeneration implemented after authentication?",
                        "description": "Session regeneration prevents session fixation attacks",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "session_4",
                        "question": "Are session cookies configured with secure attributes (HttpOnly, Secure, SameSite)?",
                        "description": "Secure cookie attributes protect against XSS and CSRF attacks",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "session_5",
                        "question": "Is concurrent session management implemented to prevent session sharing?",
                        "description": "Concurrent session controls prevent unauthorized session sharing",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    }
                ]
            },
            "database_security": {
                "title": "Database Security",
                "description": "Database security controls to protect data integrity and confidentiality",
                "questions": [
                    {
                        "id": "db_1",
                        "question": "Are database connections encrypted and using strong authentication?",
                        "description": "Encrypted database connections protect data in transit",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "db_2",
                        "question": "Is database access logging and monitoring implemented?",
                        "description": "Database monitoring detects unauthorized access and data manipulation",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "db_3",
                        "question": "Are database privileges minimized using principle of least privilege?",
                        "description": "Minimal database privileges reduce impact of compromise",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "db_4",
                        "question": "Is database backup security and encryption implemented?",
                        "description": "Secure backups protect against data loss and unauthorized access",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "db_5",
                        "question": "Are database security patches and updates regularly applied?",
                        "description": "Regular patching prevents exploitation of known database vulnerabilities",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    }
                ]
            },
            "file_management": {
                "title": "File Management",
                "description": "Secure file handling and storage practices",
                "questions": [
                    {
                        "id": "file_1",
                        "question": "Are file upload validations implemented (type, size, content)?",
                        "description": "File validation prevents malicious file uploads and system compromise",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "file_2",
                        "question": "Is file storage implemented outside of web root directory?",
                        "description": "Secure file storage prevents direct web access to uploaded files",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "file_3",
                        "question": "Are file permissions properly configured and restricted?",
                        "description": "Proper file permissions prevent unauthorized access and modification",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "file_4",
                        "question": "Is antivirus scanning implemented for uploaded files?",
                        "description": "Antivirus scanning detects and prevents malware uploads",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "file_5",
                        "question": "Are temporary files securely managed and cleaned up?",
                        "description": "Secure temp file management prevents information disclosure",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    }
                ]
            },
            "exception_management": {
                "title": "Exception Management - OWASP A3",
                "description": "OWASP Top 10 A09 (Security Logging and Monitoring Failures) - Secure error handling",
                "questions": [
                    {
                        "id": "error_1",
                        "question": "How does your application handle and log security-relevant events?",
                        "description": "Proper logging enables security monitoring and incident response",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "error_2",
                        "question": "Are error messages sanitized to prevent information disclosure?",
                        "description": "Generic error messages prevent information leakage",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "error_3",
                        "question": "Is centralized logging implemented with proper retention policies?",
                        "description": "Centralized logging supports security monitoring and compliance",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
            },
                    {
                        "id": "error_4",
                        "question": "Are exception stack traces prevented from reaching end users?",
                        "description": "Hidden stack traces prevent system information disclosure",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "error_5",
                        "question": "Is security event correlation and alerting implemented?",
                        "description": "Event correlation enables detection of security incidents",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    }
                ]
                    },
            "cryptography": {
                "title": "Cryptography - OWASP A3",
                "description": "OWASP Top 10 A02 (Cryptographic Failures) - Proper encryption and key management",
                "questions": [
                    {
                        "id": "crypto_1",
                        "question": "How is sensitive data encrypted at rest and in transit?",
                        "description": "Encryption protects sensitive data from unauthorized access",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "crypto_2",
                        "question": "Are cryptographic keys properly managed and rotated?",
                        "description": "Proper key management maintains encryption effectiveness",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "crypto_3",
                        "question": "Are strong, approved cryptographic algorithms used?",
                        "description": "Modern algorithms provide adequate security protection",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "crypto_4",
                        "question": "Is secure random number generation implemented for cryptographic operations?",
                        "description": "Secure randomness ensures cryptographic strength",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
            },
                    {
                        "id": "crypto_5",
                        "question": "Are digital signatures and integrity checks implemented where required?",
                        "description": "Digital signatures ensure data authenticity and integrity",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    }
                ]
                    },
            "auditing_logging": {
                "title": "Auditing and Logging - OWASP A10",
                "description": "OWASP Top 10 A09 - Security event logging and audit trail management",
                "questions": [
                    {
                        "id": "audit_1",
                        "question": "Are all security-relevant events logged with sufficient detail?",
                        "description": "Comprehensive logging enables security incident investigation",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "audit_2",
                        "question": "Is log integrity protection implemented to prevent tampering?",
                        "description": "Log integrity ensures audit trail reliability",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
            },
                    {
                        "id": "audit_3",
                        "question": "Are logs centralized and securely stored with proper access controls?",
                        "description": "Centralized secure logging prevents unauthorized access to audit data",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "audit_4",
                        "question": "Is real-time security monitoring and alerting implemented?",
                        "description": "Real-time monitoring enables rapid incident response",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "audit_5",
                        "question": "Are log analysis and forensic capabilities implemented?",
                        "description": "Log analysis supports security investigation and compliance",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    }
                ]
            },
            "data_protection": {
                "title": "Data Protection - OWASP A6",
                "description": "OWASP Top 10 A06 (Vulnerable and Outdated Components) - Managing security vulnerabilities",
                "questions": [
                    {
                        "id": "vuln_1",
                        "question": "How are security vulnerabilities identified and remediated?",
                        "description": "Vulnerability management prevents exploitation of known security flaws",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "vuln_2",
                        "question": "Are third-party components regularly updated and patched?",
                        "description": "Updated components prevent exploitation of known vulnerabilities",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "vuln_3",
                        "question": "Is vulnerability scanning automated and regularly performed?",
                        "description": "Regular scanning identifies new vulnerabilities quickly",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
            },
                    {
                        "id": "vuln_4",
                        "question": "Is software composition analysis implemented to track dependencies?",
                        "description": "Dependency tracking identifies vulnerable components",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "vuln_5",
                        "question": "Are penetration testing and security assessments regularly conducted?",
                        "description": "Security testing identifies vulnerabilities before attackers",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    }
                ]
                    },
            "api_security": {
                "title": "API Security",
                "description": "OWASP API Security Top 10 - Securing application programming interfaces",
                "questions": [
                    {
                        "id": "api_1",
                        "question": "How are APIs authenticated, authorized, and access-controlled?",
                        "description": "API security prevents unauthorized access to backend services and data",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
            },
                    {
                        "id": "api_2",
                        "question": "Is API rate limiting and throttling implemented?",
                        "description": "Rate limiting prevents API abuse and DoS attacks",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "api_3",
                        "question": "Are API inputs validated and outputs sanitized?",
                        "description": "Input validation prevents injection attacks through APIs",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "api_4",
                        "question": "Is API versioning and deprecation properly managed?",
                        "description": "Proper API versioning ensures security through controlled evolution",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "api_5",
                        "question": "Are API security headers and CORS policies properly configured?",
                        "description": "Security headers and CORS prevent unauthorized cross-origin access",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    }
                ]
            },
            "ai_security": {
                "title": "AI Security",
                "description": "Security considerations for artificial intelligence and machine learning components",
                "questions": [
                    {
                        "id": "ai_1",
                        "question": "Are AI/ML models protected against adversarial attacks and data poisoning?",
                        "description": "AI security prevents model manipulation and malicious training data",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "ai_2",
                        "question": "Is AI model access properly authenticated and authorized?",
                        "description": "Access controls prevent unauthorized use of AI capabilities",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "ai_3",
                        "question": "Are AI training data and models securely stored and protected?",
                        "description": "Secure storage prevents intellectual property theft and data breaches",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "ai_4",
                        "question": "Is AI model output validation and sanitization implemented?",
                        "description": "Output validation prevents malicious AI-generated content",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "ai_5",
                        "question": "Are AI ethics and bias prevention measures implemented?",
                        "description": "Ethical AI prevents discriminatory and harmful automated decisions",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    }
                ]
            }
        }
    },

    # ===== CLOUD REVIEW (3 Cloud Platforms) =====
    "cloud_review": {
        "name": "Cloud Security Review", 
        "description": "Comprehensive OWASP Cloud Top 10 based security assessment for cloud infrastructure",
        "review_type": "cloud_review",
        "categories": {
            "aws_security": {
                "title": "AWS Cloud Security",
                "description": "OWASP Cloud Top 10 based security assessment for AWS infrastructure",
                "questions": [
                    {
                        "id": "aws_iam_1",
                        "question": "How is AWS IAM configured with least privilege access principles?",
                        "description": "IAM misconfigurations are OWASP Cloud #1 risk",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "aws_iam_2",
                        "question": "Is AWS root account properly secured with MFA and restricted usage?",
                        "description": "Root account compromise can lead to complete AWS environment takeover",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "aws_iam_3",
                        "question": "Are AWS access keys rotated regularly and stored securely?",
                        "description": "Leaked or stale access keys are common attack vectors",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "aws_network_1",
                        "question": "How are AWS Security Groups and NACLs configured for network security?",
                        "description": "Network security controls prevent unauthorized access to AWS resources",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "aws_network_2",
                        "question": "Is AWS VPC properly configured with private subnets and secure routing?",
                        "description": "VPC configuration provides network isolation for AWS resources",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "aws_data_1",
                        "question": "How is data encrypted in AWS S3 buckets and other storage services?",
                        "description": "Data protection is critical for cloud security compliance",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "aws_data_2",
                        "question": "Are AWS S3 bucket policies configured to prevent public access?",
                        "description": "S3 misconfigurations can expose sensitive data publicly",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "aws_monitoring_1",
                        "question": "Is AWS CloudTrail enabled for audit logging and monitoring?",
                        "description": "CloudTrail provides audit trails for AWS API calls and activities",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    }
                ]
            },
            "azure_security": {
                "title": "Azure Cloud Security",
                "description": "OWASP Cloud Top 10 based security assessment for Microsoft Azure",
                "questions": [
                    {
                        "id": "azure_iam_1",
                        "question": "How is Azure Active Directory configured with proper RBAC?",
                        "description": "Azure AD is the foundation of identity and access management",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "azure_iam_2",
                        "question": "Is Azure Conditional Access implemented for enhanced security?",
                        "description": "Conditional Access provides dynamic access control based on risk",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "azure_iam_3",
                        "question": "Are Azure service principals properly managed and secured?",
                        "description": "Service principals enable secure application authentication in Azure",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "azure_network_1",
                        "question": "How are Azure Network Security Groups configured?",
                        "description": "NSGs provide network-level security for Azure resources",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "azure_network_2",
                        "question": "Is Azure Virtual Network properly segmented and secured?",
                        "description": "VNet segmentation isolates workloads and controls traffic flow",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "azure_data_1",
                        "question": "How is data encrypted in Azure Storage and databases?",
                        "description": "Azure encryption protects data at rest and in transit",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "azure_data_2",
                        "question": "Is Azure Key Vault used for secrets and key management?",
                        "description": "Key Vault provides secure storage for cryptographic keys and secrets",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "azure_monitoring_1",
                        "question": "Is Azure Security Center/Defender enabled for threat protection?",
                        "description": "Azure Defender provides advanced threat protection capabilities",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    }
                ]
            },
            "gcp_security": {
                "title": "GCP Cloud Security", 
                "description": "OWASP Cloud Top 10 based security assessment for Google Cloud Platform",
                "questions": [
                    {
                        "id": "gcp_iam_1",
                        "question": "How is GCP IAM configured with least privilege principles?",
                        "description": "GCP IAM controls access to all Google Cloud resources",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "gcp_iam_2",
                        "question": "Are GCP service accounts properly managed and secured?",
                        "description": "Service accounts enable secure application authentication in GCP",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "gcp_iam_3",
                        "question": "Is GCP Identity-Aware Proxy (IAP) implemented where applicable?",
                        "description": "IAP provides zero-trust access to applications and VMs",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "gcp_network_1",
                        "question": "How are GCP firewall rules configured for network security?",
                        "description": "Firewall rules control network traffic to GCP resources",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "gcp_network_2",
                        "question": "Is GCP VPC properly configured with private networks?",
                        "description": "VPC configuration provides network isolation and security",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "gcp_data_1",
                        "question": "How is data encrypted in GCP Cloud Storage and databases?",
                        "description": "GCP encryption protects data using Google-managed or customer-managed keys",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "gcp_data_2",
                        "question": "Is GCP Cloud KMS used for key management?",
                        "description": "Cloud KMS provides centralized key management for encryption",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "gcp_monitoring_1",
                        "question": "Is GCP Security Command Center enabled for threat detection?",
                        "description": "Security Command Center provides centralized security monitoring",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    }
                ]
            }
        }
    },

    # ===== DATABASE REVIEW (3 Database Platforms) =====
    "database_review": {
        "name": "Database Security Review",
        "description": "Comprehensive OWASP-based security assessment for database infrastructure covering MongoDB, PostgreSQL, and MySQL",
        "review_type": "database_review",
        "categories": {
            "mongodb_security": {
                "title": "MongoDB Security",
                "description": "OWASP-based security assessment for MongoDB database instances",
                "questions": [
                    {
                        "id": "mongo_auth_1",
                        "question": "Is authentication enabled and properly configured in MongoDB?",
                        "description": "OWASP A07 (Identification and Authentication Failures) - Prevent unauthorized database access",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "mongo_auth_2",
                        "question": "Are strong, unique passwords enforced for all MongoDB users?",
                        "description": "Weak passwords are a primary attack vector against databases",
                        "type": "radio", 
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "mongo_auth_3",
                        "question": "Is role-based access control (RBAC) implemented with least privilege principle?",
                        "description": "OWASP A01 (Broken Access Control) - Limit user permissions to minimum required",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "mongo_network_1",
                        "question": "Is network access to MongoDB restricted using IP whitelisting or VPN?",
                        "description": "OWASP A05 (Security Misconfiguration) - Prevent unauthorized network access",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "mongo_network_2", 
                        "question": "Is TLS/SSL encryption enabled for all MongoDB connections?",
                        "description": "OWASP A02 (Cryptographic Failures) - Protect data in transit",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "mongo_data_1",
                        "question": "Is encryption at rest enabled for MongoDB data files?",
                        "description": "OWASP A02 (Cryptographic Failures) - Protect sensitive data at rest",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "mongo_audit_1",
                        "question": "Is auditing enabled to log database access and operations?",
                        "description": "OWASP A09 (Security Logging and Monitoring Failures) - Track database activities",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "mongo_input_1",
                        "question": "Are NoSQL injection attacks prevented through proper input validation?",
                        "description": "OWASP A03 (Injection) - Prevent NoSQL injection vulnerabilities", 
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "mongo_backup_1",
                        "question": "Are regular encrypted backups performed and tested for recovery?",
                        "description": "Ensure data availability and integrity against ransomware and data loss",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "mongo_config_1",
                        "question": "Are MongoDB security configurations regularly reviewed and hardened?",
                        "description": "OWASP A05 (Security Misconfiguration) - Maintain secure database configuration",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    }
                ]
            },
            "postgresql_security": {
                "title": "PostgreSQL Security", 
                "description": "OWASP-based security assessment for PostgreSQL database instances",
                "questions": [
                    {
                        "id": "postgres_auth_1",
                        "question": "Is PostgreSQL authentication properly configured using strong methods (scram-sha-256)?",
                        "description": "OWASP A07 (Identification and Authentication Failures) - Use strong authentication mechanisms",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "postgres_auth_2", 
                        "question": "Are database users created with minimal necessary privileges?",
                        "description": "OWASP A01 (Broken Access Control) - Implement least privilege access control",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "postgres_auth_3",
                        "question": "Is the PostgreSQL superuser account properly secured and access restricted?",
                        "description": "Prevent unauthorized access to administrative functions",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "postgres_network_1",
                        "question": "Is PostgreSQL configured to listen only on required network interfaces?",
                        "description": "OWASP A05 (Security Misconfiguration) - Limit network exposure",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "postgres_network_2",
                        "question": "Is SSL/TLS encryption enforced for all PostgreSQL connections?",
                        "description": "OWASP A02 (Cryptographic Failures) - Protect data transmission",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "postgres_data_1",
                        "question": "Is transparent data encryption (TDE) or file system encryption implemented?",
                        "description": "OWASP A02 (Cryptographic Failures) - Protect data at rest",
                        "type": "radio", 
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "postgres_audit_1",
                        "question": "Is PostgreSQL logging configured to capture security-relevant events?",
                        "description": "OWASP A09 (Security Logging and Monitoring Failures) - Enable security monitoring",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "postgres_injection_1",
                        "question": "Are prepared statements and parameterized queries used consistently?",
                        "description": "OWASP A03 (Injection) - Prevent SQL injection attacks",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "postgres_backup_1", 
                        "question": "Are automated, encrypted backups performed with tested recovery procedures?",
                        "description": "Ensure data availability and business continuity",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "postgres_config_1",
                        "question": "Are PostgreSQL security settings regularly reviewed against security benchmarks?",
                        "description": "OWASP A05 (Security Misconfiguration) - Maintain secure configuration baseline",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    }
                ]
            },
            "mysql_security": {
                "title": "MySQL Security",
                "description": "OWASP-based security assessment for MySQL database instances", 
                "questions": [
                    {
                        "id": "mysql_auth_1",
                        "question": "Is MySQL authentication configured with strong password validation?",
                        "description": "OWASP A07 (Identification and Authentication Failures) - Enforce strong password policies",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "mysql_auth_2",
                        "question": "Are MySQL user accounts created with specific host restrictions?",
                        "description": "OWASP A01 (Broken Access Control) - Limit user access by host/network",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "mysql_auth_3",
                        "question": "Is the MySQL root account properly secured with password and host restrictions?",
                        "description": "Prevent unauthorized administrative access to MySQL",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "mysql_network_1",
                        "question": "Is MySQL configured to bind only to required network interfaces?",
                        "description": "OWASP A05 (Security Misconfiguration) - Minimize network attack surface",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "mysql_network_2",
                        "question": "Is SSL/TLS encryption enforced for all MySQL client connections?",
                        "description": "OWASP A02 (Cryptographic Failures) - Secure data in transit",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "mysql_data_1",
                        "question": "Is MySQL data encryption at rest implemented using InnoDB encryption?",
                        "description": "OWASP A02 (Cryptographic Failures) - Protect stored data",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "mysql_audit_1",
                        "question": "Is MySQL audit logging enabled to track database access and changes?",
                        "description": "OWASP A09 (Security Logging and Monitoring Failures) - Monitor database activities",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "mysql_injection_1",
                        "question": "Are prepared statements used to prevent SQL injection attacks?",
                        "description": "OWASP A03 (Injection) - Prevent SQL injection vulnerabilities",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "mysql_backup_1",
                        "question": "Are MySQL backups automated, encrypted, and regularly tested?",
                        "description": "Ensure data recovery capabilities and business continuity",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "mysql_config_1",
                        "question": "Are MySQL security configurations reviewed against CIS benchmarks?",
                        "description": "OWASP A05 (Security Misconfiguration) - Follow security hardening guidelines",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    }
                ]
            }
        }
    }
}

# Legacy questionnaire for backward compatibility (now points to application_review)
SECURITY_QUESTIONNAIRE = SECURITY_QUESTIONNAIRES["application_review"]["categories"]

def get_questionnaire_for_field(field):
    """Get questionnaire data for specific field type"""
    
    # Map field types to questionnaire categories
    field_mapping = {
        'application_review': 'application_review',
        'cloud_review': 'cloud_review',
        # Legacy field mappings for backward compatibility
        'comprehensive_application': 'application_review',
        'cloud_aws': 'cloud_review',
        'cloud_azure': 'cloud_review', 
        'cloud_gcp': 'cloud_review',
        'web_application': 'application_review',
        'mobile_application': 'application_review'
    }
    
    questionnaire_type = field_mapping.get(field, 'application_review')
    
    if questionnaire_type in SECURITY_QUESTIONNAIRES:
        return SECURITY_QUESTIONNAIRES[questionnaire_type]
    else:
        # Fallback to application review
        return SECURITY_QUESTIONNAIRES['application_review']

def filter_questions_by_technology(questionnaire_data, technology_stack, cloud_providers=None):
    """Filter questions based on technology stack and cloud providers"""
    if not technology_stack:
        return questionnaire_data
    
    # Convert technology stack to list if it's a string
    if isinstance(technology_stack, str):
        tech_list = [tech.strip().lower() for tech in technology_stack.split(',')]
    else:
        tech_list = [tech.lower() for tech in technology_stack]
    
    # Define technology-specific question mappings
    tech_question_mapping = {
        'javascript': ['input_1', 'input_3', 'auth_1', 'auth_3', 'session_1', 'session_2', 'api_1', 'api_2'],
        'python': ['input_1', 'input_2', 'auth_1', 'auth_2', 'crypto_1', 'crypto_2', 'api_1'],
        'java': ['input_1', 'input_2', 'auth_1', 'auth_2', 'session_1', 'crypto_1', 'crypto_2'],
        'react': ['input_3', 'auth_3', 'session_1', 'session_2', 'api_1', 'api_2'],
        'angular': ['input_3', 'auth_3', 'session_1', 'session_2', 'api_1', 'api_2'],
        'vue.js': ['input_3', 'auth_3', 'session_1', 'session_2', 'api_1', 'api_2'],
        'mysql': ['input_2', 'database_1', 'database_2', 'crypto_1'],
        'postgresql': ['input_2', 'database_1', 'database_2', 'crypto_1'],
        'mongodb': ['input_2', 'database_1', 'database_2', 'crypto_2'],
        'docker': ['config_1', 'config_2', 'network_1', 'network_2']
    }
    
    # Get relevant question IDs based on selected technologies
    relevant_questions = set()
    for tech in tech_list:
        if tech in tech_question_mapping:
            relevant_questions.update(tech_question_mapping[tech])
    
    # If no specific technology mapping found, include all questions
    if not relevant_questions:
        return questionnaire_data
    
    # Filter the questionnaire data
    filtered_data = {}
    for category_key, category_data in questionnaire_data.items():
        filtered_questions = []
        for question in category_data['questions']:
            if question['id'] in relevant_questions:
                filtered_questions.append(question)
        
        # Only include categories that have questions after filtering
        if filtered_questions:
            filtered_data[category_key] = {
                'title': category_data['title'],
                'description': category_data['description'],
                'questions': filtered_questions
            }
    
    # If filtering resulted in empty questionnaire, return original
    if not filtered_data:
        return questionnaire_data
    
    return filtered_data

def filter_cloud_questions_by_providers(questionnaire_data, cloud_providers):
    """Filter cloud questions based on selected cloud providers"""
    if not cloud_providers or not questionnaire_data:
        return questionnaire_data
    
    # Convert to list if string
    if isinstance(cloud_providers, str):
        provider_list = [p.strip().upper() for p in cloud_providers.split(',')]
    else:
        provider_list = [p.upper() for p in cloud_providers]
    
    # Map providers to category keys (exact match with questionnaire structure)
    provider_mapping = {
        'AWS': 'aws_security',
        'AZURE': 'azure_security', 
        'GCP': 'gcp_security'
    }
    
    # Filter categories based on selected providers
    filtered_data = {}
    for provider in provider_list:
        if provider in provider_mapping:
            category_key = provider_mapping[provider]
            if category_key in questionnaire_data:
                filtered_data[category_key] = questionnaire_data[category_key]
    
    # If no matching providers found, return empty dict (no questions)
    # This ensures only relevant cloud provider questions are shown
    return filtered_data

def filter_database_questions_by_types(questionnaire_data, database_types):
    """Filter database questions based on selected database types"""
    if not database_types or not questionnaire_data:
        return questionnaire_data
    
    # Convert to list if string
    if isinstance(database_types, str):
        db_list = [db.strip().lower() for db in database_types.split(',')]
    else:
        db_list = [db.lower() for db in database_types]
    
    # Map database types to category keys (exact match with questionnaire structure)
    db_mapping = {
        'mongodb': 'mongodb_security',
        'postgresql': 'postgresql_security', 
        'mysql': 'mysql_security'
    }
    
    # Filter categories based on selected database types
    filtered_data = {}
    for db_type in db_list:
        if db_type in db_mapping:
            category_key = db_mapping[db_type]
            if category_key in questionnaire_data:
                filtered_data[category_key] = questionnaire_data[category_key]
    
    # If no matching database types found, return empty dict (no questions)
    # This ensures only relevant database questions are shown
    return filtered_data

# Web Routes

@app.route('/')
def web_home():
    """Home page"""
    return render_template('home.html')

@app.route('/health')
def health_check():
    """Health check endpoint"""
    from datetime import datetime
    return {
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0',
        'service': 'SecureArch Portal'
    }

@app.route('/download/<path:filename>')
@login_required
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
            return redirect(request.referrer or url_for('web_dashboard'))
        
        # Additional security: verify the file is within uploads directory (prevent path traversal)
        real_uploads = os.path.realpath(uploads_base)
        real_file = os.path.realpath(file_path)
        if not real_file.startswith(real_uploads):
            flash('Access denied.', 'error')
            return redirect(request.referrer or url_for('web_dashboard'))
        
        return send_from_directory(directory, just_filename, as_attachment=True)
    
    except Exception as e:
        flash(f'Error downloading file: {str(e)}', 'error')
        return redirect(request.referrer or url_for('web_dashboard'))

@app.route('/login', methods=['GET', 'POST'])
def web_login():
    """Login page"""
    if request.method == 'POST':
        email = request.form['email'].lower().strip()
        password = request.form['password']
        
        conn = get_db()
        user = conn.execute('''
            SELECT id, email, password_hash, first_name, last_name, role, onboarding_completed
            FROM users WHERE email = ? AND is_active = 1
        ''', (email,)).fetchone()
        
        if user and check_password_hash(user['password_hash'], password):
            # Update last login
            conn.execute('UPDATE users SET last_login_at = CURRENT_TIMESTAMP WHERE id = ?', (user['id'],))
            conn.commit()
            conn.close()
            
            # Set session
            session['user_id'] = user['id']
            session['user_name'] = f"{user['first_name']} {user['last_name']}"
            session['user_role'] = user['role']
            session['user_email'] = user['email']
            
            flash(f'Welcome back, {user["first_name"]}!', 'success')
            
            # Redirect based on onboarding status and user role
            if not user['onboarding_completed']:
                return redirect(url_for('web_onboarding'))
            else:
                return redirect(url_for('web_dashboard'))
        else:
            conn.close()
            flash('Invalid email or password. Try demo: admin@demo.com / password123', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def web_register():
    """Registration page"""
    if request.method == 'POST':
        # Get form data
        data = {
            'first_name': request.form['first_name'].strip(),
            'last_name': request.form['last_name'].strip(),
            'email': request.form['email'].lower().strip(),
            'password': request.form['password'],
            'confirm_password': request.form['confirm_password'],
            'organization_name': request.form.get('organization_name', '').strip(),
            'job_title': request.form.get('job_title', '').strip(),
            'experience_level': request.form.get('experience_level', ''),
            'interests': ','.join(request.form.getlist('interests'))
        }
        
        # Validation
        if data['password'] != data['confirm_password']:
            flash('Passwords do not match.', 'error')
            return render_template('register.html')
        
        if len(data['password']) < 8:
            flash('Password must be at least 8 characters long.', 'error')
            return render_template('register.html')
        
        # Check if user exists
        conn = get_db()
        existing_user = conn.execute('SELECT id FROM users WHERE email = ?', (data['email'],)).fetchone()
        
        if existing_user:
            conn.close()
            flash('An account with this email already exists.', 'error')
            return render_template('register.html')
        
        # Create user
        user_id = str(uuid.uuid4())
        password_hash = generate_password_hash(data['password'])
        
        conn.execute('''
            INSERT INTO users (id, email, password_hash, first_name, last_name, 
                             organization_name, job_title, experience_level, interests)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (user_id, data['email'], password_hash, data['first_name'], data['last_name'],
              data['organization_name'], data['job_title'], data['experience_level'], data['interests']))
        
        conn.commit()
        conn.close()
        
        # Auto login
        session['user_id'] = user_id
        session['user_name'] = f"{data['first_name']} {data['last_name']}"
        session['user_role'] = 'user'
        session['user_email'] = data['email']
        
        flash('Account created successfully! Let\'s get you started.', 'success')
        return redirect(url_for('web_onboarding'))
    
    return render_template('register.html')

@app.route('/onboarding')
@login_required
def web_onboarding():
    """User onboarding flow"""
    return render_template('onboarding.html')

@app.route('/dashboard')
@login_required
def web_dashboard():
    """Unified role-aware dashboard for all user types"""
    user_role = session.get('user_role', 'user')
    user_id = session['user_id']
    
    conn = get_db()
    
    if user_role == 'admin':
        # Admin Dashboard - System-wide statistics
        total_users = conn.execute('SELECT COUNT(*) as count FROM users').fetchone()['count']
        active_users = conn.execute('SELECT COUNT(*) as count FROM users WHERE is_active = 1').fetchone()['count']
        total_applications = conn.execute('SELECT COUNT(*) as count FROM applications').fetchone()['count']
        total_reviews = conn.execute('SELECT COUNT(*) as count FROM security_reviews').fetchone()['count']
        pending_reviews = conn.execute('SELECT COUNT(*) as count FROM security_reviews WHERE status IN ("submitted", "in_review")').fetchone()['count']
        
        # Application statistics by status
        app_stats = conn.execute('''
            SELECT status, COUNT(*) as count 
            FROM applications 
            GROUP BY status
        ''').fetchall()
        
        # User statistics by role
        user_stats = conn.execute('''
            SELECT role, COUNT(*) as count 
            FROM users 
            WHERE is_active = 1
            GROUP BY role
        ''').fetchall()
        
        # Security findings statistics
        findings_stats = conn.execute('''
            SELECT risk_level, COUNT(*) as count 
            FROM stride_analysis 
            GROUP BY risk_level
        ''').fetchall()
        
        # Recent activity (last 10 applications)
        recent_applications = conn.execute('''
            SELECT a.id, a.name, a.status, a.created_at, 
                   u.first_name, u.last_name, u.email
            FROM applications a
            JOIN users u ON a.author_id = u.id
            ORDER BY a.created_at DESC LIMIT 10
        ''').fetchall()
        
        stats = {
            'total_users': total_users,
            'active_users': active_users,
            'total_applications': total_applications,
            'total_reviews': total_reviews,
            'pending_reviews': pending_reviews,
            'app_stats': {row['status']: row['count'] for row in app_stats},
            'user_stats': {row['role']: row['count'] for row in user_stats},
            'findings_stats': {row['risk_level']: row['count'] for row in findings_stats}
        }
        
        conn.close()
        return render_template('dashboard.html', 
                             role='admin',
                             stats=stats, 
                             recent_applications=recent_applications)
    
    elif user_role == 'security_analyst':
        # Analyst Dashboard - Review workload and statistics with comprehensive app details
        # Get applications for analyst review using workflow engine
        todo_applications = workflow_engine.get_analyst_applications(user_id, 'todo')
        in_review_applications = workflow_engine.get_analyst_applications(user_id, 'in_review')
        completed_applications = workflow_engine.get_analyst_applications(user_id, 'completed')
        
        # Get pending applications where ALL required reviews are submitted and ready for analyst pickup
        pending_apps_data = conn.execute('''
            SELECT a.id as application_id, a.name as app_name, a.business_criticality,
                   a.description, a.technology_stack, a.deployment_environment,
                   a.data_classification, a.cloud_review_required, a.database_review_required,
                   (u.first_name || ' ' || u.last_name) as author_name, u.email as author_email,
                   MIN(sr.created_at) as earliest_review_date,
                   GROUP_CONCAT(sr.field_type) as review_types,
                   GROUP_CONCAT(sr.id) as review_ids,
                   GROUP_CONCAT(sr.created_at) as review_dates,
                   COUNT(sr.id) as review_count
            FROM applications a
            JOIN security_reviews sr ON a.id = sr.application_id
            JOIN users u ON a.author_id = u.id
            WHERE a.status = 'submitted' AND sr.status = 'submitted' AND sr.analyst_id IS NULL
            GROUP BY a.id, a.name, a.business_criticality, a.description, 
                     a.technology_stack, a.deployment_environment, a.data_classification,
                     a.cloud_review_required, a.database_review_required, u.first_name, u.last_name, u.email
            HAVING (a.cloud_review_required = 'no' AND a.database_review_required = 'no' AND COUNT(sr.id) >= 1) 
                OR (a.cloud_review_required = 'yes' AND a.database_review_required = 'no' AND COUNT(sr.id) >= 2)
                OR (a.cloud_review_required = 'no' AND a.database_review_required = 'yes' AND COUNT(sr.id) >= 2)
                OR (a.cloud_review_required = 'yes' AND a.database_review_required = 'yes' AND COUNT(sr.id) >= 3)
            ORDER BY CASE 
                WHEN a.business_criticality = 'Critical' THEN 1
                WHEN a.business_criticality = 'High' THEN 2
                WHEN a.business_criticality = 'Medium' THEN 3
                ELSE 4
            END, MIN(sr.created_at) ASC
            LIMIT 10
        ''').fetchall()
        
        # Process the data to create a more usable structure
        pending_reviews = []
        for app_data in pending_apps_data:
            review_types = app_data['review_types'].split(',') if app_data['review_types'] else []
            review_ids = app_data['review_ids'].split(',') if app_data['review_ids'] else []
            review_dates = app_data['review_dates'].split(',') if app_data['review_dates'] else []
            
            pending_reviews.append({
                'application_id': app_data['application_id'],
                'app_name': app_data['app_name'],
                'business_criticality': app_data['business_criticality'],
                'description': app_data['description'],
                'technology_stack': app_data['technology_stack'],
                'deployment_environment': app_data['deployment_environment'],
                'data_classification': app_data['data_classification'],
                'author_name': app_data['author_name'],
                'author_email': app_data['author_email'],
                'created_at': app_data['earliest_review_date'],
                'review_types': review_types,
                'review_ids': review_ids,
                'review_dates': review_dates,
                'review_count': len(review_types)
            })

        # Get recent reviews with comprehensive details
        recent_reviews = conn.execute('''
            SELECT sr.id as review_id, sr.application_id, sr.status, sr.created_at,
                   sr.field_type, a.name as app_name, a.business_criticality,
                   a.description, a.technology_stack, a.deployment_environment,
                   a.data_classification,
                   (u.first_name || ' ' || u.last_name) as author_name, u.email as author_email,
                   sr.updated_at, sr.analyst_id
            FROM security_reviews sr
            JOIN applications a ON sr.application_id = a.id
            JOIN users u ON a.author_id = u.id
            WHERE sr.analyst_id = ? AND sr.status IN ('completed', 'in_review')
            ORDER BY sr.updated_at DESC, sr.created_at DESC
            LIMIT 10
        ''', (user_id,)).fetchall()

        # Get security findings statistics
        security_findings = conn.execute('''
            SELECT sa.risk_level, COUNT(*) as count
            FROM stride_analysis sa
            JOIN security_reviews sr ON sa.review_id = sr.id
            WHERE sr.analyst_id = ?
            GROUP BY sa.risk_level
        ''', (user_id,)).fetchall()

        findings_dict = {finding['risk_level']: finding['count'] for finding in security_findings}
        
        # Get overall statistics
        stats = {
            'todo': len(todo_applications),
            'in_review': len(in_review_applications),
            'completed': len(completed_applications),
            'total_assigned': len(todo_applications) + len(in_review_applications) + len(completed_applications),
            'total_pending': len(pending_reviews),
            'critical_risk_count': findings_dict.get('Critical', 0),
            'high_risk_count': findings_dict.get('High', 0),
            'medium_risk_count': findings_dict.get('Medium', 0),
            'low_risk_count': findings_dict.get('Low', 0),
            'total_findings': sum(findings_dict.values())
        }
        
        conn.close()
        return render_template('dashboard.html',
                             role='security_analyst',
                             todo_applications=todo_applications,
                             in_review_applications=in_review_applications,
                             completed_applications=completed_applications,
                             pending_reviews=pending_reviews,
                             recent_reviews=recent_reviews,
                             stats=stats)
    
    else:
        # User Dashboard - Personal applications and activities
        # Get user's applications with draft review status
        user_applications = conn.execute('''
            SELECT a.*, 
                   (SELECT COUNT(*) FROM security_reviews sr 
                    WHERE sr.application_id = a.id AND sr.status = 'draft') as has_draft_review
            FROM applications a
            WHERE a.author_id = ? 
            ORDER BY a.created_at DESC
        ''', (user_id,)).fetchall()
        
        # Get application statistics with safe defaults
        app_stats = {
            'total': len(user_applications) if user_applications else 0,
            'draft': len([app for app in user_applications if app['status'] == 'draft']) if user_applications else 0,
            'submitted': len([app for app in user_applications if app['status'] == 'submitted']) if user_applications else 0,
            'in_review': len([app for app in user_applications if app['status'] == 'in_review']) if user_applications else 0,
            'completed': len([app for app in user_applications if app['status'] == 'completed']) if user_applications else 0,
            'rejected': len([app for app in user_applications if app['status'] == 'rejected']) if user_applications else 0
        }
        
        # Get recent activity
        recent_activity = conn.execute('''
            SELECT a.name, a.status, a.created_at
            FROM applications a
            WHERE a.author_id = ?
            ORDER BY a.created_at DESC
            LIMIT 5
        ''', (user_id,)).fetchall()
        
        conn.close()
        
        return render_template('dashboard.html', 
                             role='user',
                             applications=user_applications,
                             app_stats=app_stats,
                             recent_activity=recent_activity)

@app.route('/applications')
@login_required 
def web_applications():
    """Applications management page"""
    conn = get_db()
    apps = conn.execute('''
        SELECT a.*, 
               sr.risk_score, 
               sr.status as review_status
        FROM applications a
        LEFT JOIN (
            SELECT application_id, 
                   risk_score, 
                   status,
                   MAX(created_at) as latest_created
            FROM security_reviews 
            GROUP BY application_id
        ) sr ON a.id = sr.application_id
        WHERE a.author_id = ?
        ORDER BY a.created_at DESC
    ''', (session['user_id'],)).fetchall()
    conn.close()
    
    return render_template('applications.html', applications=apps)

@app.route('/create-application', methods=['GET', 'POST'])
@login_required
def web_create_application():
    """Create new application with file upload support"""
    if request.method == 'POST':
        # Extract form data
        data = {
            'name': request.form.get('name'),
            'description': request.form.get('description'),
            'technology_stack': ', '.join(request.form.getlist('technology_stack')),
            'deployment_environment': request.form.get('deployment_environment'),
            'business_criticality': request.form.get('business_criticality'),
            'data_classification': request.form.get('data_classification'),
            'cloud_review_required': request.form.get('cloud_review_required', 'no'),
            'cloud_providers': ', '.join(request.form.getlist('cloud_providers')),
            'database_review_required': request.form.get('database_review_required', 'no'),
            'database_types': ', '.join(request.form.getlist('database_types'))
        }
        
        # Validate required fields
        if not all([data['name'], data['business_criticality'], data['data_classification']]):
            flash('Please fill in all required fields.', 'error')
            return redirect(url_for('web_create_application'))
        
        app_id = str(uuid.uuid4())
        
        # Handle file uploads
        file_paths = {}
        file_fields = {
            'logical_architecture': 'architecture',
            'physical_architecture': 'architecture', 
            'overview_document': 'document'
        }
        
        for field_name, file_type in file_fields.items():
            if field_name in request.files:
                file = request.files[field_name]
                if file.filename:  # File was selected
                    file_path = secure_upload(file, file_type, session['user_id'], app_id)
                    if file_path:
                        file_paths[f"{field_name}_file"] = file_path
                    else:
                        flash(f'Invalid file type for {field_name.replace("_", " ").title()}. Please check allowed formats.', 'error')
                        return redirect(url_for('web_create_application'))
        
        conn = get_db()
        conn.execute('''
            INSERT INTO applications (id, name, description, technology_stack,
                                    deployment_environment, business_criticality,
                                    data_classification, author_id, status, logical_architecture_file,
                                    physical_architecture_file, overview_document_file,
                                    cloud_review_required, cloud_providers, database_review_required, database_types, category_preferences)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (app_id, data['name'], data['description'], data['technology_stack'],
              data['deployment_environment'], data['business_criticality'],
              data['data_classification'], session['user_id'], 'draft',
              file_paths.get('logical_architecture_file'),
              file_paths.get('physical_architecture_file'),
              file_paths.get('overview_document_file'),
              data['cloud_review_required'], data['cloud_providers'], data['database_review_required'], data['database_types'], '{}'))
        
        conn.commit()
        conn.close()
        
        flash('Application created successfully! You can now start the security assessment from your dashboard.', 'success')
        return redirect(url_for('web_dashboard'))
    
    return render_template('create_application.html')

@app.route('/delete-application/<app_id>', methods=['DELETE'])
@login_required
def delete_application(app_id):
    """Delete application and all related data"""
    try:
        conn = get_db()
        
        # Verify the application belongs to the current user
        app = conn.execute('SELECT * FROM applications WHERE id = ? AND author_id = ?', 
                          (app_id, session['user_id'])).fetchone()
        
        if not app:
            conn.close()
            return jsonify({'error': 'Application not found or access denied'}), 404
        
        # Get all security reviews for this application
        reviews = conn.execute('SELECT id FROM security_reviews WHERE application_id = ?', 
                              (app_id,)).fetchall()
        
        # Delete STRIDE analysis for all reviews of this application
        for review in reviews:
            conn.execute('DELETE FROM stride_analysis WHERE review_id = ?', (review['id'],))
        
        # Delete all security reviews for this application
        conn.execute('DELETE FROM security_reviews WHERE application_id = ?', (app_id,))
        
        # Delete uploaded files if they exist
        import os
        file_columns = ['logical_architecture_file', 'physical_architecture_file', 'overview_document_file']
        for column in file_columns:
            file_path = app[column]
            if file_path:
                try:
                    full_path = os.path.join('uploads', file_path)
                    if os.path.exists(full_path):
                        os.remove(full_path)
                except Exception as e:
                    print(f"Warning: Could not delete file {file_path}: {e}")
        
        # Finally, delete the application itself
        conn.execute('DELETE FROM applications WHERE id = ?', (app_id,))
        
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Application deleted successfully'})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/security-assessment/<app_id>')
@login_required
def web_security_assessment(app_id):
    """Security Assessment page with Application Review and Cloud Review categories"""
    conn = get_db()
    app = conn.execute('SELECT * FROM applications WHERE id = ? AND author_id = ?', 
                      (app_id, session['user_id'])).fetchone()
    
    if not app:
        conn.close()
        return redirect(url_for('web_applications'))
    
    # Get user role to determine what they can see/do
    user_role = session.get('user_role', 'user')
    
    # Check completion status for all categories
    app_review_completed = False
    cloud_review_completed = False
    database_review_completed = False
    app_review_status = 'not_started'
    cloud_review_status = 'not_started'
    database_review_status = 'not_started'
    
    # Check for existing reviews - get the latest status for each field_type
    existing_reviews = conn.execute('''
        SELECT field_type, status 
        FROM security_reviews sr1
        WHERE application_id = ? AND field_type IS NOT NULL
        AND created_at = (
            SELECT MAX(created_at) 
            FROM security_reviews sr2 
            WHERE sr2.application_id = sr1.application_id 
            AND sr2.field_type = sr1.field_type
        )
        ORDER BY created_at DESC
    ''', (app_id,)).fetchall()
    
    for review in existing_reviews:
        if review['field_type'] == 'application_review':
            if review['status'] == 'completed':
                app_review_completed = True
                app_review_status = 'completed'
            elif review['status'] == 'submitted' and app_review_status not in ['completed']:
                app_review_status = 'submitted'
            elif review['status'] == 'in_review' and app_review_status not in ['completed', 'submitted']:
                app_review_status = 'pending_analyst'
            elif review['status'] == 'draft' and app_review_status == 'not_started':
                app_review_status = 'draft'
        elif review['field_type'] == 'cloud_review':
            if review['status'] == 'completed':
                cloud_review_completed = True
                cloud_review_status = 'completed'
            elif review['status'] == 'submitted' and cloud_review_status not in ['completed']:
                cloud_review_status = 'submitted'
            elif review['status'] == 'in_review' and cloud_review_status not in ['completed', 'submitted']:
                cloud_review_status = 'pending_analyst'
            elif review['status'] == 'draft' and cloud_review_status == 'not_started':
                cloud_review_status = 'draft'
        elif review['field_type'] == 'database_review':
            if review['status'] == 'completed':
                database_review_completed = True
                database_review_status = 'completed'
            elif review['status'] == 'submitted' and database_review_status not in ['completed']:
                database_review_status = 'submitted'
            elif review['status'] == 'in_review' and database_review_status not in ['completed', 'submitted']:
                database_review_status = 'pending_analyst'
            elif review['status'] == 'draft' and database_review_status == 'not_started':
                database_review_status = 'draft'
    
    conn.close()
    
    # Check if cloud review is required
    cloud_review_required = (app['cloud_review_required'] if 'cloud_review_required' in app.keys() else 'no') == 'yes'
    cloud_providers_str = app['cloud_providers'] if 'cloud_providers' in app.keys() and app['cloud_providers'] else ''
    cloud_providers = cloud_providers_str.split(', ') if cloud_providers_str else []
    
    # Check if database review is required
    database_review_required = (app['database_review_required'] if 'database_review_required' in app.keys() else 'no') == 'yes'
    database_types_str = app['database_types'] if 'database_types' in app.keys() and app['database_types'] else ''
    database_types = database_types_str.split(', ') if database_types_str else []
    

    
    # Calculate question counts from questionnaires
    app_review_questions = sum(len(cat['questions']) for cat in SECURITY_QUESTIONNAIRES['application_review']['categories'].values())
    
    # Calculate cloud review questions based on selected providers
    if cloud_review_required and cloud_providers:
        # Filter cloud questions by selected providers to get accurate count
        cloud_questionnaire_data = SECURITY_QUESTIONNAIRES['cloud_review']['categories']
        filtered_cloud_data = filter_cloud_questions_by_providers(cloud_questionnaire_data, app['cloud_providers'])
        cloud_review_questions = sum(len(cat['questions']) for cat in filtered_cloud_data.values())
    else:
        # Default to total count if no providers selected
        cloud_review_questions = sum(len(cat['questions']) for cat in SECURITY_QUESTIONNAIRES['cloud_review']['categories'].values())
    
    # Calculate database review questions based on selected database types
    if database_review_required and database_types:
        # Filter database questions by selected types to get accurate count
        database_questionnaire_data = SECURITY_QUESTIONNAIRES['database_review']['categories']
        filtered_database_data = filter_database_questions_by_types(database_questionnaire_data, database_types)
        database_review_questions = sum(len(cat['questions']) for cat in filtered_database_data.values())
    elif database_review_required:
        # If database review required but no types selected, show all
        database_review_questions = sum(len(cat['questions']) for cat in SECURITY_QUESTIONNAIRES['database_review']['categories'].values())
    else:
        database_review_questions = 0
    
    return render_template('security_assessment.html', 
                         application=app,
                         app_review_completed=app_review_completed,
                         cloud_review_completed=cloud_review_completed,
                         database_review_completed=database_review_completed,
                         app_review_status=app_review_status,
                         cloud_review_status=cloud_review_status,
                         database_review_status=database_review_status,
                         cloud_review_required=cloud_review_required,
                         database_review_required=database_review_required,
                         cloud_providers=cloud_providers,
                         database_types=database_types,
                         user_role=user_role,
                         app_review_questions=app_review_questions,
                         cloud_review_questions=cloud_review_questions,
                         database_review_questions=database_review_questions)

@app.route('/field-selection')
@app.route('/field-selection/<app_id>')
@login_required
def web_field_selection(app_id=None):
    """Security field selection page"""
    application = None
    
    if app_id:
        conn = get_db()
        application = conn.execute('SELECT * FROM applications WHERE id = ? AND author_id = ?', 
                                 (app_id, session['user_id'])).fetchone()
        conn.close()
        
        if not application:
            flash('Application not found.', 'error')
            return redirect(url_for('web_applications'))
    
    return render_template('field_selection.html', application=application)

@app.route('/questionnaire/<app_id>')
@login_required
def web_questionnaire(app_id):
    """Security questionnaire for application - handles both cloud and application reviews"""
    # Check if this is a retake request
    retake = request.args.get('retake', 'false').lower() == 'true'
    
    # Get field type from request parameter
    field_type = request.args.get('field', 'application_review')
    
    conn = get_db()
    app = conn.execute('SELECT * FROM applications WHERE id = ? AND author_id = ?', 
                      (app_id, session['user_id'])).fetchone()
    
    if not app:
        conn.close()
        # flash('Application not found.', 'error')  # Removed flash message
        return redirect(url_for('web_applications'))
    
    # Check for existing reviews and drafts
    existing_responses = {}
    existing_comments = {}
    existing_screenshots = {}
    saved_section = 0  # Initialize saved_section
    
    if not retake:
        # Check for completed review of the SAME field type
        completed_review = conn.execute('''
            SELECT * FROM security_reviews 
            WHERE application_id = ? AND field_type = ? AND status IN ('submitted', 'completed') 
            ORDER BY created_at DESC LIMIT 1
        ''', (app_id, field_type)).fetchone()
        
        # If this specific field type review is completed, check if both are done
        if completed_review:
            # Check if both review types are completed
            all_reviews = conn.execute('''
                SELECT field_type FROM security_reviews 
                WHERE application_id = ? AND status IN ('submitted', 'completed')
            ''', (app_id,)).fetchall()
            
            completed_types = {review['field_type'] for review in all_reviews}
            both_completed = 'application_review' in completed_types and 'cloud_review' in completed_types
            
            conn.close()
            
            # Only redirect to results if BOTH types are completed
            if both_completed:
                return redirect(url_for('web_review_results', app_id=app_id))
            else:
                # Redirect back to security assessment to complete the other type
                return redirect(url_for('web_security_assessment', app_id=app_id))
        
        # Check for existing review (both draft and submitted) to load responses
        existing_review = conn.execute('''
            SELECT questionnaire_responses, status FROM security_reviews 
            WHERE application_id = ? AND field_type = ? AND status IN ('draft', 'submitted', 'completed')
            ORDER BY 
                CASE status 
                    WHEN 'submitted' THEN 1 
                    WHEN 'completed' THEN 2 
                    WHEN 'draft' THEN 3 
                END,
                created_at DESC 
            LIMIT 1
        ''', (app_id, field_type)).fetchone()
        
        if existing_review and existing_review['questionnaire_responses']:
            try:
                review_data = json.loads(existing_review['questionnaire_responses'])
                existing_responses = review_data.get('responses', {})
                existing_comments = review_data.get('comments', {})
                existing_screenshots = review_data.get('screenshots', {})
                
                # Only use saved section for drafts, start from beginning for submitted reviews
                if existing_review['status'] == 'draft':
                    saved_section = review_data.get('current_section', 0)
                else:
                    saved_section = 0  # Start from beginning for submitted reviews
                
                # Successfully loaded existing review data
            except Exception as e:
                print(f"❌ ERROR: Failed to load review data: {e}")
                pass
    
    conn.close()
    
    # Determine questionnaire and field name based on field type
    if field_type in SECURITY_QUESTIONNAIRES:
        # Use specific questionnaire (Application, AWS, Azure, GCP)
        questionnaire_data = SECURITY_QUESTIONNAIRES[field_type]['categories']
        field_name = SECURITY_QUESTIONNAIRES[field_type]['name']
        review_type = SECURITY_QUESTIONNAIRES[field_type]['review_type']

    else:
        # Fallback to legacy questionnaire
        questionnaire_data = SECURITY_QUESTIONNAIRE
        field_name = 'Comprehensive OWASP Security Review'
        review_type = 'application_review'
        field_type = 'comprehensive_application'  # Normalize field type

    # Apply cloud provider filtering for cloud reviews
    if field_type == 'cloud_review' and 'cloud_providers' in app.keys() and app['cloud_providers']:
        questionnaire_data = filter_cloud_questions_by_providers(questionnaire_data, app['cloud_providers'])
        print(f"🔍 Cloud filtering applied for providers: {app['cloud_providers']}")
        print(f"📊 Filtered questionnaire has {len(questionnaire_data)} categories")
    
    # Apply database type filtering for database reviews
    if field_type == 'database_review' and 'database_types' in app.keys() and app['database_types']:
        questionnaire_data = filter_database_questions_by_types(questionnaire_data, app['database_types'])
        print(f"🔍 Database filtering applied for types: {app['database_types']}")
        print(f"📊 Filtered questionnaire has {len(questionnaire_data)} categories")
    
    # Get category preferences for this application and field type
    category_preferences = {}
    if app['category_preferences']:
        try:
            all_preferences = json.loads(app['category_preferences'])
            category_preferences = all_preferences.get(field_type, {})
        except:
            category_preferences = {}
    
    return render_template('questionnaire.html', 
                         application=app, 
                         questionnaire=questionnaire_data,
                         field=field_type,
                         field_name=field_name,
                         review_type=review_type,
                         existing_responses=existing_responses,
                         existing_comments=existing_comments,
                         existing_screenshots=existing_screenshots,
                         saved_section=saved_section,
                         category_preferences=category_preferences)

# === SECURITY ANALYST ROUTES ===

@app.route('/analyst/dashboard')
@analyst_required
def analyst_dashboard():
    """Redirect to unified dashboard"""
    return redirect(url_for('web_dashboard'))

@app.route('/analyst/security-assessment/<app_id>')
@analyst_required
def analyst_security_assessment(app_id):
    """Analyst Security Assessment page with Application Review and Cloud Review categories"""
    conn = get_db()
    app = conn.execute('SELECT * FROM applications WHERE id = ?', (app_id,)).fetchone()
    
    if not app:
        conn.close()
        return redirect(url_for('analyst_dashboard'))
    
    # Check completion status for both categories
    app_review_completed = False
    cloud_review_completed = False
    app_review_id = None
    cloud_review_id = None
    
    # Check for existing reviews
    existing_reviews = conn.execute('''
        SELECT id, field_type, status FROM security_reviews 
        WHERE application_id = ? AND status IN ('submitted', 'completed', 'in_review')
        ORDER BY created_at DESC
    ''', (app_id,)).fetchall()
    
    for review in existing_reviews:
        if review['field_type'] == 'application_review' and review['status'] in ['submitted', 'completed', 'in_review']:
            app_review_completed = True
            app_review_id = review['id']
        elif review['field_type'] == 'cloud_review' and review['status'] in ['submitted', 'completed', 'in_review']:
            cloud_review_completed = True
            cloud_review_id = review['id']
    
    conn.close()
    
    return render_template('analyst/security_assessment.html', 
                         application=app,
                         app_review_completed=app_review_completed,
                         cloud_review_completed=cloud_review_completed,
                         app_review_id=app_review_id,
                         cloud_review_id=cloud_review_id)

@app.route('/analyst/review/<review_id>')
@analyst_required
def analyst_review_detail(review_id):
    """View detailed review for analysis"""
    conn = get_db()
    
    # Get review with application details and field_type
    review = conn.execute('''
        SELECT sr.id, sr.application_id, sr.questionnaire_responses, sr.risk_score, 
               sr.recommendations, sr.status, sr.analyst_reviewed_at, sr.created_at, sr.field_type,
               a.name as app_name, a.description as app_description, 
               a.technology_stack, a.deployment_environment, a.business_criticality, a.data_classification,
               a.logical_architecture_file, a.physical_architecture_file, a.overview_document_file,
               u.first_name, u.last_name, u.email
        FROM security_reviews sr
        JOIN applications a ON sr.application_id = a.id
        JOIN users u ON a.author_id = u.id
        WHERE sr.id = ?
    ''', (review_id,)).fetchone()
    
    if not review:
        # flash('Review not found.', 'error')  # Removed flash message
        return redirect(url_for('analyst_dashboard'))
    
    # Update review status to 'in_review' if it's currently 'submitted'
    if review[5] == 'submitted':  # status field
        conn.execute('''
            UPDATE security_reviews 
            SET status = 'in_review', analyst_id = ?
            WHERE id = ?
        ''', (session['user_id'], review_id))
        
        # Update application status to 'in_review' 
        success, error = update_application_status(review[1], 'in_review', conn, 'security_analyst')
        if not success:
            flash(f'Failed to update application status: {error}', 'error')
        
        conn.commit()
        
        # Create notification for the user that their application is now being reviewed
        app_name = review[9]  # app_name field
        analyst_name = session.get('user_name', 'Security Analyst')
        review_type_display = 'Application Review' if review[8] == 'application_review' else 'Cloud Review'
        
        # Get analyst details for better notification
        analyst_details = conn.execute('SELECT first_name, last_name, email FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        full_analyst_name = f"{analyst_details['first_name']} {analyst_details['last_name']}" if analyst_details else analyst_name
        analyst_email = analyst_details['email'] if analyst_details else 'Unknown'
        
        # Get the application author
        app_author = conn.execute('SELECT author_id FROM applications WHERE id = ?', (review[1],)).fetchone()
        if app_author:
            # Get author details
            author_details = conn.execute('SELECT first_name, last_name, email FROM users WHERE id = ?', (app_author['author_id'],)).fetchone()
            author_name = f"{author_details['first_name']} {author_details['last_name']}" if author_details else 'User'
            
            # Notification for the application author
            create_notification(
                title=f"{review_type_display} Started",
                message=f"Security Analyst {full_analyst_name} has started reviewing your {review_type_display.lower()} for '{app_name}'. You will be notified when the review is complete.",
                notification_type='review_started',
                application_id=review[1],
                user_id=app_author['author_id']
            )
            
            # Notification for admins
            create_notification(
                title=f"{review_type_display} In Progress - Admin Alert",
                message=f"Analyst: {full_analyst_name} ({analyst_email})\nReviewing: '{app_name}'\nSubmitted by: {author_name}\nType: {review_type_display}\nStatus: Review in progress",
                notification_type='review_started',
                application_id=review[1],
                target_role='admin'
            )
    
    # Parse the questionnaire data (now contains responses, comments, screenshots)
    questionnaire_data = json.loads(review[2]) if review[2] else {}  # questionnaire_responses
    
    # Parse questionnaire responses and comments
    
    # Extract components from the new data structure
    if isinstance(questionnaire_data, dict) and 'responses' in questionnaire_data:
        # New format with comments and screenshots
        responses = questionnaire_data.get('responses', {})
        comments = questionnaire_data.get('comments', {})
        screenshots = questionnaire_data.get('screenshots', {})
        answered_questions = questionnaire_data.get('answered_questions', 0)
        total_questions = questionnaire_data.get('total_questions', 0)
        high_risk_count = questionnaire_data.get('high_risk_count', 0)
    else:
        # Legacy format (just responses)
        responses = questionnaire_data
        comments = {}
        screenshots = {}
        answered_questions = len([r for r in responses.values() if r])
        total_questions = sum(len(cat['questions']) for cat in SECURITY_QUESTIONNAIRE.values())
        high_risk_count = len([r for r in responses.values() if r == 'no'])
    
    # Get existing STRIDE analysis
    stride_analysis = conn.execute('''
        SELECT * FROM stride_analysis WHERE review_id = ? ORDER BY threat_category
    ''', (review_id,)).fetchall()
    
    conn.close()
    
    # Determine which questionnaire to use based on field_type
    field_type = review[8] if len(review) > 8 and review[8] else 'application_review'  # field_type column
    
    if field_type in SECURITY_QUESTIONNAIRES:
        questionnaire = SECURITY_QUESTIONNAIRES[field_type]['categories']
        questionnaire_name = SECURITY_QUESTIONNAIRES[field_type]['name']
    else:
        questionnaire = SECURITY_QUESTIONNAIRE  # Fallback to legacy
        questionnaire_name = 'Comprehensive OWASP Security Review'
    
    # Generate detailed analysis data - Show ALL questions (answered and unanswered)
    question_analysis = []
    
    for category_key, category in questionnaire.items():
        for question in category['questions']:
            question_id = question['id']
            response = responses.get(question_id, 'Not answered')
            comment = comments.get(question_id, '')
            screenshot = screenshots.get(question_id, '')
            
            # Determine risk level based on response
            if response == 'no':
                risk_level = 'High'
                risk_class = 'danger'
            elif response == 'na' or response == 'partial':  # Backward compatibility
                risk_level = 'N/A' 
                risk_class = 'secondary'
            elif response == 'yes':
                risk_level = 'Low'
                risk_class = 'success'
            else:
                risk_level = 'Unknown'
                risk_class = 'secondary'
            
            # Map to STRIDE categories
            stride_categories = OWASP_TO_STRIDE_MAPPING.get(category_key, [])
            
            question_analysis.append({
                'category': category['title'],
                'question': question['question'],
                'description': question.get('description', ''),
                'question_id': question_id,
                'response': response,
                'comment': comment,
                'screenshot': screenshot,
                'risk_level': risk_level,
                'risk_class': risk_class,
                'stride_categories': stride_categories,
                'category_key': category_key
            })
    
    # Generate STRIDE threats based on responses (for the existing analyze_stride_threats function)
    identified_threats = analyze_stride_threats(responses)
    
    return render_template('analyst/review_detail.html', 
                         review=review,
                         responses=responses,
                         comments=comments,
                         screenshots=screenshots,
                         question_analysis=question_analysis,
                         answered_questions=answered_questions,
                         total_questions=total_questions,
                         high_risk_count=high_risk_count,
                         questionnaire=questionnaire,  # Use field-specific questionnaire
                         questionnaire_name=questionnaire_name,
                         field_type=field_type,
                         stride_categories=STRIDE_CATEGORIES,
                         stride_analysis=stride_analysis,
                         identified_threats=identified_threats,
                         OWASP_TO_STRIDE_MAPPING=OWASP_TO_STRIDE_MAPPING,
                         STRIDE_CATEGORIES=STRIDE_CATEGORIES)

@app.route('/analyst/review/<review_id>/stride', methods=['POST'])
@analyst_required
def save_stride_analysis(review_id):
    """Save STRIDE analysis for a review"""
    conn = get_db()
    
    # Verify review exists and analyst can access it
    review = conn.execute('SELECT id FROM security_reviews WHERE id = ?', (review_id,)).fetchone()
    if not review:
        return jsonify({'success': False, 'error': 'Review not found'}), 404
    
    try:
        # Get the finding data from the request
        finding_data = None
        if request.is_json:
            finding_data = request.get_json()
        
        if finding_data and 'question_id' in finding_data:
            # Individual finding from marking questions
            question_id = finding_data['question_id']
            stride_categories = finding_data.get('stride_categories', [])
            description = finding_data.get('description', '')
            recommendation = finding_data.get('recommendation', '')
            risk_level = finding_data.get('risk_level', 'Medium')
            
            # Save individual finding
            for stride_category in stride_categories:
                finding_id = str(uuid.uuid4())
                conn.execute('''
                    INSERT INTO stride_analysis (id, review_id, threat_category, threat_description, 
                                               risk_level, mitigation_status, question_id, 
                                               recommendations, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (finding_id, review_id, stride_category, description, risk_level, 
                      'identified', question_id, recommendation, datetime.now().isoformat()))
            
            conn.commit()
            return jsonify({'success': True, 'message': 'Finding saved successfully'})
        
        else:
            # Legacy bulk STRIDE analysis from form submission
            # Clear existing STRIDE analysis
            conn.execute('DELETE FROM stride_analysis WHERE review_id = ?', (review_id,))
            
            # Process each STRIDE category
            for category_key in STRIDE_CATEGORIES.keys():
                threat_desc = request.form.get(f'{category_key}_description', '').strip()
                risk_level = request.form.get(f'{category_key}_risk', 'Low')
                mitigation_status = request.form.get(f'{category_key}_status', 'identified')
                
                if threat_desc:  # Only save if description provided
                    analysis_id = str(uuid.uuid4())
                    conn.execute('''
                        INSERT INTO stride_analysis (id, review_id, threat_category, threat_description, 
                                                   risk_level, mitigation_status, question_id, 
                                                   recommendations, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (analysis_id, review_id, category_key, threat_desc, risk_level, 
                          mitigation_status, None, '', datetime.now().isoformat()))
            
            conn.commit()
            flash('STRIDE analysis saved successfully!', 'success')
            return redirect(url_for('analyst_review_detail', review_id=review_id))
            
    except Exception as e:
        conn.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/analyst/review/<review_id>/finalize', methods=['POST'])
@analyst_required
def finalize_review(review_id):
    """Finalize security review with analyst recommendations"""
    conn = get_db()
    
    final_report = request.form.get('final_report')
    overall_risk = request.form.get('overall_risk')
    final_recommendations = request.form.get('final_recommendations')
    
    # Create final report structure
    final_report_data = {
        'overall_risk_level': overall_risk,
        'executive_summary': final_report,
        'detailed_recommendations': final_recommendations,
        'analyst_notes': request.form.get('analyst_notes', ''),
        'finalized_by': session['user_id'],
        'finalized_at': datetime.now().isoformat()
    }
    
    # Update review
    conn.execute('''
        UPDATE security_reviews 
        SET status = 'completed', 
            final_report = ?,
            analyst_reviewed_at = CURRENT_TIMESTAMP,
            analyst_id = ?
        WHERE id = ?
    ''', (json.dumps(final_report_data), session['user_id'], review_id))
    
    # Get application_id and details for this review
    review_info = conn.execute('''
        SELECT sr.application_id, sr.field_type, a.name as app_name, a.author_id 
        FROM security_reviews sr 
        JOIN applications a ON sr.application_id = a.id 
        WHERE sr.id = ?
    ''', (review_id,)).fetchone()
    
    app_id = review_info['application_id']
    review_type_display = 'Application Review' if review_info['field_type'] == 'application_review' else 'Cloud Review'
    app_name = review_info['app_name']
    app_author_id = review_info['author_id']
    
    # Get detailed user information for better notifications
    analyst_details = conn.execute('SELECT first_name, last_name, email FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    full_analyst_name = f"{analyst_details['first_name']} {analyst_details['last_name']}" if analyst_details else analyst_name
    analyst_email = analyst_details['email'] if analyst_details else 'Unknown'
    
    author_details = conn.execute('SELECT first_name, last_name, email FROM users WHERE id = ?', (app_author_id,)).fetchone()
    author_name = f"{author_details['first_name']} {author_details['last_name']}" if author_details else 'User'
    author_email = author_details['email'] if author_details else 'Unknown'
    
    # Create notification for the user that their review is completed
    create_notification(
        title=f"{review_type_display} Completed",
        message=f"Your {review_type_display.lower()} for '{app_name}' has been completed by Security Analyst {full_analyst_name}. You can now view the detailed security report.",
        notification_type='review_completed',
        application_id=app_id,
        user_id=app_author_id
    )
    
    # Create notification for admins about completion
    create_notification(
        title=f"{review_type_display} Completed - Admin Alert",
        message=f"Analyst: {full_analyst_name} ({analyst_email})\nCompleted: '{app_name}'\nFor: {author_name} ({author_email})\nType: {review_type_display}\nStatus: Review completed",
        notification_type='review_completed',
        application_id=app_id,
        target_role='admin'
    )
    
    # Check if all reviews for this application are completed
    all_reviews = conn.execute('''
        SELECT status FROM security_reviews 
        WHERE application_id = ? AND status IN ('submitted', 'completed', 'in_review')
    ''', (app_id,)).fetchall()
    
    # If all reviews are completed, update application status
    all_completed = all([review['status'] == 'completed' for review in all_reviews])
    if all_completed and len(all_reviews) > 0:
        success, error = update_application_status(app_id, 'completed', conn, 'security_analyst')
        if not success:
            flash(f'Failed to complete application: {error}', 'error')
        
        # Create notification that entire security assessment is complete
        create_notification(
            title="Security Assessment Complete",
            message=f"All security reviews for '{app_name}' have been completed. Your comprehensive security report is now available.",
            notification_type='assessment_complete',
            application_id=app_id,
            user_id=app_author_id
        )
        
        # Create admin notification for complete assessment
        create_notification(
            title="Security Assessment Complete - Admin Alert",
            message=f"Application: '{app_name}'\nSubmitted by: {author_name} ({author_email})\nStatus: All security reviews completed\nComprehensive security report is now available.",
            notification_type='assessment_complete',
            application_id=app_id,
            target_role='admin'
        )
    
    conn.commit()
    conn.close()
    
    flash('Security review finalized successfully!', 'success')
    return redirect(url_for('analyst_dashboard'))

@app.route('/analyst/review/<review_id>/complete')
@analyst_required
def review_completion_page(review_id):
    """Display review completion page for finalizing the review"""
    conn = get_db()
    
    # Get review details with application info
    review = conn.execute('''
        SELECT sr.*, a.name as app_name, a.business_criticality, a.technology_stack,
               u.first_name, u.last_name, u.email,
               sr.id as review_id, sr.status as review_status
        FROM security_reviews sr
        JOIN applications a ON sr.application_id = a.id
        JOIN users u ON a.author_id = u.id
        WHERE sr.id = ?
    ''', (review_id,)).fetchone()
    
    if not review:
        flash('Review not found', 'error')
        conn.close()
        return redirect(url_for('analyst_reviews'))
    
    # Check if already completed
    if review['review_status'] == 'completed':
        flash('This review has already been completed', 'info')
        conn.close()
        return redirect(url_for('analyst_reviews'))
    
    # Get STRIDE analysis for this review
    stride_analysis = conn.execute('''
        SELECT * FROM stride_analysis 
        WHERE review_id = ?
        ORDER BY created_at DESC
    ''', (review_id,)).fetchall()
    
    # Get questionnaire responses summary
    responses = {}
    if review['questionnaire_responses']:
        try:
            responses = json.loads(review['questionnaire_responses'])
        except json.JSONDecodeError:
            responses = {}
    
    # Calculate summary statistics
    total_findings = len(stride_analysis)
    high_risk_findings = len([f for f in stride_analysis if f['risk_level'] == 'High'])
    critical_findings = len([f for f in stride_analysis if f['risk_level'] == 'Critical'])
    
    conn.close()
    
    return render_template('analyst/review_completion.html',
                         review=review,
                         stride_analysis=stride_analysis,
                         responses=responses,
                         total_findings=total_findings,
                         high_risk_findings=high_risk_findings,
                         critical_findings=critical_findings)

def update_application_status(app_id, new_status, conn, user_role='user', business_context=None):
    """Update application status with enhanced role-based validation"""
    
    # Get current status and business context
    current = conn.execute('''
        SELECT status, business_criticality, author_id 
        FROM applications WHERE id = ?
    ''', (app_id,)).fetchone()
    
    if not current:
        return False, "Application not found"
    
    current_status = current['status']
    
    # Prepare business context if not provided
    if business_context is None:
        business_context = {
            'criticality': current['business_criticality'],
            'application_id': app_id
        }
    
    # Check if transition is valid using workflow engine
    is_valid, error_message = workflow_engine.can_transition(
        current_status, new_status, user_role, business_context
    )
    
    if not is_valid:
        return False, error_message
    
    # Update the status
    conn.execute('UPDATE applications SET status = ? WHERE id = ?', (new_status, app_id))
    
    # Log the status change for audit
    from app.database import log_user_action
    from flask import session
    
    user_id = session.get('user_id') if 'session' in globals() else 'system'
    log_user_action(
        user_id=user_id,
        action='status_change',
        resource_type='application',
        resource_id=app_id,
        details=f"Status changed from {current_status} to {new_status}"
    )
    
    return True, None

def analyze_stride_threats(responses):
    """Analyze questionnaire responses to identify STRIDE threats"""
    threats = {category: [] for category in STRIDE_CATEGORIES.keys()}
    
    for category_key, category_data in SECURITY_QUESTIONNAIRE.items():
        stride_categories = OWASP_TO_STRIDE_MAPPING.get(category_key, [])
        
        for question in category_data['questions']:
            question_id = question['id']
            if question_id in responses:
                response_value = responses[question_id]
                
                # Handle both old numeric format and new string format
                high_risk = False
                if isinstance(response_value, str):
                        # New format: 'yes', 'no', 'na'
                    if response_value == 'no':
                        high_risk = True
                        risk_level = 'High'
                    elif response_value == 'na' or response_value == 'partial':  # Backward compatibility
                        high_risk = False  # N/A doesn't count as high risk
                        risk_level = 'N/A'
                else:
                    # Legacy numeric format (for backward compatibility)
                    try:
                        response_index = int(response_value)
                        # If response indicates low security (index 3 or 4), add as threat
                        if response_index >= 3:
                            high_risk = True
                            risk_level = 'High' if response_index == 4 else 'Medium'
                    except (ValueError, TypeError):
                        continue
                
                # Add threat if high risk response identified
                if high_risk:
                    for stride_cat in stride_categories:
                        threats[stride_cat].append({
                            'question': question['question'],
                            'category': category_data['title'],
                            'risk_level': risk_level,
                            'response': response_value,
                            'question_id': question_id
                        })
    
    return threats

@app.route('/update-category-preferences/<app_id>', methods=['POST'])
@login_required
def update_category_preferences(app_id):
    """Update category enable/disable preferences for an application"""
    try:
        data = request.get_json()
        field_type = data.get('field_type', 'application_review')
        category_preferences = data.get('preferences', {})
        
        conn = get_db()
        
        # Verify user owns this application
        app = conn.execute('SELECT * FROM applications WHERE id = ? AND author_id = ?', 
                          (app_id, session['user_id'])).fetchone()
        
        if not app:
            conn.close()
            return jsonify({'success': False, 'error': 'Application not found'}), 404
        
        # Get existing preferences
        current_preferences = {}
        if app['category_preferences']:
            try:
                current_preferences = json.loads(app['category_preferences'])
            except:
                current_preferences = {}
        
        # Update preferences for this field type
        current_preferences[field_type] = category_preferences
        
        # Save back to database
        conn.execute('UPDATE applications SET category_preferences = ? WHERE id = ?', 
                    (json.dumps(current_preferences), app_id))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/auto-save-questionnaire/<app_id>', methods=['POST'])
@login_required 
def auto_save_questionnaire(app_id):
    """Auto-save questionnaire responses as draft"""
    try:
        # Handle both JSON and form data (for sendBeacon compatibility)
        if request.is_json:
            data = request.get_json()
        else:
            # Handle sendBeacon blob data
            try:
                data = json.loads(request.data.decode('utf-8'))
            except:
                data = {}
        
        responses = data.get('responses', {})
        comments = data.get('comments', {})
        screenshots = data.get('screenshots', {})
        field_type = data.get('field_type', 'application_review')  # Get field type from request
        
        # Compile draft data
        questionnaire_data = {
            'responses': responses,
            'comments': comments, 
            'screenshots': screenshots,
            'answered_questions': len([r for r in responses.values() if r]),
            'current_section': data.get('current_section', 0),
            'is_draft': True
        }
        
        # Auto-saving responses for current field type
        
        conn = get_db()
        
        try:
            # Begin transaction
            conn.execute('BEGIN')
            
            # Check if draft already exists for this specific field type
            existing_draft = conn.execute('''
                SELECT id FROM security_reviews 
                WHERE application_id = ? AND field_type = ? AND status = 'draft'
            ''', (app_id, field_type)).fetchone()
            
            if existing_draft:
                # Update existing draft
                conn.execute('''
                    UPDATE security_reviews 
                    SET questionnaire_responses = ?, updated_at = ?
                    WHERE id = ?
                ''', (json.dumps(questionnaire_data), datetime.now().isoformat(), existing_draft[0]))
            else:
                # Create new draft
                draft_id = str(uuid.uuid4())
                conn.execute('''
                    INSERT INTO security_reviews (id, application_id, questionnaire_responses, 
                                                 status, field_type, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (draft_id, app_id, json.dumps(questionnaire_data), 'draft', field_type,
                      datetime.now().isoformat(), datetime.now().isoformat()))
            
            conn.commit()
            conn.close()
            
            return jsonify({'success': True, 'message': 'Draft saved'})
            
        except Exception as e:
            conn.execute('ROLLBACK')
            conn.close()
            return jsonify({'success': False, 'error': str(e)}), 500
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/submission-review/<app_id>')
@login_required
def submission_review(app_id):
    """Review submission page showing unanswered questions by category"""
    field_type = request.args.get('field', 'application_review')
    
    try:
        conn = get_db()
        app = conn.execute('SELECT * FROM applications WHERE id = ? AND author_id = ?', 
                          (app_id, session['user_id'])).fetchone()
        
        if not app:
            conn.close()
            return redirect(url_for('web_applications'))
        # Get existing review responses (both draft and submitted)
        existing_responses = {}
        existing_comments = {}
        
        review = conn.execute('''
            SELECT questionnaire_responses, status FROM security_reviews 
            WHERE application_id = ? AND field_type = ? AND status IN ('draft', 'submitted', 'completed')
            ORDER BY 
                CASE status 
                    WHEN 'submitted' THEN 1 
                    WHEN 'completed' THEN 2 
                    WHEN 'draft' THEN 3 
                END,
                created_at DESC 
            LIMIT 1
        ''', (app_id, field_type)).fetchone()
        
        if review and review['questionnaire_responses']:
            try:
                review_data = json.loads(review['questionnaire_responses'])
                existing_responses = review_data.get('responses', {})
                existing_comments = review_data.get('comments', {})
            except:
                pass
        
        conn.close()
        
        # Get questionnaire data based on field type
        if field_type == 'cloud_review' and app['cloud_providers']:
            questionnaire_data = SECURITY_QUESTIONNAIRES[field_type]['categories']
            questionnaire_data = filter_cloud_questions_by_providers(questionnaire_data, app['cloud_providers'])
        elif field_type == 'database_review':
            questionnaire_data = SECURITY_QUESTIONNAIRES[field_type]['categories']
            # Filter database questions by selected database types
            if app.get('database_types'):
                questionnaire_data = filter_database_questions_by_types(questionnaire_data, app['database_types'])
        else:
            questionnaire_data = SECURITY_QUESTIONNAIRES.get(field_type, {}).get('categories', {})
        

        

        
        # Analyze completion by category
        categories_summary = []
        total_questions = 0
        total_answered = 0
        
        for category_key, category_data in questionnaire_data.items():
            category_questions = len(category_data['questions'])
            category_answered = 0
            unanswered_questions = []
            
            for question in category_data['questions']:
                total_questions += 1
                # Check if question is answered (response exists and is not empty/null)
                response_value = existing_responses.get(question['id'])
                if response_value and str(response_value).strip():
                    category_answered += 1
                    total_answered += 1
                else:
                    unanswered_questions.append({
                        'id': question['id'],
                        'text': question['text'][:100] + ('...' if len(question['text']) > 100 else '')  # Truncate long questions
                    })
            
            categories_summary.append({
                'key': category_key,
                'name': category_data['name'],
                'total_questions': category_questions,
                'answered': category_answered,
                'unanswered': category_questions - category_answered,
                'completion_percentage': round((category_answered / category_questions) * 100) if category_questions > 0 else 0,
                'unanswered_questions': unanswered_questions
            })
        
        overall_completion = round((total_answered / total_questions) * 100) if total_questions > 0 else 0
        
        return render_template('submission_review.html', 
                             application=app,
                             field_type=field_type,
                             categories_summary=categories_summary,
                             total_questions=total_questions,
                             total_answered=total_answered,
                             total_unanswered=total_questions - total_answered,
                             overall_completion=overall_completion)
    except Exception as e:
        print(f"Error in submission_review: {e}")
        return redirect(url_for('web_applications'))

@app.route('/submit-questionnaire/<app_id>', methods=['POST'])
@login_required
def submit_questionnaire(app_id):
    """Submit questionnaire responses with comments and screenshots for specific field type"""
    responses = {}
    comments = {}
    screenshots = {}
    
    # Get field type from form
    field_type = request.form.get('field_type', 'application_review')
    
    # Get disabled categories from form
    disabled_categories_str = request.form.get('disabled_categories', '[]')
    try:
        disabled_categories = json.loads(disabled_categories_str)
    except:
        disabled_categories = []
    
    # Count answered questions for completion tracking
    answered_questions = 0
    high_risk_answers = 0
    
    # Get appropriate questionnaire based on field type
    if field_type in SECURITY_QUESTIONNAIRES:
        questionnaire = SECURITY_QUESTIONNAIRES[field_type]['categories']
    else:
        questionnaire = SECURITY_QUESTIONNAIRE
    
    # Process all form responses
    for key, value in request.form.items():
        if '_comment' in key:
            # Handle comment fields
            question_id = key.replace('_comment', '')
            if value.strip():  # Only store non-empty comments
                comments[question_id] = value.strip()
        elif not key.startswith(('field', 'security_confidence', 'primary_concern', 'additional_comments', 'disabled_categories')):
            # Handle regular question responses
            if value:  # If question has an answer
                responses[key] = value
                answered_questions += 1
                # Count high-risk answers (No responses)
                if value == 'no':
                    high_risk_answers += 1
    
    # Handle screenshot uploads
    upload_dir = os.path.join(UPLOAD_FOLDER, 'screenshots', app_id)
    os.makedirs(upload_dir, exist_ok=True)
    
    for key, file in request.files.items():
        if '_screenshot' in key and file.filename:
            question_id = key.replace('_screenshot', '')
            if allowed_file(file.filename, 'architecture'):  # Use architecture validation for images
                file_path = secure_upload(file, 'architecture', session['user_id'], f"{app_id}_{question_id}")
                if file_path:
                    screenshots[question_id] = file_path
    
    # Determine security level based on high-risk answers
    high_risk_percentage = (high_risk_answers / answered_questions * 100) if answered_questions > 0 else 0
    
    # Calculate risk score instead of security level
    if high_risk_percentage <= 20:
        risk_score = 1.0  # Low risk
    elif high_risk_percentage <= 50:
        risk_score = 2.0  # Medium risk
    else:
        risk_score = 3.0  # High risk
    
    # Generate recommendations (updated to not use risk_score)
    recommendations = generate_recommendations(responses, high_risk_percentage)
    
    # Calculate total questions excluding disabled categories
    total_questions = 0
    for category_key, category in questionnaire.items():
        if category_key not in disabled_categories:
            total_questions += len(category['questions'])
    
    # Compile all data for storage
    questionnaire_data = {
        'responses': responses,
        'comments': comments,
        'screenshots': screenshots,
        'answered_questions': answered_questions,
        'total_questions': total_questions,
        'high_risk_count': high_risk_answers,
        'disabled_categories': disabled_categories
    }
    
    # Save to database with proper transaction handling
    review_id = str(uuid.uuid4())
    conn = get_db()
    
    try:
        # Begin transaction
        conn.execute('BEGIN')
        
        # Delete any existing draft for this specific field_type
        conn.execute('DELETE FROM security_reviews WHERE application_id = ? AND field_type = ? AND status = "draft"', (app_id, field_type))
        
        conn.execute('''
            INSERT INTO security_reviews (id, application_id, author_id, field_type, questionnaire_responses, 
                                         risk_score, recommendations, 
                                         status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (review_id, app_id, session['user_id'], field_type, json.dumps(questionnaire_data), risk_score, 
              json.dumps(recommendations), 'submitted', datetime.now().isoformat()))
        
        # Check if all required review types are submitted after this submission
        existing_reviews = conn.execute('''
            SELECT field_type, status FROM security_reviews 
            WHERE application_id = ? AND author_id = ? AND status IN ('submitted', 'completed')
        ''', (app_id, session['user_id'])).fetchall()
        
        # Check completion status
        app_review_done = False
        cloud_review_done = False
        database_review_done = False
        
        for review in existing_reviews:
            if review['field_type'] == 'application_review':
                app_review_done = True
            elif review['field_type'] == 'cloud_review':
                cloud_review_done = True
            elif review['field_type'] == 'database_review':
                database_review_done = True
        
        # Get application to check if cloud and database reviews are required
        app = conn.execute('SELECT cloud_review_required, database_review_required FROM applications WHERE id = ?', (app_id,)).fetchone()
        cloud_review_required = app and app['cloud_review_required'] == 'yes'
        database_review_required = app and app['database_review_required'] == 'yes'
        
        # All completed only if app review is done AND (cloud review not required OR cloud review is done) AND (database review not required OR database review is done)
        all_completed = (app_review_done and 
                        (not cloud_review_required or cloud_review_done) and 
                        (not database_review_required or database_review_done))
        
        # Only update application status to 'submitted' when ALL required reviews are submitted
        if all_completed:
            success, error = update_application_status(app_id, 'submitted', conn, 'user')
            if not success:
                conn.execute('ROLLBACK')
                flash(f'Failed to submit application: {error}', 'error')
                return redirect(url_for('web_security_assessment', app_id=app_id))
        
        # Commit the transaction
        conn.commit()
        
    except Exception as e:
        conn.execute('ROLLBACK')
        flash(f'Error submitting questionnaire: {str(e)}', 'error')
        return redirect(url_for('web_security_assessment', app_id=app_id))
    
    conn.close()
    
    # Redirect back to security assessment page to show updated status
    flash('Assessment submitted successfully! Your responses have been saved.', 'success')
    return redirect(url_for('web_security_assessment', app_id=app_id))

def generate_recommendations(responses, high_risk_percentage):
    """Generate security recommendations based on responses and risk percentage"""
    recommendations = []
    
    # Check specific question responses for targeted recommendations
    for question_id, response in responses.items():
        if response == 'no':
            # Add specific recommendations based on question
            if 'input' in question_id:
                recommendations.append({
                    'category': 'Input Validation',
                    'title': 'Implement Comprehensive Input Validation',
                    'description': 'Implement server-side whitelist validation, input encoding, and parameterized queries.',
                    'priority': 'High'
                })
            elif 'auth' in question_id:
                recommendations.append({
                    'category': 'Authentication',
                    'title': 'Strengthen Authentication Controls',
                    'description': 'Implement multi-factor authentication and strong password policies.',
                    'priority': 'High'
                })
            elif 'crypto' in question_id:
                recommendations.append({
                    'category': 'Cryptography',
                    'title': 'Improve Cryptographic Implementation',
                    'description': 'Use strong algorithms (AES-256, RSA-4096) and proper key management.',
                    'priority': 'High'
                })
    
    # Add general recommendations based on overall risk
    if high_risk_percentage > 50:
        recommendations.append({
            'category': 'General',
            'title': 'Comprehensive Security Review Required',
            'description': 'Multiple high-risk areas identified. Consider a thorough security audit.',
            'priority': 'Critical'
        })
    elif high_risk_percentage > 20:
        recommendations.append({
            'category': 'General',
            'title': 'Address Identified Risk Areas',
            'description': 'Focus on improving security controls in areas marked as "No".',
            'priority': 'Medium'
        })
    
    # If no specific recommendations, add generic positive feedback
    if not recommendations:
        recommendations.append({
            'category': 'General',
            'title': 'Good Security Posture',
            'description': 'Your application demonstrates strong security controls. Continue monitoring and updating.',
            'priority': 'Low'
        })
    
    return recommendations

@app.route('/review-results/<app_id>')
@login_required
def web_review_results(app_id):
    """Display review results"""
    conn = get_db()
    
    app = conn.execute('SELECT * FROM applications WHERE id = ? AND author_id = ?', 
                      (app_id, session['user_id'])).fetchone()
    
    # Check if application exists and is not in draft status
    if not app:
        conn.close()
        return redirect(url_for('web_applications'))
    
    # Prevent access to review results for draft applications
    if app['status'] == 'draft':
        conn.close()
        flash('Review results are not available for draft applications. Please submit your application for review first.', 'warning')
        return redirect(url_for('web_security_assessment', app_id=app_id))
    
    # Get ALL submitted reviews for this application (both Application Review and Cloud Review)
    all_reviews = conn.execute('''SELECT * FROM security_reviews 
                                 WHERE application_id = ? AND status IN ('submitted', 'completed', 'in_review') 
                                 ORDER BY field_type, created_at DESC''', 
                             (app_id,)).fetchall()
    
    if not all_reviews:
        conn.close()
        flash('No review results available yet. Please complete the security assessment first.', 'info')
        return redirect(url_for('web_security_assessment', app_id=app_id))
    
    # Combine data from all reviews
    combined_responses = {}
    combined_comments = {}
    combined_screenshots = {}
    combined_answered_questions = 0
    combined_total_questions = 0
    combined_high_risk_count = 0
    combined_recommendations = []
    
    # Track which review types we have
    review_types = []
    latest_review = all_reviews[0]  # For general review info
    
    for review in all_reviews:
        field_type = review['field_type'] or 'application_review'
        review_types.append(field_type)
        
        # Parse questionnaire data
        questionnaire_data = json.loads(review['questionnaire_responses']) if review['questionnaire_responses'] else {}
        
        # Extract components from the data structure
        if isinstance(questionnaire_data, dict) and 'responses' in questionnaire_data:
            # New format with comments and screenshots
            review_responses = questionnaire_data.get('responses', {})
            review_comments = questionnaire_data.get('comments', {})
            review_screenshots = questionnaire_data.get('screenshots', {})
            review_answered_questions = questionnaire_data.get('answered_questions', 0)
            review_total_questions = questionnaire_data.get('total_questions', 0)
            review_high_risk_count = questionnaire_data.get('high_risk_count', 0)
        else:
            # Legacy format (just responses)
            review_responses = questionnaire_data
            review_comments = {}
            review_screenshots = {}
            review_answered_questions = len([r for r in review_responses.values() if r])
            if field_type in SECURITY_QUESTIONNAIRES:
                questionnaire = SECURITY_QUESTIONNAIRES[field_type]['categories']
                review_total_questions = sum(len(cat['questions']) for cat in questionnaire.values())
            else:
                review_total_questions = sum(len(cat['questions']) for cat in SECURITY_QUESTIONNAIRE.values())
            review_high_risk_count = len([r for r in review_responses.values() if r == 'no'])
        
        # Combine the data
        combined_responses.update(review_responses)
        combined_comments.update(review_comments)
        combined_screenshots.update(review_screenshots)
        combined_answered_questions += review_answered_questions
        combined_total_questions += review_total_questions
        combined_high_risk_count += review_high_risk_count
        
        # Add recommendations
        try:
            # Handle SQLite Row object properly
            try:
                recommendations_data = review['recommendations'] if review['recommendations'] else '[]'
            except (KeyError, IndexError):
                recommendations_data = '[]'
            review_recommendations = json.loads(recommendations_data)
            combined_recommendations.extend(review_recommendations)
        except (json.JSONDecodeError, TypeError, KeyError, IndexError):
            pass
    
    # Use combined data
    responses = combined_responses
    comments = combined_comments
    screenshots = combined_screenshots
    answered_questions = combined_answered_questions
    total_questions = combined_total_questions
    high_risk_count = combined_high_risk_count
    review = latest_review  # Use latest review for other metadata
    
    # Use combined recommendations
    recommendations = combined_recommendations
    
    # Only show analyst findings - no automatic findings from questionnaire responses
    findings = []
    
    # Get STRIDE findings created by analysts for ALL reviews
    stride_findings = []
    for review in all_reviews:
        review_findings = conn.execute('''
            SELECT threat_category, threat_description, risk_level, recommendations, question_id, created_at
            FROM stride_analysis 
            WHERE review_id = ?
            ORDER BY created_at DESC
        ''', (review['id'],)).fetchall()
        stride_findings.extend(review_findings)
    
    for stride_finding in stride_findings:
        # Get question details if question_id exists
        question_title = "General Security Finding"
        question_category = stride_finding['threat_category'].replace('_', ' ').title()
        
        if stride_finding['question_id']:
            # Search in both application and cloud questionnaires
            for questionnaire_type in ['application_review', 'cloud_review']:
                if questionnaire_type in SECURITY_QUESTIONNAIRES:
                    questionnaire = SECURITY_QUESTIONNAIRES[questionnaire_type]['categories']
                    for category_key, category in questionnaire.items():
                        for question in category['questions']:
                            if question['id'] == stride_finding['question_id']:
                                question_title = question['question']
                                question_category = category['title']
                                break
        
        findings.append({
            'title': f"STRIDE Analysis: {question_title}",
            'description': stride_finding['threat_description'] or f"{stride_finding['threat_category'].replace('_', ' ').title()} threat identified by analyst",
            'severity': stride_finding['risk_level'] or 'Medium',
            'category': question_category,
            'recommendation': stride_finding['recommendations'] or 'Review security implementation',
            'source': 'analyst',
            'stride_category': stride_finding['threat_category']
        })
    
    conn.close()
    
    return render_template('review_results.html', 
                         application=app, 
                         review=review, 
                         responses=responses,
                         comments=comments,
                         screenshots=screenshots,
                         findings=findings,
                         recommendations=recommendations,
                         answered_questions=answered_questions,
                         total_questions=total_questions,
                         high_risk_count=high_risk_count,
                         review_types=review_types,
                         questionnaire=SECURITY_QUESTIONNAIRE)

@app.route('/logout')
def web_logout():
    """Logout user"""
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('web_home'))

@app.route('/profile')
@login_required
def web_profile():
    """User profile page"""
    conn = get_db()
    
    # Get user information
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('web_dashboard'))
    
    # Get user statistics
    user_apps = conn.execute('SELECT COUNT(*) as count FROM applications WHERE author_id = ?', 
                             (session['user_id'],)).fetchone()['count']
    
    user_reviews = conn.execute('SELECT COUNT(*) as count FROM security_reviews sr JOIN applications a ON sr.application_id = a.id WHERE a.author_id = ?', 
                               (session['user_id'],)).fetchone()['count']
    
    # Get recent activity (last 5 applications)
    recent_activity = conn.execute('''
        SELECT name, created_at, status 
        FROM applications 
        WHERE author_id = ? 
        ORDER BY created_at DESC 
        LIMIT 5
    ''', (session['user_id'],)).fetchall()
    
    conn.close()
    
    stats = {
        'applications': user_apps,
        'reviews': user_reviews
    }
    
    return render_template('profile.html', user=user, stats=stats, recent_activity=recent_activity)

@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def web_edit_profile():
    """Edit user profile"""
    conn = get_db()
    
    if request.method == 'POST':
        # Get form data
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        organization_name = request.form.get('organization_name', '').strip()
        job_title = request.form.get('job_title', '').strip()
        experience_level = request.form.get('experience_level', '').strip()
        interests = request.form.get('interests', '').strip()
        
        # Validate required fields
        if not first_name or not last_name:
            flash('First name and last name are required.', 'error')
            return redirect(url_for('web_edit_profile'))
        
        # Update user profile
        try:
            conn.execute('''
                UPDATE users 
                SET first_name = ?, last_name = ?, organization_name = ?, 
                    job_title = ?, experience_level = ?, interests = ?
                WHERE id = ?
            ''', (first_name, last_name, organization_name, job_title, 
                  experience_level, interests, session['user_id']))
            
            conn.commit()
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('web_profile'))
            
        except Exception as e:
            flash('Error updating profile. Please try again.', 'error')
            return redirect(url_for('web_edit_profile'))
        
        finally:
            conn.close()
    
    # GET request - show edit form
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    conn.close()
    
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('web_dashboard'))
    
    return render_template('edit_profile.html', user=user)

@app.route('/profile/change-password', methods=['GET', 'POST'])
@login_required
def web_change_password():
    """Change user password"""
    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Validate input
        if not current_password or not new_password or not confirm_password:
            flash('All password fields are required.', 'error')
            return redirect(url_for('web_change_password'))
        
        if new_password != confirm_password:
            flash('New passwords do not match.', 'error')
            return redirect(url_for('web_change_password'))
        
        if len(new_password) < 8:
            flash('New password must be at least 8 characters long.', 'error')
            return redirect(url_for('web_change_password'))
        
        conn = get_db()
        
        # Verify current password
        user = conn.execute('SELECT password_hash FROM users WHERE id = ?', 
                           (session['user_id'],)).fetchone()
        
        if not user or not check_password_hash(user['password_hash'], current_password):
            flash('Current password is incorrect.', 'error')
            conn.close()
            return redirect(url_for('web_change_password'))
        
        # Update password
        try:
            new_password_hash = generate_password_hash(new_password)
            conn.execute('UPDATE users SET password_hash = ? WHERE id = ?', 
                        (new_password_hash, session['user_id']))
            conn.commit()
            flash('Password changed successfully!', 'success')
            return redirect(url_for('web_profile'))
            
        except Exception as e:
            flash('Error changing password. Please try again.', 'error')
            return redirect(url_for('web_change_password'))
        
        finally:
            conn.close()
    
    # GET request - show change password form
    return render_template('change_password.html')

# Error handlers
@app.errorhandler(404)
def not_found(error):
    from datetime import datetime
    return render_template('error.html', 
                         error_code=404, 
                         error_message='Page not found',
                         timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S')), 404

@app.errorhandler(500)
def internal_error(error):
    from datetime import datetime
    return render_template('error.html', 
                         error_code=500, 
                         error_message='Internal server error',
                         timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S')), 500

def allowed_file(filename, file_type):
    """Check if file extension is allowed for the given file type"""
    if '.' not in filename:
        return False
    return filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS[file_type]

def secure_upload(file, file_type, user_id, app_id):
    """Securely upload and store file with proper naming and validation"""
    if not file or file.filename == '':
        return None
    
    if not allowed_file(file.filename, file_type):
        return None
    
    # Create secure filename
    original_filename = secure_filename(file.filename)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"{user_id}_{app_id}_{timestamp}_{original_filename}"
    
    # Determine subdirectory based on file type
    subdir = 'architecture' if file_type == 'architecture' else 'documents'
    filepath = os.path.join(UPLOAD_FOLDER, subdir, filename)
    
    try:
        file.save(filepath)
        return filepath
    except Exception as e:
        print(f"File upload error: {e}")
        return None

@app.route('/review-results/all')
@login_required
def web_review_results_all():
    """Handle invalid /review-results/all URL - redirect silently to applications"""
    return redirect(url_for('web_applications'))

@app.route('/results')
@login_required
def web_results():
    """Results page for users - shows applications with findings count"""
    user_role = session.get('user_role', 'user')
    
    # Only allow regular users to access this page
    if user_role != 'user':
        return redirect(url_for('web_dashboard'))
    
    conn = get_db()
    
    # Get user's applications with findings count
    applications_with_findings = conn.execute('''
        SELECT a.id, a.name, a.description, a.business_criticality,
               a.technology_stack, a.status, a.created_at,
               COUNT(DISTINCT sr.id) as review_count,
               COUNT(DISTINCT sa.id) as findings_count,
               COUNT(CASE WHEN sa.risk_level = 'High' THEN 1 END) as high_risk_count,
               COUNT(CASE WHEN sa.risk_level = 'Medium' THEN 1 END) as medium_risk_count,
               COUNT(CASE WHEN sa.risk_level = 'Low' THEN 1 END) as low_risk_count,
               MAX(sr.updated_at) as last_review_date
        FROM applications a
        LEFT JOIN security_reviews sr ON a.id = sr.application_id 
            AND sr.status IN ('submitted', 'completed', 'in_review')
        LEFT JOIN stride_analysis sa ON sr.id = sa.review_id
        WHERE a.author_id = ? AND a.status != 'draft'
        GROUP BY a.id, a.name, a.description, a.business_criticality, 
                 a.technology_stack, a.status, a.created_at
        ORDER BY a.created_at DESC
    ''', (session['user_id'],)).fetchall()
    
    conn.close()
    
    return render_template('results.html', applications=applications_with_findings)

# Add this route after the existing routes, before the analyst routes

@app.route('/submit-for-review', methods=['POST'])
@login_required
def submit_for_review():
    """Submit application for security review by analysts"""
    try:
        data = request.get_json()
        app_id = data.get('app_id')
        review_type = data.get('review_type')
        
        if not app_id or not review_type:
            return jsonify({'success': False, 'error': 'Missing required parameters'}), 400
        
        conn = get_db()
        
        # Verify the application belongs to the current user
        app = conn.execute('SELECT * FROM applications WHERE id = ? AND author_id = ?', 
                          (app_id, session['user_id'])).fetchone()
        
        if not app:
            conn.close()
            return jsonify({'success': False, 'error': 'Application not found'}), 404
        
        # Check if a review already exists for this type
        existing_review = conn.execute('''
            SELECT id FROM security_reviews 
            WHERE application_id = ? AND field_type = ?
        ''', (app_id, review_type)).fetchone()
        
        if existing_review:
            conn.close()
            return jsonify({'success': False, 'error': 'Review already exists for this category'}), 400
        
        # Create a new review with 'submitted' status (waiting for analyst)
        review_id = str(uuid.uuid4())
        conn.execute('''
            INSERT INTO security_reviews (
                id, application_id, field_type, status, author_id, created_at
            ) VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ''', (review_id, app_id, review_type, 'submitted', session['user_id']))
        
        # Update application status to 'submitted' if it's currently 'draft'
        success, error = update_application_status(app_id, 'submitted', conn, 'user')
        if not success:
            return jsonify({'success': False, 'error': f'Failed to submit: {error}'}), 400
        
        conn.commit()
        conn.close()
        
        # Create notification for analysts
        app_name = app['name']
        user_name = session.get('user_name', 'A user')
        review_type_display = 'Application Review' if review_type == 'application_review' else 'Cloud Review'
        
        # Get user details for better notification
        user_details = conn.execute('SELECT first_name, last_name, email FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        full_user_name = f"{user_details['first_name']} {user_details['last_name']}" if user_details else user_name
        user_email = user_details['email'] if user_details else 'Unknown'
        
        create_notification(
            title=f"New {review_type_display} Submitted",
            message=f"{full_user_name} ({user_email}) has submitted '{app_name}' for {review_type_display.lower()}. Review is now pending assignment.",
            notification_type='new_submission',
            application_id=app_id,
            target_role='security_analyst'
        )
        
        # Create notification for admins with more details
        create_notification(
            title=f"New {review_type_display} Submitted - Admin Alert",
            message=f"User: {full_user_name} ({user_email})\nApplication: '{app_name}'\nType: {review_type_display}\nStatus: Pending analyst assignment",
            notification_type='new_submission',
            application_id=app_id,
            target_role='admin'
        )
        
        # Create notification for the user
        create_notification(
            title=f"{review_type_display} Submitted",
            message=f"Your {review_type_display.lower()} for '{app_name}' has been submitted and is pending review by our security analysts.",
            notification_type='submission_confirmation',
            application_id=app_id,
            user_id=session['user_id']
        )
        
        return jsonify({'success': True, 'message': 'Application submitted for review'})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# === NOTIFICATION FUNCTIONS ===

def create_notification(title, message, notification_type='info', application_id=None, user_id=None, target_role=None):
    """Create a new notification"""
    try:
        conn = get_db()
        notification_id = str(uuid.uuid4())
        
        # Set expiration to 30 days from now
        expires_at = datetime.now() + timedelta(days=30)
        
        conn.execute('''
            INSERT INTO notifications (id, title, message, type, application_id, user_id, target_role, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (notification_id, title, message, notification_type, application_id, user_id, target_role, expires_at))
        
        conn.commit()
        conn.close()
        return notification_id
    except Exception as e:
        print(f"Error creating notification: {e}")
        return None

def get_notifications_for_user(user_id, user_role, limit=10):
    """Get notifications for a specific user based on their role"""
    try:
        conn = get_db()
        
        # Get notifications for the user and their role, excluding expired ones
        notifications = conn.execute('''
            SELECT n.*, a.name as app_name 
            FROM notifications n
            LEFT JOIN applications a ON n.application_id = a.id
            WHERE (n.user_id = ? OR n.target_role = ? OR n.target_role IS NULL)
            AND (n.expires_at IS NULL OR n.expires_at > CURRENT_TIMESTAMP)
            ORDER BY n.created_at DESC
            LIMIT ?
        ''', (user_id, user_role, limit)).fetchall()
        
        conn.close()
        return notifications
    except Exception as e:
        print(f"Error getting notifications: {e}")
        return []

def mark_notification_read(notification_id, user_id):
    """Mark a notification as read by a user"""
    try:
        conn = get_db()
        
        # Get current read_by list
        notification = conn.execute('SELECT read_by FROM notifications WHERE id = ?', (notification_id,)).fetchone()
        if notification:
            import json
            read_by = json.loads(notification['read_by']) if notification['read_by'] else []
            
            if user_id not in read_by:
                read_by.append(user_id)
                conn.execute('UPDATE notifications SET read_by = ? WHERE id = ?', 
                           (json.dumps(read_by), notification_id))
                conn.commit()
        
        conn.close()
        return True
    except Exception as e:
        print(f"Error marking notification as read: {e}")
        return False

def get_unread_count(user_id, user_role):
    """Get count of unread notifications for a user"""
    try:
        conn = get_db()
        
        notifications = conn.execute('''
            SELECT id, read_by FROM notifications
            WHERE (user_id = ? OR target_role = ? OR target_role IS NULL)
            AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
        ''', (user_id, user_role)).fetchall()
        
        unread_count = 0
        for notification in notifications:
            import json
            read_by = json.loads(notification['read_by']) if notification['read_by'] else []
            if user_id not in read_by:
                unread_count += 1
        
        conn.close()
        return unread_count
    except Exception as e:
        print(f"Error getting unread count: {e}")
        return 0

# === NOTIFICATION API ROUTES ===

@app.route('/api/notifications')
@login_required
def api_get_notifications():
    """Get notifications for the current user"""
    try:
        limit = request.args.get('limit', 10, type=int)
        notifications = get_notifications_for_user(
            session['user_id'], 
            session.get('user_role', 'user'), 
            limit
        )
        
        # Convert to JSON-serializable format
        notifications_list = []
        for notif in notifications:
            notifications_list.append({
                'id': notif['id'],
                'title': notif['title'],
                'message': notif['message'],
                'type': notif['type'],
                'application_id': notif['application_id'],
                'app_name': notif['app_name'],
                'created_at': notif['created_at'],
                'read_by': json.loads(notif['read_by']) if notif['read_by'] else [],
                'is_read': session['user_id'] in (json.loads(notif['read_by']) if notif['read_by'] else [])
            })
        
        return jsonify({'success': True, 'notifications': notifications_list})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/notifications/<notification_id>/read', methods=['POST'])
@login_required
def api_mark_notification_read(notification_id):
    """Mark a notification as read"""
    try:
        success = mark_notification_read(notification_id, session['user_id'])
        if success:
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'error': 'Failed to mark as read'}), 400
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/notifications/unread-count')
@login_required
def api_unread_count():
    """Get unread notification count for the current user"""
    try:
        count = get_unread_count(session['user_id'], session.get('user_role', 'user'))
        return jsonify({'success': True, 'count': count})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/notifications/mark-all-read', methods=['POST'])
@login_required
def api_mark_all_read():
    """Mark all notifications as read for the current user"""
    try:
        notifications = get_notifications_for_user(
            session['user_id'], 
            session.get('user_role', 'user'), 
            100  # Get more notifications to mark them all
        )
        
        for notif in notifications:
            mark_notification_read(notif['id'], session['user_id'])
        
        return jsonify({'success': True})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# === ADMIN ROUTES ===

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    """Admin Dashboard with system-wide statistics"""
    conn = get_db()
    
    # System-wide statistics
    total_users = conn.execute('SELECT COUNT(*) as count FROM users').fetchone()['count']
    active_users = conn.execute('SELECT COUNT(*) as count FROM users WHERE is_active = 1').fetchone()['count']
    total_applications = conn.execute('SELECT COUNT(*) as count FROM applications').fetchone()['count']
    total_reviews = conn.execute('SELECT COUNT(*) as count FROM security_reviews').fetchone()['count']
    pending_reviews = conn.execute('SELECT COUNT(*) as count FROM security_reviews WHERE status IN ("submitted", "in_review")').fetchone()['count']
    
    # Application statistics by status
    app_stats = conn.execute('''
        SELECT status, COUNT(*) as count 
        FROM applications 
        GROUP BY status
    ''').fetchall()
    
    # User statistics by role
    user_stats = conn.execute('''
        SELECT role, COUNT(*) as count 
        FROM users 
        WHERE is_active = 1
        GROUP BY role
    ''').fetchall()
    
    # Security findings statistics
    findings_stats = conn.execute('''
        SELECT risk_level, COUNT(*) as count 
        FROM stride_analysis 
        GROUP BY risk_level
    ''').fetchall()
    
    # Recent activity (last 10 applications)
    recent_applications = conn.execute('''
        SELECT a.id, a.name, a.status, a.created_at, 
               u.first_name, u.last_name, u.email
        FROM applications a
        JOIN users u ON a.author_id = u.id
        ORDER BY a.created_at DESC LIMIT 10
    ''').fetchall()
    
    conn.close()
    
    stats = {
        'total_users': total_users,
        'active_users': active_users,
        'total_applications': total_applications,
        'total_reviews': total_reviews,
        'pending_reviews': pending_reviews,
        'app_stats': {row['status']: row['count'] for row in app_stats},
        'user_stats': {row['role']: row['count'] for row in user_stats},
        'findings_stats': {row['risk_level']: row['count'] for row in findings_stats}
    }
    
    return render_template('admin/dashboard.html', 
                         stats=stats, 
                         recent_applications=recent_applications)

@app.route('/admin/users')
@admin_required
def admin_users():
    """Admin User Management"""
    conn = get_db()
    
    # Get all users with additional information
    users_raw = conn.execute('''
        SELECT u.*, 
               COUNT(a.id) as application_count,
               COUNT(sr.id) as review_count
        FROM users u
        LEFT JOIN applications a ON u.id = a.author_id
        LEFT JOIN security_reviews sr ON u.id = sr.analyst_id
        GROUP BY u.id
        ORDER BY u.created_at DESC
    ''').fetchall()
    
    conn.close()
    
    # Convert Row objects to dictionaries for JSON serialization
    users = [dict(user) for user in users_raw]
    
    return render_template('admin/users.html', users=users)

@app.route('/admin/users/<user_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_edit_user(user_id):
    """Edit user details and role"""
    conn = get_db()
    
    if request.method == 'POST':
        # Update user information
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        role = request.form.get('role')
        is_active = 1 if request.form.get('is_active') == 'on' else 0
        
        try:
            conn.execute('''
                UPDATE users 
                SET first_name = ?, last_name = ?, email = ?, role = ?, is_active = ?
                WHERE id = ?
            ''', (first_name, last_name, email, role, is_active, user_id))
            conn.commit()
            
            flash(f'User {first_name} {last_name} updated successfully!', 'success')
            return redirect(url_for('admin_users'))
            
        except Exception as e:
            flash(f'Error updating user: {str(e)}', 'error')
    
    # Get user details
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('admin_users'))
    
    return render_template('admin/edit_user.html', user=user)

@app.route('/admin/users/<user_id>/toggle-status', methods=['POST'])
@admin_required
def admin_toggle_user_status(user_id):
    """Toggle user active status"""
    conn = get_db()
    
    user = conn.execute('SELECT is_active, first_name, last_name FROM users WHERE id = ?', (user_id,)).fetchone()
    if user:
        new_status = 0 if user['is_active'] else 1
        conn.execute('UPDATE users SET is_active = ? WHERE id = ?', (new_status, user_id))
        conn.commit()
        
        status_text = "activated" if new_status else "deactivated"
        flash(f'User {user["first_name"]} {user["last_name"]} {status_text} successfully!', 'success')
    else:
        flash('User not found', 'error')
    
    conn.close()
    return redirect(url_for('admin_users'))

@app.route('/admin/applications')
@admin_required
def admin_applications():
    """Admin Application Management"""
    conn = get_db()
    
    # Get all applications with user information
    applications_raw = conn.execute('''
        SELECT a.*, 
               u.first_name, u.last_name, u.email,
               COUNT(sr.id) as review_count,
               MAX(sr.created_at) as last_review_date
        FROM applications a
        JOIN users u ON a.author_id = u.id
        LEFT JOIN security_reviews sr ON a.id = sr.application_id
        GROUP BY a.id
        ORDER BY a.created_at DESC
    ''').fetchall()
    
    conn.close()
    
    # Convert Row objects to dictionaries for JSON serialization
    applications = [dict(app) for app in applications_raw]
    
    return render_template('admin/applications.html', applications=applications)

@app.route('/admin/applications/<app_id>/change-status', methods=['POST'])
@admin_required
def admin_change_application_status(app_id):
    """Admin override of application status"""
    new_status = request.form.get('status')
    
    conn = get_db()
    app = conn.execute('SELECT name FROM applications WHERE id = ?', (app_id,)).fetchone()
    
    if app:
        conn.execute('UPDATE applications SET status = ? WHERE id = ?', (new_status, app_id))
        conn.commit()
        flash(f'Application "{app["name"]}" status changed to {new_status}!', 'success')
    else:
        flash('Application not found', 'error')
    
    conn.close()
    return redirect(url_for('admin_applications'))

@app.route('/admin/applications/<app_id>/delete', methods=['POST'])
@admin_required
def admin_delete_application(app_id):
    """Admin delete application with all related data"""
    conn = get_db()
    
    try:
        app = conn.execute('SELECT name FROM applications WHERE id = ?', (app_id,)).fetchone()
        
        if app:
            # Delete related records first (due to foreign key constraints)
            conn.execute('DELETE FROM stride_analysis WHERE review_id IN (SELECT id FROM security_reviews WHERE application_id = ?)', (app_id,))
            conn.execute('DELETE FROM security_reviews WHERE application_id = ?', (app_id,))
            conn.execute('DELETE FROM notifications WHERE application_id = ?', (app_id,))
            conn.execute('DELETE FROM applications WHERE id = ?', (app_id,))
            conn.commit()
            
            flash(f'Application "{app["name"]}" and all related data deleted successfully!', 'success')
        else:
            flash('Application not found', 'error')
            
    except Exception as e:
        flash(f'Error deleting application: {str(e)}', 'error')
    
    conn.close()
    return redirect(url_for('admin_applications'))

@app.route('/admin/reviews')
@admin_required
def admin_reviews():
    """Admin Security Review Management"""
    conn = get_db()
    
    # Get all security reviews with application and user information
    reviews_raw = conn.execute('''
        SELECT sr.*, 
               a.name as app_name,
               u1.first_name as author_first, u1.last_name as author_last, u1.email as author_email,
               u2.first_name as analyst_first, u2.last_name as analyst_last, u2.email as analyst_email
        FROM security_reviews sr
        JOIN applications a ON sr.application_id = a.id
        JOIN users u1 ON a.author_id = u1.id
        LEFT JOIN users u2 ON sr.analyst_id = u2.id
        ORDER BY sr.created_at DESC
    ''').fetchall()
    
    # Get available analysts for reassignment
    analysts_raw = conn.execute('''
        SELECT id, first_name, last_name, email 
        FROM users 
        WHERE role IN ('security_analyst', 'admin') AND is_active = 1
        ORDER BY first_name, last_name
    ''').fetchall()
    
    conn.close()
    
    # Convert Row objects to dictionaries for JSON serialization
    reviews = [dict(review) for review in reviews_raw]
    analysts = [dict(analyst) for analyst in analysts_raw]
    
    return render_template('admin/reviews.html', reviews=reviews, analysts=analysts)

@app.route('/admin/reviews/<review_id>/reassign', methods=['POST'])
@admin_required
def admin_reassign_review(review_id):
    """Reassign review to different analyst"""
    new_analyst_id = request.form.get('analyst_id')
    
    conn = get_db()
    
    # Get analyst name for flash message
    analyst = conn.execute('SELECT first_name, last_name FROM users WHERE id = ?', (new_analyst_id,)).fetchone()
    
    if analyst:
        conn.execute('UPDATE security_reviews SET analyst_id = ? WHERE id = ?', (new_analyst_id, review_id))
        conn.commit()
        flash(f'Review reassigned to {analyst["first_name"]} {analyst["last_name"]}!', 'success')
    else:
        flash('Analyst not found', 'error')
    
    conn.close()
    return redirect(url_for('admin_reviews'))

@app.route('/admin/audit-logs')
@admin_required
def admin_audit_logs():
    """View system audit logs"""
    conn = get_db()
    
    # Get recent audit logs with user information
    logs = conn.execute('''
        SELECT al.*, u.first_name, u.last_name, u.email
        FROM audit_logs al
        LEFT JOIN users u ON al.user_id = u.id
        ORDER BY al.created_at DESC
        LIMIT 100
    ''').fetchall()
    
    conn.close()
    
    return render_template('admin/audit_logs.html', logs=logs)

@app.route('/admin/settings')
@admin_required
def admin_settings():
    """System configuration settings"""
    return render_template('admin/settings.html')

@app.route('/admin/reports')
@admin_required
def admin_reports():
    """Generate system reports"""
    conn = get_db()
    
    # Comprehensive system statistics for reporting
    report_data = {
        'users': {
            'total': conn.execute('SELECT COUNT(*) as count FROM users').fetchone()['count'],
            'active': conn.execute('SELECT COUNT(*) as count FROM users WHERE is_active = 1').fetchone()['count'],
            'by_role': dict(conn.execute('SELECT role, COUNT(*) as count FROM users GROUP BY role').fetchall())
        },
        'applications': {
            'total': conn.execute('SELECT COUNT(*) as count FROM applications').fetchone()['count'],
            'by_status': dict(conn.execute('SELECT status, COUNT(*) as count FROM applications GROUP BY status').fetchall()),
            'by_criticality': dict(conn.execute('SELECT business_criticality, COUNT(*) as count FROM applications GROUP BY business_criticality').fetchall())
        },
        'reviews': {
            'total': conn.execute('SELECT COUNT(*) as count FROM security_reviews').fetchone()['count'],
            'by_status': dict(conn.execute('SELECT status, COUNT(*) as count FROM security_reviews GROUP BY status').fetchall()),
            'by_analyst': dict(conn.execute('''
                SELECT u.first_name || " " || u.last_name as analyst_name, COUNT(*) as count 
                FROM security_reviews sr 
                JOIN users u ON sr.analyst_id = u.id 
                WHERE sr.analyst_id IS NOT NULL 
                GROUP BY sr.analyst_id
            ''').fetchall())
        },
        'findings': {
            'total': conn.execute('SELECT COUNT(*) as count FROM stride_analysis').fetchone()['count'],
            'by_risk_level': dict(conn.execute('SELECT risk_level, COUNT(*) as count FROM stride_analysis GROUP BY risk_level').fetchall()),
            'by_category': dict(conn.execute('SELECT threat_category, COUNT(*) as count FROM stride_analysis GROUP BY threat_category').fetchall())
        }
    }
    
    conn.close()
    
    return render_template('admin/reports.html', report_data=report_data)

@app.route('/analyst/reviews')
@analyst_required
def analyst_reviews():
    """Analyst Security Review Management"""
    conn = get_db()
    
    # Get applications with their review types grouped
    apps_data = conn.execute('''
        SELECT a.id as application_id, a.name as app_name, a.business_criticality,
               a.description, a.technology_stack, a.deployment_environment,
               (u.first_name || ' ' || u.last_name) as author_name, u.email,
               MIN(sr.created_at) as earliest_review_date,
               GROUP_CONCAT(sr.field_type) as review_types,
               GROUP_CONCAT(sr.id) as review_ids,
               GROUP_CONCAT(sr.status) as review_statuses,
               GROUP_CONCAT(sr.created_at) as review_dates
        FROM applications a
        JOIN security_reviews sr ON a.id = sr.application_id
        JOIN users u ON a.author_id = u.id
        WHERE sr.analyst_id = ? OR (sr.analyst_id IS NULL AND sr.status IN ('submitted', 'in_review'))
        GROUP BY a.id, a.name, a.business_criticality, a.description, 
                 a.technology_stack, a.deployment_environment,
                 u.first_name, u.last_name, u.email
        ORDER BY MIN(sr.created_at) DESC
    ''', (session['user_id'],)).fetchall()
    
    # Process the data to create a more usable structure
    applications = []
    for app_data in apps_data:
        review_types = app_data['review_types'].split(',') if app_data['review_types'] else []
        review_ids = app_data['review_ids'].split(',') if app_data['review_ids'] else []
        review_statuses = app_data['review_statuses'].split(',') if app_data['review_statuses'] else []
        review_dates = app_data['review_dates'].split(',') if app_data['review_dates'] else []
        
        # Create review objects for each review type
        reviews = []
        for i, review_type in enumerate(review_types):
            reviews.append({
                'id': review_ids[i] if i < len(review_ids) else '',
                'field_type': review_type,
                'status': review_statuses[i] if i < len(review_statuses) else '',
                'created_at': review_dates[i] if i < len(review_dates) else ''
            })
        
        # Determine overall review status based on all reviews
        statuses = [review['status'] for review in reviews]
        if 'completed' in statuses:
            overall_status = 'completed'
        elif 'in_review' in statuses:
            overall_status = 'in_review'
        elif 'submitted' in statuses:
            overall_status = 'submitted'
        else:
            overall_status = 'draft'
        
        applications.append({
            'application_id': app_data['application_id'],
            'app_name': app_data['app_name'],
            'business_criticality': app_data['business_criticality'],
            'description': app_data['description'],
            'technology_stack': app_data['technology_stack'],
            'deployment_environment': app_data['deployment_environment'],
            'author_name': app_data['author_name'],
            'email': app_data['email'],
            'earliest_review_date': app_data['earliest_review_date'],
            'reviews': reviews,
            'review_count': len(reviews),
            'review_status': overall_status
        })
    
    conn.close()
    
    return render_template('analyst/reviews.html', applications=applications)

@app.route('/debug/reviews')
@analyst_required
def debug_reviews():
    """Debug route to check review statuses"""
    conn = get_db()
    
    # Get all reviews for debugging
    reviews = conn.execute('''
        SELECT sr.id, sr.status, sr.field_type, a.name as app_name, sr.analyst_id
        FROM security_reviews sr
        JOIN applications a ON sr.application_id = a.id
        ORDER BY sr.updated_at DESC
    ''').fetchall()
    
    conn.close()
    
    # Convert to list for JSON serialization
    reviews_list = []
    for review in reviews:
        reviews_list.append({
            'id': review['id'],
            'status': review['status'],
            'field_type': review['field_type'],
            'app_name': review['app_name'],
            'analyst_id': review['analyst_id']
        })
    
    return jsonify(reviews_list)

@app.route('/edit-application/<app_id>', methods=['GET', 'POST'])
@login_required
def edit_application(app_id):
	"""Edit an existing application (only for the author while in draft/rejected)."""
	conn = get_db()
	application = conn.execute('SELECT * FROM applications WHERE id = ? AND author_id = ?',
							   (app_id, session['user_id'])).fetchone()
	if not application:
		conn.close()
		flash('Application not found.', 'error')
		return redirect(url_for('web_applications'))

	# Prevent editing once submitted/in_review/completed by default
	if application['status'] not in ('draft', 'rejected'):
		conn.close()
		flash('Editing is only allowed while the application is in Draft or Rejected state.', 'warning')
		return redirect(url_for('web_applications'))

	if request.method == 'POST':
		# Extract form data
		data = {
			'name': request.form.get('name', application['name']),
			'description': request.form.get('description', application['description']),
			'technology_stack': ', '.join(request.form.getlist('technology_stack')),
			'deployment_environment': request.form.get('deployment_environment', application['deployment_environment']),
			'business_criticality': request.form.get('business_criticality', application['business_criticality']),
			'data_classification': request.form.get('data_classification', application['data_classification']),
			'cloud_review_required': request.form.get('cloud_review_required', application['cloud_review_required'] or 'no'),
			'cloud_providers': ', '.join(request.form.getlist('cloud_providers')),
			'database_review_required': request.form.get('database_review_required', application['database_review_required'] or 'no'),
			'database_types': ', '.join(request.form.getlist('database_types'))
		}

		# If no new multi-select values are provided, keep existing values
		if not data['technology_stack']:
			data['technology_stack'] = application['technology_stack'] or ''
		if not data['cloud_providers']:
			data['cloud_providers'] = application['cloud_providers'] or ''
		if not data['database_types']:
			data['database_types'] = application['database_types'] or ''

		# Validate required fields
		if not all([data['name'], data['business_criticality'], data['data_classification']]):
			flash('Please fill in all required fields.', 'error')
			conn.close()
			return redirect(url_for('edit_application', app_id=app_id))

		# Handle optional file uploads; if not provided, keep existing
		file_paths = {
			'logical_architecture_file': application['logical_architecture_file'],
			'physical_architecture_file': application['physical_architecture_file'],
			'overview_document_file': application['overview_document_file']
		}
		file_fields = {
			'logical_architecture': 'architecture',
			'physical_architecture': 'architecture',
			'overview_document': 'document'
		}
		for field_name, file_type in file_fields.items():
			if field_name in request.files:
				file = request.files[field_name]
				if file and getattr(file, 'filename', ''):
					path = secure_upload(file, file_type, session['user_id'], app_id)
					if path:
						file_paths[f"{field_name}_file"] = path
					else:
						flash(f'Invalid file type for {field_name.replace("_", " ").title()}.', 'error')
						conn.close()
						return redirect(url_for('edit_application', app_id=app_id))

		# Perform update
		conn.execute('''
			UPDATE applications
			SET name = ?, description = ?, technology_stack = ?,
				deployment_environment = ?, business_criticality = ?,
				data_classification = ?, logical_architecture_file = ?,
				physical_architecture_file = ?, overview_document_file = ?,
				cloud_review_required = ?, cloud_providers = ?,
				database_review_required = ?, database_types = ?
			WHERE id = ? AND author_id = ?
		''', (
			data['name'], data['description'], data['technology_stack'],
			data['deployment_environment'], data['business_criticality'],
			data['data_classification'], file_paths['logical_architecture_file'],
			file_paths['physical_architecture_file'], file_paths['overview_document_file'],
			data['cloud_review_required'], data['cloud_providers'],
			data['database_review_required'], data['database_types'],
			app_id, session['user_id']
		))
		conn.commit()
		conn.close()
		flash('Application updated successfully.', 'success')
		return redirect(url_for('web_applications'))

	# GET: show form with existing values
	conn.close()
	return render_template('edit_application.html', application=application)

@app.route('/uploads/<path:filename>')
@login_required
def serve_uploads(filename):
	"""Serve files from the uploads directory (screenshots, docs, diagrams)."""
	uploads_base = os.path.join(app.root_path, 'uploads')
	# Normalize path to prevent traversal
	file_path = os.path.join(uploads_base, filename)
	real_uploads = os.path.realpath(uploads_base)
	real_file = os.path.realpath(file_path)
	if not real_file.startswith(real_uploads):
		return ('Forbidden', 403)
	if not os.path.exists(real_file):
		return ('Not Found', 404)
	return send_from_directory(os.path.dirname(real_file), os.path.basename(real_file))

@app.route('/admin/applications/export')
@login_required
def admin_export_applications():
	"""Export applications list as CSV for admins/analysts."""
	# Basic role check: allow admin and security_analyst
	user_role = session.get('user_role', 'user')
	if user_role not in ('admin', 'security_analyst'):
		flash('Access denied.', 'error')
		return redirect(url_for('web_dashboard'))
	
	conn = get_db()
	rows = conn.execute('''
		SELECT a.name, a.description, a.technology_stack, a.deployment_environment,
		       a.business_criticality, a.data_classification, a.status,
		       (u.first_name || ' ' || u.last_name) as author_name,
		       a.created_at
		FROM applications a
		LEFT JOIN users u ON a.author_id = u.id
		ORDER BY a.created_at DESC
	''').fetchall()
	conn.close()
	
	# Build CSV
	output = io.StringIO()
	writer = csv.writer(output)
	writer.writerow(['Application', 'Description', 'Tech Stack', 'Environment', 'Criticality', 'Classification', 'Status', 'Author', 'Created'])
	for r in rows:
		writer.writerow([
			r['name'], r['description'], r['technology_stack'], r['deployment_environment'],
			r['business_criticality'], r['data_classification'], r['status'], r['author_name'], r['created_at']
		])
	csv_data = output.getvalue()
	output.close()
	
	return Response(
		csv_data,
		mimetype='text/csv',
		headers={'Content-Disposition': 'attachment; filename=applications_export.csv'}
	)

if __name__ == '__main__':
    # Initialize database
    init_db()
    # Migrate database for STRIDE analysis support
    migrate_database()
    print("🚀 SecureArch Portal Web Application starting...")
    print("📊 Database initialized with demo users")
    print("🔐 Authentication system ready")
    print("📋 Security questionnaires loaded")
    print("🛡️ STRIDE threat modeling ready")
    print("🌐 Server starting on http://localhost:5000")
    print("👤 Demo User: user@demo.com / password123")
    print("🔍 Demo Analyst: analyst@demo.com / analyst123")
    print("🛡️ Demo Admin: superadmin@demo.com / admin123")
    
    # Start Flask app
    app.run(host='0.0.0.0', port=5000, debug=True) 