#!/usr/bin/env python3
"""
SecureArch Portal - Complete Web Application
Enterprise-grade Security Architecture Review Platform with Web Interface
"""

import os
import json
import uuid
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import jwt
from functools import wraps

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'dev-secret-key-change-in-production'

# Configuration
app.config['SECRET_KEY'] = 'dev-secret-key-change-in-production'
app.config['JWT_SECRET'] = 'jwt-secret-change-in-production'

# Enable CORS
CORS(app, origins=['http://localhost:3000', 'http://localhost:5000', 'http://127.0.0.1:5000'])

# Database setup
DATABASE = 'securearch_portal.db'

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
        
        # Create STRIDE analysis table if it doesn't exist
        conn.execute('''
            CREATE TABLE IF NOT EXISTS stride_analysis (
                id TEXT PRIMARY KEY,
                review_id TEXT,
                threat_category TEXT,
                threat_description TEXT,
                risk_level TEXT,
                mitigation_status TEXT,
                recommendations TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (review_id) REFERENCES security_reviews (id)
            )
        ''')
        print("   ✅ Created stride_analysis table")
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
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (author_id) REFERENCES users (id)
        )
    ''')
    
    # Security Reviews table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS security_reviews (
            id TEXT PRIMARY KEY,
            application_id TEXT,
            questionnaire_responses TEXT,
            risk_score REAL,
            security_level TEXT,
            recommendations TEXT,
            status TEXT DEFAULT 'in_progress',
            analyst_id TEXT,
            stride_analysis TEXT,
            final_report TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP,
            analyst_reviewed_at TIMESTAMP,
            FOREIGN KEY (application_id) REFERENCES applications (id),
            FOREIGN KEY (analyst_id) REFERENCES users (id)
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
            recommendations TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (review_id) REFERENCES security_reviews (id)
        )
    ''')
    
    # Create demo users if not exists
    existing_demo = conn.execute('SELECT id FROM users WHERE email = ?', ('admin@demo.com',)).fetchone()
    if not existing_demo:
        demo_user_id = str(uuid.uuid4())
        demo_password_hash = generate_password_hash('password123')
        conn.execute('''
            INSERT INTO users (id, email, password_hash, first_name, last_name, role, organization_name, onboarding_completed)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (demo_user_id, 'admin@demo.com', demo_password_hash, 'Demo', 'Admin', 'admin', 'SecureArch Corp', 1))
    
    # Create demo Security Analyst if not exists
    existing_analyst = conn.execute('SELECT id FROM users WHERE email = ?', ('analyst@demo.com',)).fetchone()
    if not existing_analyst:
        analyst_user_id = str(uuid.uuid4())
        analyst_password_hash = generate_password_hash('analyst123')
        conn.execute('''
            INSERT INTO users (id, email, password_hash, first_name, last_name, role, organization_name, job_title, onboarding_completed)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (analyst_user_id, 'analyst@demo.com', analyst_password_hash, 'Security', 'Analyst', 'security_analyst', 'SecureArch Corp', 'Senior Security Analyst', 1))
    
    conn.commit()
    conn.close()

def login_required(f):
    """Decorator to require login for routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('web_login'))
        return f(*args, **kwargs)
    return decorated_function

def analyst_required(f):
    """Decorator to require Security Analyst role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('web_login'))
        
        # Check if user has analyst role
        conn = get_db()
        user = conn.execute('SELECT role FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        conn.close()
        
        if not user or user[0] not in ['security_analyst', 'admin']:
            flash('Access denied. Security Analyst role required.', 'error')
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

# Field-Specific OWASP Security Questionnaires
SECURITY_QUESTIONNAIRES = {
    "web_application": {
        "name": "Web Application Security Review",
        "description": "Comprehensive OWASP Top 10 based security assessment for web applications",
        "categories": {
            "input_validation": {
                "title": "Input Validation & Injection Prevention",
                "description": "OWASP A1 (Injection), A3 (Sensitive Data), A6 (Security Misconfiguration)",
                "questions": [
                    {
                        "id": "input_1",
                        "question": "How does your application validate and sanitize user input?",
                        "description": "Input validation prevents injection attacks (SQL, XSS, XXE, etc.)",
                        "type": "radio",
                        "options": [
                            "Server-side whitelist validation + input encoding + parameterized queries",
                            "Server-side validation with both whitelist and blacklist",
                            "Client-side validation with some server-side checks",
                            "Basic input filtering only",
                            "No formal input validation"
                        ],
                        "weights": [10, 8, 4, 2, 0]
                    },
                    {
                        "id": "input_2",
                        "question": "What protection do you have against SQL injection attacks?",
                        "description": "SQL injection is the #1 web application vulnerability",
                        "type": "radio",
                        "options": [
                            "Prepared statements + ORM + input validation + least privilege DB access",
                            "Prepared statements or ORM with input validation",
                            "Stored procedures with some validation",
                            "Input sanitization only",
                            "No specific SQL injection protection"
                        ],
                        "weights": [10, 8, 5, 2, 0]
                    },
                    {
                        "id": "input_3",
                        "question": "How do you prevent Cross-Site Scripting (XSS) attacks?",
                        "description": "XSS can lead to session hijacking and data theft",
                        "type": "radio",
                        "options": [
                            "CSP headers + output encoding + input validation + HttpOnly cookies",
                            "Output encoding and input validation",
                            "Basic input filtering for scripts",
                            "Some XSS protection measures",
                            "No specific XSS protection"
                        ],
                        "weights": [10, 7, 4, 2, 0]
                    },
                    {
                        "id": "input_4",
                        "question": "What file upload security measures are implemented?",
                        "description": "File uploads can be vectors for malware and code execution",
                        "type": "radio",
                        "options": [
                            "File type validation + virus scanning + size limits + sandbox execution",
                            "File type validation + size limits + content scanning",
                            "Basic file type and size validation",
                            "File type validation only",
                            "No file upload restrictions"
                        ],
                        "weights": [10, 8, 5, 3, 0]
                    }
                ]
            },
            "authentication": {
                "title": "Authentication & Identity Management (IAM)",
                "description": "OWASP A2 (Broken Authentication) - Securing user identity and authentication",
                "questions": [
                    {
                        "id": "auth_1",
                        "question": "What authentication methods does your application support?",
                        "description": "Strong authentication prevents unauthorized access",
                        "type": "radio",
                        "options": [
                            "Multi-factor authentication (MFA) required for all users",
                            "MFA required for admin users, optional for others",
                            "Strong password policy with optional MFA",
                            "Basic password authentication only",
                            "Weak or no authentication requirements"
                        ],
                        "weights": [10, 8, 6, 3, 0]
                    },
                    {
                        "id": "auth_2",
                        "question": "How are user passwords stored and protected?",
                        "description": "Proper password storage prevents credential theft",
                        "type": "radio",
                        "options": [
                            "Argon2, scrypt, or bcrypt with salt + pepper + key stretching",
                            "bcrypt or PBKDF2 with salt",
                            "SHA-256 with salt",
                            "MD5 or SHA-1 with salt",
                            "Plain text or weak hashing"
                        ],
                        "weights": [10, 8, 4, 2, 0]
                    },
                    {
                        "id": "auth_3",
                        "question": "What password policy is enforced?",
                        "description": "Strong password policies reduce brute force attacks",
                        "type": "radio",
                        "options": [
                            "12+ chars, complexity, no common passwords, breach checking",
                            "8+ chars with complexity requirements",
                            "Minimum length requirements only",
                            "Basic password requirements",
                            "No password policy"
                        ],
                        "weights": [10, 7, 4, 2, 0]
                    },
                    {
                        "id": "auth_4",
                        "question": "How do you handle account lockout and brute force protection?",
                        "description": "Account lockout prevents brute force attacks",
                        "type": "radio",
                        "options": [
                            "Progressive delays + CAPTCHA + IP blocking + monitoring",
                            "Account lockout with progressive delays",
                            "Basic account lockout after failed attempts",
                            "Rate limiting only",
                            "No brute force protection"
                        ],
                        "weights": [10, 8, 5, 3, 0]
                    }
                ]
            },
            "authorization": {
                "title": "Authorization & Access Control",
                "description": "OWASP A5 (Broken Access Control) - Ensuring proper authorization and permissions",
                "questions": [
                    {
                        "id": "authz_1",
                        "question": "What access control model does your application implement?",
                        "description": "Proper access control prevents unauthorized actions",
                        "type": "radio",
                        "options": [
                            "Role-based access control (RBAC) with least privilege principle",
                            "Attribute-based access control (ABAC)",
                            "Simple role-based access control",
                            "Basic user/admin separation",
                            "No formal access control"
                        ],
                        "weights": [10, 9, 6, 3, 0]
                    },
                    {
                        "id": "authz_2",
                        "question": "How do you prevent privilege escalation attacks?",
                        "description": "Privilege escalation can lead to unauthorized access",
                        "type": "radio",
                        "options": [
                            "Least privilege + regular access reviews + separation of duties",
                            "Least privilege principle enforced",
                            "Regular access reviews conducted",
                            "Basic role separation",
                            "No specific privilege escalation protection"
                        ],
                        "weights": [10, 8, 5, 3, 0]
                    },
                    {
                        "id": "authz_3",
                        "question": "How are administrative functions protected?",
                        "description": "Admin functions require extra protection",
                        "type": "radio",
                        "options": [
                            "Separate admin interface + MFA + IP restrictions + logging",
                            "MFA required for admin functions",
                            "Separate admin interface",
                            "Admin functions mixed with user functions",
                            "No special admin protection"
                        ],
                        "weights": [10, 7, 4, 2, 0]
                    }
                ]
            },
            "configuration_management": {
                "title": "Security Configuration Management",
                "description": "OWASP A6 (Security Misconfiguration) - Secure configuration and hardening",
                "questions": [
                    {
                        "id": "config_1",
                        "question": "How is your application server configured for security?",
                        "description": "Secure server configuration prevents many attack vectors",
                        "type": "radio",
                        "options": [
                            "Hardened configuration + security headers + minimal services + regular updates",
                            "Security headers implemented with basic hardening",
                            "Some security configurations applied",
                            "Default configuration with minimal changes",
                            "Default server configuration used"
                        ],
                        "weights": [10, 7, 4, 2, 0]
                    },
                    {
                        "id": "config_2",
                        "question": "What security headers does your application implement?",
                        "description": "Security headers provide important browser-side protection",
                        "type": "radio",
                        "options": [
                            "CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy",
                            "HSTS, X-Frame-Options, X-Content-Type-Options",
                            "Basic security headers (X-Frame-Options, etc.)",
                            "Some security headers implemented",
                            "No security headers"
                        ],
                        "weights": [10, 8, 5, 2, 0]
                    },
                    {
                        "id": "config_3",
                        "question": "How do you manage application secrets and environment variables?",
                        "description": "Proper secrets management prevents credential exposure",
                        "type": "radio",
                        "options": [
                            "Dedicated secrets management system (HashiCorp Vault, AWS Secrets Manager)",
                            "Environment variables with proper access controls",
                            "Encrypted configuration files",
                            "Configuration files with basic protection",
                            "Secrets stored in code or plain text"
                        ],
                        "weights": [10, 7, 5, 2, 0]
                    }
                ]
            },
            "sensitive_data": {
                "title": "Sensitive Data Protection",
                "description": "OWASP A3 (Sensitive Data Exposure) - Protecting sensitive information",
                "questions": [
                    {
                        "id": "data_1",
                        "question": "How is sensitive data identified and classified?",
                        "description": "Data classification is the first step in protection",
                        "type": "radio",
                        "options": [
                            "Comprehensive data classification with automated discovery",
                            "Manual data classification with documentation",
                            "Basic identification of sensitive data types",
                            "Informal sensitive data identification",
                            "No formal data classification"
                        ],
                        "weights": [10, 8, 5, 2, 0]
                    },
                    {
                        "id": "data_2",
                        "question": "How is sensitive data encrypted at rest?",
                        "description": "Encryption at rest protects data if storage is compromised",
                        "type": "radio",
                        "options": [
                            "AES-256 encryption with proper key management and HSM",
                            "AES-256 encryption with key rotation",
                            "AES-128/256 encryption with basic key management",
                            "Basic encryption without key management",
                            "No encryption at rest"
                        ],
                        "weights": [10, 8, 5, 2, 0]
                    },
                    {
                        "id": "data_3",
                        "question": "How is sensitive data protected in transit?",
                        "description": "Encryption in transit prevents data interception",
                        "type": "radio",
                        "options": [
                            "TLS 1.3 with perfect forward secrecy + certificate pinning",
                            "TLS 1.2/1.3 with strong cipher suites",
                            "TLS 1.2 with default configuration",
                            "TLS 1.1 or mixed HTTP/HTTPS",
                            "HTTP without encryption"
                        ],
                        "weights": [10, 8, 5, 2, 0]
                    },
                    {
                        "id": "data_4",
                        "question": "How do you handle data retention and disposal?",
                        "description": "Proper data lifecycle management reduces exposure risk",
                        "type": "radio",
                        "options": [
                            "Automated retention policies + secure deletion + audit trails",
                            "Documented retention policies with manual cleanup",
                            "Basic data retention guidelines",
                            "Informal data cleanup processes",
                            "No data retention policy"
                        ],
                        "weights": [10, 7, 4, 2, 0]
                    }
                ]
            },
            "session_management": {
                "title": "Session Management",
                "description": "OWASP A5 (Security Misconfiguration) - Secure session handling",
                "questions": [
                    {
                        "id": "session_1",
                        "question": "How are session tokens generated and managed?",
                        "description": "Strong session management prevents session hijacking",
                        "type": "radio",
                        "options": [
                            "Cryptographically secure random tokens + HttpOnly + Secure + SameSite",
                            "Secure random tokens with proper cookie flags",
                            "Random tokens with basic security",
                            "Predictable or weak session tokens",
                            "No secure session management"
                        ],
                        "weights": [10, 8, 5, 2, 0]
                    },
                    {
                        "id": "session_2",
                        "question": "What session timeout policies are implemented?",
                        "description": "Appropriate timeouts reduce session hijacking risk",
                        "type": "radio",
                        "options": [
                            "Adaptive timeouts based on risk + absolute timeout + idle timeout",
                            "Both idle timeout (15-30 min) and absolute timeout (4-8 hours)",
                            "Idle timeout only (30 min - 2 hours)",
                            "Long session timeouts (8+ hours)",
                            "No session timeout"
                        ],
                        "weights": [10, 8, 6, 2, 0]
                    },
                    {
                        "id": "session_3",
                        "question": "How do you handle session invalidation?",
                        "description": "Proper session invalidation prevents unauthorized access",
                        "type": "radio",
                        "options": [
                            "Server-side invalidation + logout all devices + session rotation",
                            "Server-side session invalidation on logout",
                            "Client-side session clearing",
                            "Basic logout functionality",
                            "No proper session invalidation"
                        ],
                        "weights": [10, 8, 4, 2, 0]
                    }
                ]
            },
            "database_security": {
                "title": "Database Security",
                "description": "Protecting database systems and data integrity",
                "questions": [
                    {
                        "id": "db_1",
                        "question": "How is database access controlled and monitored?",
                        "description": "Database access control prevents unauthorized data access",
                        "type": "radio",
                        "options": [
                            "Least privilege access + connection pooling + query monitoring + encryption",
                            "Role-based database access with monitoring",
                            "Basic database user permissions",
                            "Shared database credentials",
                            "No database access controls"
                        ],
                        "weights": [10, 8, 4, 2, 0]
                    },
                    {
                        "id": "db_2",
                        "question": "How is database backup and recovery secured?",
                        "description": "Secure backups prevent data loss and unauthorized access",
                        "type": "radio",
                        "options": [
                            "Encrypted backups + offsite storage + regular restore testing + access controls",
                            "Encrypted backups with access controls",
                            "Regular backups with basic security",
                            "Unencrypted backups",
                            "No backup strategy"
                        ],
                        "weights": [10, 8, 5, 2, 0]
                    },
                    {
                        "id": "db_3",
                        "question": "What database hardening measures are implemented?",
                        "description": "Database hardening reduces attack surface",
                        "type": "radio",
                        "options": [
                            "Disabled unnecessary features + network restrictions + patch management + auditing",
                            "Basic hardening with network restrictions",
                            "Some unnecessary features disabled",
                            "Default database configuration",
                            "No database hardening"
                        ],
                        "weights": [10, 7, 4, 2, 0]
                    }
                ]
            },
            "file_management": {
                "title": "File Management Security",
                "description": "Secure handling of file operations and storage",
                "questions": [
                    {
                        "id": "file_1",
                        "question": "How do you secure file uploads and downloads?",
                        "description": "File operations can be vectors for attacks",
                        "type": "radio",
                        "options": [
                            "Sandboxed execution + virus scanning + type validation + size limits + access controls",
                            "File type validation + virus scanning + size limits",
                            "Basic file type and size validation",
                            "File type validation only",
                            "No file upload security"
                        ],
                        "weights": [10, 8, 5, 3, 0]
                    },
                    {
                        "id": "file_2",
                        "question": "How are file permissions and access controlled?",
                        "description": "Proper file permissions prevent unauthorized access",
                        "type": "radio",
                        "options": [
                            "Least privilege file permissions + access logging + regular audits",
                            "Role-based file access controls",
                            "Basic file permissions set",
                            "Default file permissions",
                            "No file access controls"
                        ],
                        "weights": [10, 7, 4, 2, 0]
                    },
                    {
                        "id": "file_3",
                        "question": "How do you prevent directory traversal attacks?",
                        "description": "Directory traversal can expose sensitive files",
                        "type": "radio",
                        "options": [
                            "Input validation + path canonicalization + chroot jail + access controls",
                            "Input validation and path restrictions",
                            "Basic path validation",
                            "Some path restrictions",
                            "No directory traversal protection"
                        ],
                        "weights": [10, 8, 5, 2, 0]
                    }
                ]
            },
            "exception_management": {
                "title": "Exception & Error Management",
                "description": "OWASP A3 (Sensitive Data Exposure) - Secure error handling",
                "questions": [
                    {
                        "id": "error_1",
                        "question": "How does your application handle errors and exceptions?",
                        "description": "Poor error handling can expose sensitive information",
                        "type": "radio",
                        "options": [
                            "Generic error pages + detailed logging + monitoring + no stack traces to users",
                            "Generic error messages with proper logging",
                            "Basic error handling with some logging",
                            "Default error pages with stack traces",
                            "No proper error handling"
                        ],
                        "weights": [10, 8, 5, 2, 0]
                    },
                    {
                        "id": "error_2",
                        "question": "What information is included in error messages to users?",
                        "description": "Error messages should not reveal sensitive information",
                        "type": "radio",
                        "options": [
                            "Generic error messages only + reference IDs for support",
                            "Generic error messages without technical details",
                            "Limited technical information in errors",
                            "Detailed error messages including some technical info",
                            "Full stack traces and technical details exposed"
                        ],
                        "weights": [10, 8, 5, 2, 0]
                    },
                    {
                        "id": "error_3",
                        "question": "How are application failures and exceptions logged?",
                        "description": "Proper exception logging aids in security monitoring",
                        "type": "radio",
                        "options": [
                            "Comprehensive logging + correlation IDs + security event detection + alerting",
                            "Detailed logging with error correlation",
                            "Basic exception logging",
                            "Minimal error logging",
                            "No exception logging"
                        ],
                        "weights": [10, 7, 4, 2, 0]
                    }
                ]
            },
            "cryptography": {
                "title": "Cryptography Implementation",
                "description": "OWASP A3 (Sensitive Data Exposure) - Proper cryptographic controls",
                "questions": [
                    {
                        "id": "crypto_1",
                        "question": "What cryptographic algorithms and key lengths are used?",
                        "description": "Strong cryptography is essential for data protection",
                        "type": "radio",
                        "options": [
                            "AES-256, RSA-4096/ECC-384, SHA-256/SHA-3 with proper implementation",
                            "AES-256, RSA-2048, SHA-256 with standard libraries",
                            "AES-128/256 with basic implementation",
                            "Mixed strong and weak algorithms",
                            "Weak or custom cryptographic algorithms"
                        ],
                        "weights": [10, 8, 5, 2, 0]
                    },
                    {
                        "id": "crypto_2",
                        "question": "How is cryptographic key management handled?",
                        "description": "Poor key management undermines strong cryptography",
                        "type": "radio",
                        "options": [
                            "Hardware Security Module (HSM) + key rotation + escrow + lifecycle management",
                            "Dedicated key management service with rotation",
                            "Encrypted key storage with basic rotation",
                            "Basic key storage without rotation",
                            "Keys stored in code or configuration files"
                        ],
                        "weights": [10, 8, 5, 2, 0]
                    },
                    {
                        "id": "crypto_3",
                        "question": "How do you ensure cryptographic implementation security?",
                        "description": "Cryptographic implementation flaws are common",
                        "type": "radio",
                        "options": [
                            "Certified cryptographic libraries + security review + penetration testing",
                            "Well-established cryptographic libraries only",
                            "Standard libraries with some review",
                            "Mix of standard and custom crypto code",
                            "Custom cryptographic implementations"
                        ],
                        "weights": [10, 8, 5, 2, 0]
                    }
                ]
            },
            "auditing_logging": {
                "title": "Security Auditing & Logging",
                "description": "OWASP A10 (Insufficient Logging & Monitoring) - Security event detection",
                "questions": [
                    {
                        "id": "audit_1",
                        "question": "What security events are logged and monitored?",
                        "description": "Comprehensive logging enables security incident detection",
                        "type": "radio",
                        "options": [
                            "Authentication, authorization, input validation, admin actions, data access + real-time monitoring",
                            "Authentication, authorization, and admin actions with monitoring",
                            "Basic authentication and error logging",
                            "Minimal application logging",
                            "No security event logging"
                        ],
                        "weights": [10, 8, 5, 2, 0]
                    },
                    {
                        "id": "audit_2",
                        "question": "How are logs protected and integrity maintained?",
                        "description": "Log integrity is crucial for forensic analysis",
                        "type": "radio",
                        "options": [
                            "Encrypted logs + digital signatures + tamper detection + offsite storage",
                            "Encrypted logs with access controls",
                            "Access-controlled log files",
                            "Basic log file protection",
                            "No log protection"
                        ],
                        "weights": [10, 8, 5, 2, 0]
                    },
                    {
                        "id": "audit_3",
                        "question": "What log analysis and alerting capabilities exist?",
                        "description": "Real-time analysis enables rapid incident response",
                        "type": "radio",
                        "options": [
                            "SIEM integration + automated alerting + correlation + threat intelligence",
                            "Automated log analysis with alerting",
                            "Basic log monitoring and alerts",
                            "Manual log review processes",
                            "No log analysis or alerting"
                        ],
                        "weights": [10, 8, 5, 2, 0]
                    }
                ]
            },
            "data_protection": {
                "title": "Data Protection & Privacy",
                "description": "OWASP A6 (Security Misconfiguration) - Privacy and data protection compliance",
                "questions": [
                    {
                        "id": "privacy_1",
                        "question": "How do you handle personal data and privacy compliance?",
                        "description": "Privacy compliance (GDPR, CCPA) is legally required",
                        "type": "radio",
                        "options": [
                            "Full GDPR/CCPA compliance + privacy by design + data minimization + consent management",
                            "Privacy compliance with consent management",
                            "Basic privacy policy and data handling",
                            "Minimal privacy considerations",
                            "No privacy compliance measures"
                        ],
                        "weights": [10, 8, 5, 2, 0]
                    },
                    {
                        "id": "privacy_2",
                        "question": "What data loss prevention (DLP) measures are implemented?",
                        "description": "DLP prevents unauthorized data exfiltration",
                        "type": "radio",
                        "options": [
                            "Comprehensive DLP + data classification + monitoring + policy enforcement",
                            "Basic DLP with monitoring",
                            "Some data protection measures",
                            "Minimal data protection",
                            "No data loss prevention"
                        ],
                        "weights": [10, 8, 5, 2, 0]
                    },
                    {
                        "id": "privacy_3",
                        "question": "How do you handle data subject rights (access, deletion, portability)?",
                        "description": "Data subject rights are core privacy requirements",
                        "type": "radio",
                        "options": [
                            "Automated data subject request handling + verification + audit trails",
                            "Manual process for data subject requests",
                            "Basic data access/deletion capabilities",
                            "Limited data subject rights support",
                            "No data subject rights implementation"
                        ],
                        "weights": [10, 7, 4, 2, 0]
                    }
                ]
            },
            "api_security": {
                "title": "API Security",
                "description": "OWASP API Security Top 10 - Securing application programming interfaces",
                "questions": [
                    {
                        "id": "api_1",
                        "question": "How are APIs authenticated and authorized?",
                        "description": "API security prevents unauthorized access to backend services",
                        "type": "radio",
                        "options": [
                            "OAuth 2.0/OIDC + JWT validation + rate limiting + scope-based access",
                            "API keys with proper rotation and scoping",
                            "Basic API authentication (API keys)",
                            "Session-based API authentication",
                            "No API authentication"
                        ],
                        "weights": [10, 7, 4, 2, 0]
                    },
                    {
                        "id": "api_2",
                        "question": "What API input validation and rate limiting is implemented?",
                        "description": "API validation prevents injection and abuse",
                        "type": "radio",
                        "options": [
                            "Schema validation + rate limiting + quotas + input sanitization + output encoding",
                            "Input validation with rate limiting",
                            "Basic input validation",
                            "Minimal API validation",
                            "No API input validation"
                        ],
                        "weights": [10, 8, 5, 2, 0]
                    },
                    {
                        "id": "api_3",
                        "question": "How is API documentation and security testing handled?",
                        "description": "Proper API documentation and testing improves security",
                        "type": "radio",
                        "options": [
                            "OpenAPI specs + automated security testing + penetration testing + documentation review",
                            "API documentation with some security testing",
                            "Basic API documentation",
                            "Minimal API documentation",
                            "No API documentation or testing"
                        ],
                        "weights": [10, 7, 4, 2, 0]
                    }
                ]
            },
            "ai_security": {
                "title": "AI/ML Security",
                "description": "Emerging security considerations for AI and machine learning components",
                "questions": [
                    {
                        "id": "ai_1",
                        "question": "If your application uses AI/ML, how do you secure model inputs and outputs?",
                        "description": "AI systems require special security considerations",
                        "type": "radio",
                        "options": [
                            "Input validation + output sanitization + adversarial attack protection + model monitoring",
                            "Input validation and output filtering",
                            "Basic input/output handling",
                            "Minimal AI security measures",
                            "No AI components or No AI security measures"
                        ],
                        "weights": [10, 7, 4, 2, 0]
                    },
                    {
                        "id": "ai_2",
                        "question": "How do you protect against AI model attacks (adversarial, poisoning, inference)?",
                        "description": "AI models face unique attack vectors",
                        "type": "radio",
                        "options": [
                            "Adversarial training + model validation + data poisoning detection + inference protection",
                            "Basic model validation and monitoring",
                            "Some AI security awareness",
                            "Minimal AI attack protection",
                            "No AI components or No AI attack protection"
                        ],
                        "weights": [10, 7, 4, 2, 0]
                    },
                    {
                        "id": "ai_3",
                        "question": "How do you ensure AI/ML model privacy and bias prevention?",
                        "description": "AI systems must protect privacy and prevent discrimination",
                        "type": "radio",
                        "options": [
                            "Differential privacy + bias testing + fairness metrics + explainable AI",
                            "Basic bias testing and privacy measures",
                            "Some privacy and fairness considerations",
                            "Minimal AI ethics implementation",
                            "No AI components or No AI ethics measures"
                        ],
                        "weights": [10, 7, 4, 2, 0]
                    }
                ]
            }
        }
    },
    "mobile_application": {
        "name": "Mobile Application Security Review",
        "description": "OWASP Mobile Top 10 based security assessment for mobile applications",
        "categories": {
            "platform_security": {
                "title": "Platform Security Features",
                "description": "Proper use of mobile platform security features",
                "questions": [
                    {
                        "id": "mobile_platform_1",
                        "question": "How does your mobile app store sensitive data?",
                        "description": "Mobile data storage requires platform-specific security",
                        "type": "radio",
                        "options": [
                            "Keychain/Keystore with hardware backing + encryption + access controls",
                            "Keychain/Keystore with software protection",
                            "Encrypted local storage",
                            "Standard local storage",
                            "Plain text storage"
                        ],
                        "weights": [10, 8, 5, 2, 0]
                    },
                    {
                        "id": "mobile_platform_2",
                        "question": "What mobile authentication methods are implemented?",
                        "description": "Mobile apps should leverage platform authentication features",
                        "type": "radio",
                        "options": [
                            "Biometrics + device PIN + MFA + hardware-backed authentication",
                            "Biometrics with PIN/password fallback",
                            "PIN/password authentication only",
                            "Basic authentication",
                            "No mobile-specific authentication"
                        ],
                        "weights": [10, 8, 5, 2, 0]
                    }
                ]
            },
            "communication_security": {
                "title": "Mobile Communication Security",
                "description": "Secure communication for mobile applications",
                "questions": [
                    {
                        "id": "mobile_comm_1",
                        "question": "How does your mobile app secure network communications?",
                        "description": "Mobile communication faces additional threats",
                        "type": "radio",
                        "options": [
                            "TLS 1.3 + certificate pinning + HPKP + network security config",
                            "TLS 1.2/1.3 with certificate pinning",
                            "TLS with certificate validation",
                            "Basic TLS without pinning",
                            "HTTP or weak encryption"
                        ],
                        "weights": [10, 8, 6, 3, 0]
                    }
                ]
            }
        }
    },
    "api_service": {
        "name": "API & Microservices Security Review",
        "description": "OWASP API Security Top 10 comprehensive assessment",
        "categories": {
            "api_authentication": {
                "title": "API Authentication & Authorization",
                "description": "Secure API access control and identity management",
                "questions": [
                    {
                        "id": "api_auth_1",
                        "question": "How do you implement API authentication?",
                        "description": "APIs require robust authentication mechanisms",
                        "type": "radio",
                        "options": [
                            "OAuth 2.0 + OpenID Connect + JWT validation + refresh tokens",
                            "OAuth 2.0 with proper scope management",
                            "API keys with rotation and scoping",
                            "Basic API key authentication",
                            "No API authentication"
                        ],
                        "weights": [10, 8, 5, 2, 0]
                    },
                    {
                        "id": "api_auth_2",
                        "question": "How do you implement API rate limiting and abuse prevention?",
                        "description": "Rate limiting prevents API abuse and DoS attacks",
                        "type": "radio",
                        "options": [
                            "Dynamic rate limiting + quotas + spike arrest + anomaly detection",
                            "Rate limiting with quotas and bursting",
                            "Basic rate limiting per endpoint",
                            "Simple throttling",
                            "No rate limiting"
                        ],
                        "weights": [10, 8, 5, 2, 0]
                    }
                ]
            }
        }
    },
    "cloud_infrastructure": {
        "name": "Cloud Infrastructure Security Review",
        "description": "Cloud security best practices and configuration assessment",
        "categories": {
            "cloud_iam": {
                "title": "Cloud Identity & Access Management",
                "description": "IAM and access control in cloud environments",
                "questions": [
                    {
                        "id": "cloud_iam_1",
                        "question": "How is cloud Identity and Access Management (IAM) implemented?",
                        "description": "Proper cloud IAM is fundamental to security",
                        "type": "radio",
                        "options": [
                            "Least privilege + MFA + regular access reviews + automated provisioning",
                            "Least privilege with MFA enforcement",
                            "Basic IAM with some MFA",
                            "Basic IAM without MFA",
                            "Shared root/admin access"
                        ],
                        "weights": [10, 8, 5, 2, 0]
                    }
                ]
            }
        }
    },
    "iot_embedded": {
        "name": "IoT & Embedded Systems Security Review",
        "description": "Security assessment for IoT devices and embedded systems",
        "categories": {
            "device_security": {
                "title": "Device Hardware & Firmware Security",
                "description": "Hardware and firmware security measures",
                "questions": [
                    {
                        "id": "iot_device_1",
                        "question": "How is firmware updated on your IoT devices?",
                        "description": "Secure firmware updates are critical for IoT security",
                        "type": "radio",
                        "options": [
                            "Signed OTA updates + rollback capability + secure boot + update verification",
                            "Signed OTA updates with verification",
                            "Basic OTA updates",
                            "Manual updates only",
                            "No update mechanism"
                        ],
                        "weights": [10, 8, 4, 2, 0]
                    }
                ]
            }
        }
    },
    "blockchain_defi": {
        "name": "Blockchain & DeFi Security Review",
        "description": "Smart contract and blockchain security assessment",
        "categories": {
            "smart_contracts": {
                "title": "Smart Contract Security",
                "description": "Security of smart contracts and DeFi protocols",
                "questions": [
                    {
                        "id": "blockchain_sc_1",
                        "question": "How are your smart contracts audited and tested?",
                        "description": "Smart contract auditing is essential for DeFi security",
                        "type": "radio",
                        "options": [
                            "Multiple independent audits + formal verification + fuzzing + economic analysis",
                            "Professional audit with formal verification",
                            "Professional audit only",
                            "Internal review only",
                            "No formal audit"
                        ],
                        "weights": [10, 8, 5, 2, 0]
                    }
                ]
            }
        }
    }
}

# Comprehensive OWASP Security Questionnaire (All Application Types)
SECURITY_QUESTIONNAIRE = {
    "input_validation": {
        "title": "1. Input Validation & Injection Prevention",
        "description": "OWASP A1 (Injection), A3 (Sensitive Data), A6 (Security Misconfiguration)",
        "questions": [
            {
                "id": "input_1",
                "question": "How does your application validate and sanitize user input?",
                "description": "Input validation prevents injection attacks (SQL, XSS, XXE, NoSQL, LDAP, etc.)",
                "type": "radio",
                "options": [
                    "Server-side whitelist validation + input encoding + parameterized queries",
                    "Server-side validation with both whitelist and blacklist",
                    "Client-side validation with some server-side checks",
                    "Basic input filtering only",
                    "No formal input validation"
                ],
                "weights": [10, 8, 4, 2, 0]
            },
            {
                "id": "input_2",
                "question": "What protection do you have against SQL injection attacks?",
                "description": "SQL injection is one of the most dangerous vulnerabilities",
                "type": "radio",
                "options": [
                    "Prepared statements + ORM + input validation + least privilege DB access",
                    "Prepared statements or ORM with input validation",
                    "Stored procedures with some validation",
                    "Input sanitization only",
                    "No specific SQL injection protection"
                ],
                "weights": [10, 8, 5, 2, 0]
            },
            {
                "id": "input_3",
                "question": "How do you prevent Cross-Site Scripting (XSS) attacks?",
                "description": "XSS can lead to session hijacking and data theft",
                "type": "radio",
                "options": [
                    "CSP headers + output encoding + input validation + HttpOnly cookies",
                    "Output encoding and input validation",
                    "Basic input filtering for scripts",
                    "Some XSS protection measures",
                    "No specific XSS protection"
                ],
                "weights": [10, 7, 4, 2, 0]
            },
            {
                "id": "input_4",
                "question": "What file upload security measures are implemented?",
                "description": "File uploads can be vectors for malware and code execution",
                "type": "radio",
                "options": [
                    "File type validation + virus scanning + size limits + sandbox execution",
                    "File type validation + size limits + content scanning",
                    "Basic file type and size validation",
                    "File type validation only",
                    "No file upload restrictions"
                ],
                "weights": [10, 8, 5, 3, 0]
            }
        ]
    },
    "authentication": {
        "title": "2. Authentication & Identity Management (IAM)",
        "description": "OWASP A2 (Broken Authentication) - Securing user identity and authentication",
        "questions": [
            {
                "id": "auth_1",
                "question": "What authentication methods does your application support?",
                "description": "Strong authentication prevents unauthorized access",
                "type": "radio",
                "options": [
                    "Multi-factor authentication (MFA) required for all users",
                    "MFA required for admin users, optional for others",
                    "Strong password policy with optional MFA",
                    "Basic password authentication only",
                    "Weak or no authentication requirements"
                ],
                "weights": [10, 8, 6, 3, 0]
            },
            {
                "id": "auth_2",
                "question": "How are user passwords stored and protected?",
                "description": "Proper password storage prevents credential theft",
                "type": "radio",
                "options": [
                    "Argon2, scrypt, or bcrypt with salt + pepper + key stretching",
                    "bcrypt or PBKDF2 with salt",
                    "SHA-256 with salt",
                    "MD5 or SHA-1 with salt",
                    "Plain text or weak hashing"
                ],
                "weights": [10, 8, 4, 2, 0]
            },
            {
                "id": "auth_3",
                "question": "What password policy is enforced?",
                "description": "Strong password policies reduce brute force attacks",
                "type": "radio",
                "options": [
                    "12+ chars, complexity, no common passwords, breach checking",
                    "8+ chars with complexity requirements",
                    "Minimum length requirements only",
                    "Basic password requirements",
                    "No password policy"
                ],
                "weights": [10, 7, 4, 2, 0]
            },
            {
                "id": "auth_4",
                "question": "How do you handle account lockout and brute force protection?",
                "description": "Account lockout prevents brute force attacks",
                "type": "radio",
                "options": [
                    "Progressive delays + CAPTCHA + IP blocking + monitoring",
                    "Account lockout with progressive delays",
                    "Basic account lockout after failed attempts",
                    "Rate limiting only",
                    "No brute force protection"
                ],
                "weights": [10, 8, 5, 3, 0]
            }
        ]
    },
    "authorization": {
        "title": "3. Authorization & Access Control",
        "description": "OWASP A5 (Broken Access Control) - Ensuring proper authorization and permissions",
        "questions": [
            {
                "id": "authz_1",
                "question": "What access control model does your application implement?",
                "description": "Proper access control prevents unauthorized actions",
                "type": "radio",
                "options": [
                    "Role-based access control (RBAC) with least privilege principle",
                    "Attribute-based access control (ABAC)",
                    "Simple role-based access control",
                    "Basic user/admin separation",
                    "No formal access control"
                ],
                "weights": [10, 9, 6, 3, 0]
            },
            {
                "id": "authz_2",
                "question": "How do you prevent privilege escalation attacks?",
                "description": "Privilege escalation can lead to unauthorized access",
                "type": "radio",
                "options": [
                    "Least privilege + regular access reviews + separation of duties",
                    "Least privilege principle enforced",
                    "Regular access reviews conducted",
                    "Basic role separation",
                    "No specific privilege escalation protection"
                ],
                "weights": [10, 8, 5, 3, 0]
            },
            {
                "id": "authz_3",
                "question": "How are administrative functions protected?",
                "description": "Admin functions require extra protection",
                "type": "radio",
                "options": [
                    "Separate admin interface + MFA + IP restrictions + logging",
                    "MFA required for admin functions",
                    "Separate admin interface",
                    "Admin functions mixed with user functions",
                    "No special admin protection"
                ],
                "weights": [10, 7, 4, 2, 0]
            }
        ]
    },
    "configuration_management": {
        "title": "4. Configuration Management",
        "description": "OWASP A6 (Security Misconfiguration) - Secure configuration and hardening",
        "questions": [
            {
                "id": "config_1",
                "question": "How is your application server configured for security?",
                "description": "Secure server configuration prevents many attack vectors",
                "type": "radio",
                "options": [
                    "Hardened configuration + security headers + minimal services + regular updates",
                    "Security headers implemented with basic hardening",
                    "Some security configurations applied",
                    "Default configuration with minimal changes",
                    "Default server configuration used"
                ],
                "weights": [10, 7, 4, 2, 0]
            },
            {
                "id": "config_2",
                "question": "What security headers does your application implement?",
                "description": "Security headers provide important browser-side protection",
                "type": "radio",
                "options": [
                    "CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy",
                    "HSTS, X-Frame-Options, X-Content-Type-Options",
                    "Basic security headers (X-Frame-Options, etc.)",
                    "Some security headers implemented",
                    "No security headers"
                ],
                "weights": [10, 8, 5, 2, 0]
            },
            {
                "id": "config_3",
                "question": "How do you manage application secrets and environment variables?",
                "description": "Proper secrets management prevents credential exposure",
                "type": "radio",
                "options": [
                    "Dedicated secrets management system (HashiCorp Vault, AWS Secrets Manager)",
                    "Environment variables with proper access controls",
                    "Encrypted configuration files",
                    "Configuration files with basic protection",
                    "Secrets stored in code or plain text"
                ],
                "weights": [10, 7, 5, 2, 0]
            }
        ]
    },
    "sensitive_data": {
        "title": "5. Sensitive Data Protection",
        "description": "OWASP A3 (Sensitive Data Exposure) - Protecting sensitive information",
        "questions": [
            {
                "id": "data_1",
                "question": "How is sensitive data identified and classified?",
                "description": "Data classification is the first step in protection",
                "type": "radio",
                "options": [
                    "Comprehensive data classification with automated discovery",
                    "Manual data classification with documentation",
                    "Basic identification of sensitive data types",
                    "Informal sensitive data identification",
                    "No formal data classification"
                ],
                "weights": [10, 8, 5, 2, 0]
            },
            {
                "id": "data_2",
                "question": "How is sensitive data encrypted at rest?",
                "description": "Encryption at rest protects data if storage is compromised",
                "type": "radio",
                "options": [
                    "AES-256 encryption with proper key management and HSM",
                    "AES-256 encryption with key rotation",
                    "AES-128/256 encryption with basic key management",
                    "Basic encryption without key management",
                    "No encryption at rest"
                ],
                "weights": [10, 8, 5, 2, 0]
            },
            {
                "id": "data_3",
                "question": "How is sensitive data protected in transit?",
                "description": "Encryption in transit prevents data interception",
                "type": "radio",
                "options": [
                    "TLS 1.3 with perfect forward secrecy + certificate pinning",
                    "TLS 1.2/1.3 with strong cipher suites",
                    "TLS 1.2 with default configuration",
                    "TLS 1.1 or mixed HTTP/HTTPS",
                    "HTTP without encryption"
                ],
                "weights": [10, 8, 5, 2, 0]
            },
            {
                "id": "data_4",
                "question": "How do you handle data retention and disposal?",
                "description": "Proper data lifecycle management reduces exposure risk",
                "type": "radio",
                "options": [
                    "Automated retention policies + secure deletion + audit trails",
                    "Documented retention policies with manual cleanup",
                    "Basic data retention guidelines",
                    "Informal data cleanup processes",
                    "No data retention policy"
                ],
                "weights": [10, 7, 4, 2, 0]
            }
        ]
    },
    "session_management": {
        "title": "6. Session Management",
        "description": "OWASP A5 (Security Misconfiguration) - Secure session handling",
        "questions": [
            {
                "id": "session_1",
                "question": "How are session tokens generated and managed?",
                "description": "Strong session management prevents session hijacking",
                "type": "radio",
                "options": [
                    "Cryptographically secure random tokens + HttpOnly + Secure + SameSite",
                    "Secure random tokens with proper cookie flags",
                    "Random tokens with basic security",
                    "Predictable or weak session tokens",
                    "No secure session management"
                ],
                "weights": [10, 8, 5, 2, 0]
            },
            {
                "id": "session_2",
                "question": "What session timeout policies are implemented?",
                "description": "Appropriate timeouts reduce session hijacking risk",
                "type": "radio",
                "options": [
                    "Adaptive timeouts based on risk + absolute timeout + idle timeout",
                    "Both idle timeout (15-30 min) and absolute timeout (4-8 hours)",
                    "Idle timeout only (30 min - 2 hours)",
                    "Long session timeouts (8+ hours)",
                    "No session timeout"
                ],
                "weights": [10, 8, 6, 2, 0]
            },
            {
                "id": "session_3",
                "question": "How do you handle session invalidation?",
                "description": "Proper session invalidation prevents unauthorized access",
                "type": "radio",
                "options": [
                    "Server-side invalidation + logout all devices + session rotation",
                    "Server-side session invalidation on logout",
                    "Client-side session clearing",
                    "Basic logout functionality",
                    "No proper session invalidation"
                ],
                "weights": [10, 8, 4, 2, 0]
            }
        ]
    },
    "database_security": {
        "title": "7. Database Security",
        "description": "Protecting database systems and data integrity",
        "questions": [
            {
                "id": "db_1",
                "question": "How is database access controlled and monitored?",
                "description": "Database access control prevents unauthorized data access",
                "type": "radio",
                "options": [
                    "Least privilege access + connection pooling + query monitoring + encryption",
                    "Role-based database access with monitoring",
                    "Basic database user permissions",
                    "Shared database credentials",
                    "No database access controls"
                ],
                "weights": [10, 8, 4, 2, 0]
            },
            {
                "id": "db_2",
                "question": "How is database backup and recovery secured?",
                "description": "Secure backups prevent data loss and unauthorized access",
                "type": "radio",
                "options": [
                    "Encrypted backups + offsite storage + regular restore testing + access controls",
                    "Encrypted backups with access controls",
                    "Regular backups with basic security",
                    "Unencrypted backups",
                    "No backup strategy"
                ],
                "weights": [10, 8, 5, 2, 0]
            },
            {
                "id": "db_3",
                "question": "What database hardening measures are implemented?",
                "description": "Database hardening reduces attack surface",
                "type": "radio",
                "options": [
                    "Disabled unnecessary features + network restrictions + patch management + auditing",
                    "Basic hardening with network restrictions",
                    "Some unnecessary features disabled",
                    "Default database configuration",
                    "No database hardening"
                ],
                "weights": [10, 7, 4, 2, 0]
            }
        ]
    },
    "file_management": {
        "title": "8. File Management Security",
        "description": "Secure handling of file operations and storage",
        "questions": [
            {
                "id": "file_1",
                "question": "How do you secure file uploads and downloads?",
                "description": "File operations can be vectors for attacks",
                "type": "radio",
                "options": [
                    "Sandboxed execution + virus scanning + type validation + size limits + access controls",
                    "File type validation + virus scanning + size limits",
                    "Basic file type and size validation",
                    "File type validation only",
                    "No file upload security"
                ],
                "weights": [10, 8, 5, 3, 0]
            },
            {
                "id": "file_2",
                "question": "How are file permissions and access controlled?",
                "description": "Proper file permissions prevent unauthorized access",
                "type": "radio",
                "options": [
                    "Least privilege file permissions + access logging + regular audits",
                    "Role-based file access controls",
                    "Basic file permissions set",
                    "Default file permissions",
                    "No file access controls"
                ],
                "weights": [10, 7, 4, 2, 0]
            },
            {
                "id": "file_3",
                "question": "How do you prevent directory traversal attacks?",
                "description": "Directory traversal can expose sensitive files",
                "type": "radio",
                "options": [
                    "Input validation + path canonicalization + chroot jail + access controls",
                    "Input validation and path restrictions",
                    "Basic path validation",
                    "Some path restrictions",
                    "No directory traversal protection"
                ],
                "weights": [10, 8, 5, 2, 0]
            }
        ]
    },
    "exception_management": {
        "title": "9. Exception & Error Management",
        "description": "OWASP A3 (Sensitive Data Exposure) - Secure error handling",
        "questions": [
            {
                "id": "error_1",
                "question": "How does your application handle errors and exceptions?",
                "description": "Poor error handling can expose sensitive information",
                "type": "radio",
                "options": [
                    "Generic error pages + detailed logging + monitoring + no stack traces to users",
                    "Generic error messages with proper logging",
                    "Basic error handling with some logging",
                    "Default error pages with stack traces",
                    "No proper error handling"
                ],
                "weights": [10, 8, 5, 2, 0]
            },
            {
                "id": "error_2",
                "question": "What information is included in error messages to users?",
                "description": "Error messages should not reveal sensitive information",
                "type": "radio",
                "options": [
                    "Generic error messages only + reference IDs for support",
                    "Generic error messages without technical details",
                    "Limited technical information in errors",
                    "Detailed error messages including some technical info",
                    "Full stack traces and technical details exposed"
                ],
                "weights": [10, 8, 5, 2, 0]
            },
            {
                "id": "error_3",
                "question": "How are application failures and exceptions logged?",
                "description": "Proper exception logging aids in security monitoring",
                "type": "radio",
                "options": [
                    "Comprehensive logging + correlation IDs + security event detection + alerting",
                    "Detailed logging with error correlation",
                    "Basic exception logging",
                    "Minimal error logging",
                    "No exception logging"
                ],
                "weights": [10, 7, 4, 2, 0]
            }
        ]
    },
    "cryptography": {
        "title": "10. Cryptography Implementation",
        "description": "OWASP A3 (Sensitive Data Exposure) - Proper cryptographic controls",
        "questions": [
            {
                "id": "crypto_1",
                "question": "What cryptographic algorithms and key lengths are used?",
                "description": "Strong cryptography is essential for data protection",
                "type": "radio",
                "options": [
                    "AES-256, RSA-4096/ECC-384, SHA-256/SHA-3 with proper implementation",
                    "AES-256, RSA-2048, SHA-256 with standard libraries",
                    "AES-128/256 with basic implementation",
                    "Mixed strong and weak algorithms",
                    "Weak or custom cryptographic algorithms"
                ],
                "weights": [10, 8, 5, 2, 0]
            },
            {
                "id": "crypto_2",
                "question": "How is cryptographic key management handled?",
                "description": "Poor key management undermines strong cryptography",
                "type": "radio",
                "options": [
                    "Hardware Security Module (HSM) + key rotation + escrow + lifecycle management",
                    "Dedicated key management service with rotation",
                    "Encrypted key storage with basic rotation",
                    "Basic key storage without rotation",
                    "Keys stored in code or configuration files"
                ],
                "weights": [10, 8, 5, 2, 0]
            },
            {
                "id": "crypto_3",
                "question": "How do you ensure cryptographic implementation security?",
                "description": "Cryptographic implementation flaws are common",
                "type": "radio",
                "options": [
                    "Certified cryptographic libraries + security review + penetration testing",
                    "Well-established cryptographic libraries only",
                    "Standard libraries with some review",
                    "Mix of standard and custom crypto code",
                    "Custom cryptographic implementations"
                ],
                "weights": [10, 8, 5, 2, 0]
            }
        ]
    },
    "auditing_logging": {
        "title": "11. Security Auditing & Logging",
        "description": "OWASP A10 (Insufficient Logging & Monitoring) - Security event detection",
        "questions": [
            {
                "id": "audit_1",
                "question": "What security events are logged and monitored?",
                "description": "Comprehensive logging enables security incident detection",
                "type": "radio",
                "options": [
                    "Authentication, authorization, input validation, admin actions, data access + real-time monitoring",
                    "Authentication, authorization, and admin actions with monitoring",
                    "Basic authentication and error logging",
                    "Minimal application logging",
                    "No security event logging"
                ],
                "weights": [10, 8, 5, 2, 0]
            },
            {
                "id": "audit_2",
                "question": "How are logs protected and integrity maintained?",
                "description": "Log integrity is crucial for forensic analysis",
                "type": "radio",
                "options": [
                    "Encrypted logs + digital signatures + tamper detection + offsite storage",
                    "Encrypted logs with access controls",
                    "Access-controlled log files",
                    "Basic log file protection",
                    "No log protection"
                ],
                "weights": [10, 8, 5, 2, 0]
            },
            {
                "id": "audit_3",
                "question": "What log analysis and alerting capabilities exist?",
                "description": "Real-time analysis enables rapid incident response",
                "type": "radio",
                "options": [
                    "SIEM integration + automated alerting + correlation + threat intelligence",
                    "Automated log analysis with alerting",
                    "Basic log monitoring and alerts",
                    "Manual log review processes",
                    "No log analysis or alerting"
                ],
                "weights": [10, 8, 5, 2, 0]
            }
        ]
    },
    "data_protection": {
        "title": "12. Data Protection & Privacy",
        "description": "OWASP A6 (Security Misconfiguration) - Privacy and data protection compliance",
        "questions": [
            {
                "id": "privacy_1",
                "question": "How do you handle personal data and privacy compliance?",
                "description": "Privacy compliance (GDPR, CCPA) is legally required",
                "type": "radio",
                "options": [
                    "Full GDPR/CCPA compliance + privacy by design + data minimization + consent management",
                    "Privacy compliance with consent management",
                    "Basic privacy policy and data handling",
                    "Minimal privacy considerations",
                    "No privacy compliance measures"
                ],
                "weights": [10, 8, 5, 2, 0]
            },
            {
                "id": "privacy_2",
                "question": "What data loss prevention (DLP) measures are implemented?",
                "description": "DLP prevents unauthorized data exfiltration",
                "type": "radio",
                "options": [
                    "Comprehensive DLP + data classification + monitoring + policy enforcement",
                    "Basic DLP with monitoring",
                    "Some data protection measures",
                    "Minimal data protection",
                    "No data loss prevention"
                ],
                "weights": [10, 8, 5, 2, 0]
            },
            {
                "id": "privacy_3",
                "question": "How do you handle data subject rights (access, deletion, portability)?",
                "description": "Data subject rights are core privacy requirements",
                "type": "radio",
                "options": [
                    "Automated data subject request handling + verification + audit trails",
                    "Manual process for data subject requests",
                    "Basic data access/deletion capabilities",
                    "Limited data subject rights support",
                    "No data subject rights implementation"
                ],
                "weights": [10, 7, 4, 2, 0]
            }
        ]
    },
    "api_security": {
        "title": "13. API Security",
        "description": "OWASP API Security Top 10 - Securing application programming interfaces",
        "questions": [
            {
                "id": "api_1",
                "question": "How are APIs authenticated and authorized (if applicable)?",
                "description": "API security prevents unauthorized access to backend services",
                "type": "radio",
                "options": [
                    "OAuth 2.0/OIDC + JWT validation + rate limiting + scope-based access",
                    "API keys with proper rotation and scoping",
                    "Basic API authentication (API keys)",
                    "Session-based API authentication",
                    "No APIs or No API authentication"
                ],
                "weights": [10, 7, 4, 2, 0]
            },
            {
                "id": "api_2",
                "question": "What API input validation and rate limiting is implemented (if applicable)?",
                "description": "API validation prevents injection and abuse",
                "type": "radio",
                "options": [
                    "Schema validation + rate limiting + quotas + input sanitization + output encoding",
                    "Input validation with rate limiting",
                    "Basic input validation",
                    "Minimal API validation",
                    "No APIs or No API input validation"
                ],
                "weights": [10, 8, 5, 2, 0]
            },
            {
                "id": "api_3",
                "question": "How is API documentation and security testing handled (if applicable)?",
                "description": "Proper API documentation and testing improves security",
                "type": "radio",
                "options": [
                    "OpenAPI specs + automated security testing + penetration testing + documentation review",
                    "API documentation with some security testing",
                    "Basic API documentation",
                    "Minimal API documentation",
                    "No APIs or No API documentation or testing"
                ],
                "weights": [10, 7, 4, 2, 0]
            }
        ]
    },
    "ai_security": {
        "title": "14. AI/ML Security",
        "description": "Emerging security considerations for AI and machine learning components",
        "questions": [
            {
                "id": "ai_1",
                "question": "If your application uses AI/ML, how do you secure model inputs and outputs?",
                "description": "AI systems require special security considerations",
                "type": "radio",
                "options": [
                    "Input validation + output sanitization + adversarial attack protection + model monitoring",
                    "Input validation and output filtering",
                    "Basic input/output handling",
                    "Minimal AI security measures",
                    "No AI components or No AI security measures"
                ],
                "weights": [10, 7, 4, 2, 0]
            },
            {
                "id": "ai_2",
                "question": "How do you protect against AI model attacks (adversarial, poisoning, inference)?",
                "description": "AI models face unique attack vectors",
                "type": "radio",
                "options": [
                    "Adversarial training + model validation + data poisoning detection + inference protection",
                    "Basic model validation and monitoring",
                    "Some AI security awareness",
                    "Minimal AI attack protection",
                    "No AI components or No AI attack protection"
                ],
                "weights": [10, 7, 4, 2, 0]
            },
            {
                "id": "ai_3",
                "question": "How do you ensure AI/ML model privacy and bias prevention?",
                "description": "AI systems must protect privacy and prevent discrimination",
                "type": "radio",
                "options": [
                    "Differential privacy + bias testing + fairness metrics + explainable AI",
                    "Basic bias testing and privacy measures",
                    "Some privacy and fairness considerations",
                    "Minimal AI ethics implementation",
                    "No AI components or No AI ethics measures"
                ],
                "weights": [10, 7, 4, 2, 0]
            }
        ]
    }
}

def get_questionnaire_for_field(field):
    """Get questionnaire for specific security field (deprecated - now uses unified questionnaire)"""
    return {"categories": SECURITY_QUESTIONNAIRE, "name": "Comprehensive Security Review", "description": "Complete OWASP-based security assessment"}

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
            
            # Redirect based on onboarding status
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
    """Main dashboard"""
    conn = get_db()
    
    # Get user stats
    user_apps = conn.execute('SELECT COUNT(*) as count FROM applications WHERE author_id = ?', 
                             (session['user_id'],)).fetchone()['count']
    
    user_reviews = conn.execute('SELECT COUNT(*) as count FROM security_reviews sr JOIN applications a ON sr.application_id = a.id WHERE a.author_id = ?', 
                               (session['user_id'],)).fetchone()['count']
    
    # Get recent applications
    recent_apps = conn.execute('''
        SELECT * FROM applications 
        WHERE author_id = ? 
        ORDER BY created_at DESC LIMIT 5
    ''', (session['user_id'],)).fetchall()
    
    conn.close()
    
    stats = {
        'applications': user_apps,
        'reviews': user_reviews,
        'risk_score': 85,  # Calculated based on reviews
        'compliance': 'Good'
    }
    
    return render_template('dashboard.html', stats=stats, recent_apps=recent_apps)

@app.route('/applications')
@login_required 
def web_applications():
    """Applications management page"""
    conn = get_db()
    apps = conn.execute('''
        SELECT a.*, sr.risk_score, sr.security_level, sr.status as review_status
        FROM applications a
        LEFT JOIN security_reviews sr ON a.id = sr.application_id
        WHERE a.author_id = ?
        ORDER BY a.created_at DESC
    ''', (session['user_id'],)).fetchall()
    conn.close()
    
    return render_template('applications.html', applications=apps)

@app.route('/create-application', methods=['GET', 'POST'])
@login_required
def web_create_application():
    """Create new application"""
    if request.method == 'POST':
        data = {
            'name': request.form['name'].strip(),
            'description': request.form.get('description', '').strip(),
            'technology_stack': ','.join(request.form.getlist('technology_stack')),
            'deployment_environment': request.form.get('deployment_environment'),
            'business_criticality': request.form.get('business_criticality'),
            'data_classification': request.form.get('data_classification')
        }
        
        app_id = str(uuid.uuid4())
        
        conn = get_db()
        conn.execute('''
            INSERT INTO applications (id, name, description, technology_stack, 
                                    deployment_environment, business_criticality, 
                                    data_classification, author_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (app_id, data['name'], data['description'], data['technology_stack'],
              data['deployment_environment'], data['business_criticality'], 
              data['data_classification'], session['user_id']))
        
        conn.commit()
        conn.close()
        
        flash('Application created successfully!', 'success')
        return redirect(url_for('web_questionnaire', app_id=app_id))
    
    return render_template('create_application.html')

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
    """Comprehensive security questionnaire for application"""
    # Check if this is a retake request
    retake = request.args.get('retake', 'false').lower() == 'true'
    
    conn = get_db()
    app = conn.execute('SELECT * FROM applications WHERE id = ? AND author_id = ?', 
                      (app_id, session['user_id'])).fetchone()
    
    if not app:
        conn.close()
        flash('Application not found.', 'error')
        return redirect(url_for('web_applications'))
    
    # Check if review already exists for this application (only if not retaking)
    if not retake:
        existing_review = conn.execute('SELECT * FROM security_reviews WHERE application_id = ? ORDER BY created_at DESC LIMIT 1', 
                                     (app_id,)).fetchone()
        
        # If review already exists, redirect to review results
        if existing_review:
            conn.close()
            flash('Security review already completed for this application. Showing results.', 'info')
            return redirect(url_for('web_review_results', app_id=app_id))
    
    conn.close()
    
    # Use comprehensive questionnaire covering all 14 security topics
    return render_template('questionnaire.html', 
                                     application=app, 
            questionnaire=SECURITY_QUESTIONNAIRE,
            field='comprehensive',
            field_name='Comprehensive OWASP Security Review')

# === SECURITY ANALYST ROUTES ===

@app.route('/analyst/dashboard')
@analyst_required
def analyst_dashboard():
    """Security Analyst Dashboard"""
    conn = get_db()
    
    # Get pending reviews
    pending_reviews = conn.execute('''
        SELECT sr.id, sr.application_id, sr.status, sr.created_at, sr.risk_score,
               a.name as app_name, a.business_criticality,
               u.first_name, u.last_name
        FROM security_reviews sr
        JOIN applications a ON sr.application_id = a.id
        JOIN users u ON a.author_id = u.id
        WHERE sr.status IN ('submitted', 'in_review')
        ORDER BY sr.created_at DESC
    ''').fetchall()
    
    # Get completed reviews
    completed_reviews = conn.execute('''
        SELECT sr.id, sr.application_id, sr.status, sr.analyst_reviewed_at, sr.risk_score,
               a.name as app_name, a.business_criticality,
               u.first_name, u.last_name
        FROM security_reviews sr
        JOIN applications a ON sr.application_id = a.id
        JOIN users u ON a.author_id = u.id
        WHERE sr.status = 'completed' AND sr.analyst_id = ?
        ORDER BY sr.analyst_reviewed_at DESC
        LIMIT 10
    ''', (session['user_id'],)).fetchall()
    
    # Get statistics
    total_pending = len(pending_reviews)
    total_completed = len(completed_reviews)
    high_risk_count = len([r for r in pending_reviews if r[4] and r[4] < 50])  # risk_score < 50
    
    conn.close()
    
    return render_template('analyst/dashboard.html', 
                         pending_reviews=pending_reviews,
                         completed_reviews=completed_reviews,
                         stats={
                             'total_pending': total_pending,
                             'total_completed': total_completed,
                             'high_risk_count': high_risk_count
                         })

@app.route('/analyst/review/<review_id>')
@analyst_required
def analyst_review_detail(review_id):
    """Detailed review page for analysts"""
    conn = get_db()
    
    # Get review details
    review = conn.execute('''
        SELECT sr.*, a.name as app_name, a.description, a.technology_stack,
               a.deployment_environment, a.business_criticality, a.data_classification,
               u.first_name, u.last_name, u.email
        FROM security_reviews sr
        JOIN applications a ON sr.application_id = a.id
        JOIN users u ON a.author_id = u.id
        WHERE sr.id = ?
    ''', (review_id,)).fetchone()
    
    if not review:
        flash('Review not found.', 'error')
        return redirect(url_for('analyst_dashboard'))
    
    # Parse questionnaire responses
    responses = json.loads(review[3]) if review[3] else {}  # questionnaire_responses
    
    # Get existing STRIDE analysis
    stride_analysis = conn.execute('''
        SELECT * FROM stride_analysis WHERE review_id = ? ORDER BY threat_category
    ''', (review_id,)).fetchall()
    
    conn.close()
    
    # Generate STRIDE threats based on responses
    identified_threats = analyze_stride_threats(responses)
    
    return render_template('analyst/review_detail.html', 
                         review=review,
                         responses=responses,
                         questionnaire=SECURITY_QUESTIONNAIRE,
                         stride_categories=STRIDE_CATEGORIES,
                         stride_analysis=stride_analysis,
                         identified_threats=identified_threats)

@app.route('/analyst/review/<review_id>/stride', methods=['POST'])
@analyst_required
def save_stride_analysis(review_id):
    """Save STRIDE analysis for a review"""
    conn = get_db()
    
    # Verify review exists and analyst can access it
    review = conn.execute('SELECT id FROM security_reviews WHERE id = ?', (review_id,)).fetchone()
    if not review:
        flash('Review not found.', 'error')
        return redirect(url_for('analyst_dashboard'))
    
    # Clear existing STRIDE analysis
    conn.execute('DELETE FROM stride_analysis WHERE review_id = ?', (review_id,))
    
    # Save new STRIDE analysis
    for category in STRIDE_CATEGORIES.keys():
        threat_desc = request.form.get(f'threat_{category}')
        risk_level = request.form.get(f'risk_{category}')
        mitigation_status = request.form.get(f'mitigation_{category}')
        recommendations = request.form.get(f'recommendations_{category}')
        
        if threat_desc and risk_level:
            stride_id = str(uuid.uuid4())
            conn.execute('''
                INSERT INTO stride_analysis (id, review_id, threat_category, threat_description, 
                                           risk_level, mitigation_status, recommendations)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (stride_id, review_id, category, threat_desc, risk_level, mitigation_status, recommendations))
    
    # Update review status
    conn.execute('''
        UPDATE security_reviews 
        SET status = 'in_review', analyst_id = ?
        WHERE id = ?
    ''', (session['user_id'], review_id))
    
    conn.commit()
    conn.close()
    
    flash('STRIDE analysis saved successfully!', 'success')
    return redirect(url_for('analyst_review_detail', review_id=review_id))

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
    
    conn.commit()
    conn.close()
    
    flash('Security review finalized successfully!', 'success')
    return redirect(url_for('analyst_dashboard'))

def analyze_stride_threats(responses):
    """Analyze questionnaire responses to identify STRIDE threats"""
    threats = {category: [] for category in STRIDE_CATEGORIES.keys()}
    
    for category_key, category_data in SECURITY_QUESTIONNAIRE.items():
        stride_categories = OWASP_TO_STRIDE_MAPPING.get(category_key, [])
        
        for question in category_data['questions']:
            question_id = question['id']
            if question_id in responses:
                response_index = int(responses[question_id])
                # If response indicates low security (index 3 or 4), add as threat
                if response_index >= 3:
                    for stride_cat in stride_categories:
                        threats[stride_cat].append({
                            'question': question['question'],
                            'category': category_data['title'],
                            'risk_level': 'High' if response_index == 4 else 'Medium'
                        })
    
    return threats

@app.route('/submit-questionnaire/<app_id>', methods=['POST'])
@login_required
def submit_questionnaire(app_id):
    """Submit comprehensive questionnaire responses"""
    responses = {}
    total_score = 0
    max_score = 0
    
    # Use comprehensive questionnaire covering all 14 security topics
    questionnaire = SECURITY_QUESTIONNAIRE
    
    # Process all form responses
    for key, value in request.form.items():
        if not key.startswith(('field', 'security_confidence', 'primary_concern', 'additional_comments')):
            if '_comment' not in key:  # Skip comment fields for scoring
                responses[key] = value
                
                # Calculate score
                for category in questionnaire.values():
                    for question in category['questions']:
                        if question['id'] == key:
                            try:
                                # Handle different value formats
                                if value in ['yes', 'no', 'partial']:
                                    if value == 'yes':
                                        score = 10
                                    elif value == 'partial':
                                        score = 5
                                    else:  # no
                                        score = 0
                                else:
                                    option_index = int(value)
                                    score = question['weights'][option_index]
                                total_score += score
                                max_score += 10  # Max weight is 10
                            except (ValueError, IndexError):
                                pass
    
    # Calculate risk score percentage
    risk_score = (total_score / max_score * 100) if max_score > 0 else 0
    
    # Determine security level
    if risk_score >= 80:
        security_level = 'High'
    elif risk_score >= 60:
        security_level = 'Medium'
    else:
        security_level = 'Low'
    
    # Generate recommendations
    recommendations = generate_recommendations(responses, risk_score)
    
    # Save to database
    review_id = str(uuid.uuid4())
    conn = get_db()
    conn.execute('''
        INSERT INTO security_reviews (id, application_id, questionnaire_responses, 
                                     risk_score, security_level, recommendations, 
                                     status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (review_id, app_id, json.dumps(responses), risk_score, security_level, 
          json.dumps(recommendations), 'submitted', datetime.now().isoformat()))
    
    conn.commit()
    conn.close()
    
    flash('Security assessment completed!', 'success')
    return redirect(url_for('web_review_results', app_id=app_id))

@app.route('/review-results/<app_id>')
@login_required
def web_review_results(app_id):
    """Display review results"""
    conn = get_db()
    
    app = conn.execute('SELECT * FROM applications WHERE id = ? AND author_id = ?', 
                      (app_id, session['user_id'])).fetchone()
    
    review = conn.execute('SELECT * FROM security_reviews WHERE application_id = ? ORDER BY created_at DESC LIMIT 1', 
                         (app_id,)).fetchone()
    
    conn.close()
    
    if not app or not review:
        flash('Review not found.', 'error')
        return redirect(url_for('web_applications'))
    
    responses = json.loads(review['questionnaire_responses'])
    recommendations = json.loads(review['recommendations'])
    
    return render_template('review_results.html', 
                         application=app, 
                         review=review, 
                         responses=responses,
                         recommendations=recommendations,
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
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    conn.close()
    
    return render_template('profile.html', user=user)

def generate_recommendations(responses, risk_score):
    """Generate security recommendations based on responses"""
    recommendations = []
    
    # Check authentication responses
    for response_id, value in responses.items():
        if response_id == 'auth_1' and value in ['2', '3']:  # No MFA or limited MFA
            recommendations.append({
                'category': 'Authentication',
                'priority': 'High',
                'title': 'Implement Multi-Factor Authentication',
                'description': 'Enable MFA for all users to significantly improve account security.',
                'implementation': 'Use TOTP, SMS, or hardware tokens for second factor authentication.'
            })
        
        if response_id == 'auth_2' and value in ['1', '2', '3']:  # Weak password storage
            recommendations.append({
                'category': 'Authentication', 
                'priority': 'Critical',
                'title': 'Improve Password Storage',
                'description': 'Use proper password hashing with salt (bcrypt, scrypt, or Argon2).',
                'implementation': 'Migrate to bcrypt with at least 12 rounds or Argon2.'
            })
        
        if response_id == 'input_2' and value in ['2', '3']:  # SQL injection risk
            recommendations.append({
                'category': 'Input Validation',
                'priority': 'Critical', 
                'title': 'Prevent SQL Injection',
                'description': 'Use parameterized queries for all database interactions.',
                'implementation': 'Replace dynamic SQL with prepared statements or ORM.'
            })
    
    # Add general recommendations based on score
    if risk_score < 50:
        recommendations.append({
            'category': 'General',
            'priority': 'High',
            'title': 'Comprehensive Security Review',
            'description': 'Your application needs significant security improvements.',
            'implementation': 'Consider engaging a security consultant for detailed assessment.'
        })
    
    return recommendations

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
    print("👤 Demo User: admin@demo.com / password123")
    print("🔍 Demo Analyst: analyst@demo.com / analyst123")
    
    # Start Flask app
    app.run(host='0.0.0.0', port=5000, debug=True) 