#!/usr/bin/env python3
"""
SecureArch Portal - Complete Web Application
Enterprise-grade Security Architecture Review Platform with Web Interface
"""

import os
import json
import uuid
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_from_directory
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import jwt
from functools import wraps
from werkzeug.utils import secure_filename

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
            question_id TEXT,
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
                "title": "Input Validation & Injection Prevention",
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
                    }
                ]
            },
            "authentication": {
                "title": "Authentication & Identity Management",
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
                    }
                ]
            },
            "authorization": {
                "title": "Authorization & Access Control",
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
                    }
                ]
            },
            "session_management": {
                "title": "Session Management",
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
                    }
                ]
            },
            "cryptography": {
                "title": "Cryptographic Controls",
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
                    }
                ]
            },
            "error_handling": {
                "title": "Error Handling & Logging",
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
                    }
                ]
            },
            "data_protection": {
                "title": "Data Protection & Privacy",
                "description": "OWASP Top 10 A02 - Protecting sensitive data throughout its lifecycle",
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
                    }
                ]
            },
            "communication_security": {
                "title": "Communication Security",
                "description": "OWASP Top 10 A02 - Securing data transmission and API communications",
                "questions": [
                    {
                        "id": "comm_1",
                        "question": "Is HTTPS/TLS implemented for all data transmission?",
                        "description": "HTTPS/TLS protects data in transit from interception",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "comm_2",
                        "question": "Are certificate validation and pinning implemented?",
                        "description": "Certificate validation prevents man-in-the-middle attacks",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "comm_3",
                        "question": "Is secure communication implemented for API endpoints?",
                        "description": "API security prevents unauthorized access and data exposure",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    }
                ]
            },
            "api_security": {
                "title": "API Security & Integration",
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
                    }
                ]
            },
            "configuration_security": {
                "title": "Security Configuration Management",
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
                    }
                ]
            },
            "vulnerability_management": {
                "title": "Vulnerability Management",
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
                    }
                ]
            },
            "secure_development": {
                "title": "Secure Development Practices",
                "description": "OWASP SAMM - Secure software development lifecycle practices",
                "questions": [
                    {
                        "id": "dev_1",
                        "question": "Are secure coding practices integrated into the development process?",
                        "description": "Secure coding prevents introduction of security vulnerabilities",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "dev_2",
                        "question": "Is security testing integrated into CI/CD pipelines?",
                        "description": "Automated security testing catches vulnerabilities early",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "dev_3",
                        "question": "Are code reviews performed with security focus?",
                        "description": "Security-focused code reviews identify potential vulnerabilities",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    }
                ]
            },
            "incident_response": {
                "title": "Incident Response & Recovery",
                "description": "OWASP Top 10 A09 - Security incident detection and response capabilities",
                "questions": [
                    {
                        "id": "incident_1",
                        "question": "How are security incidents detected, reported, and responded to?",
                        "description": "Incident response minimizes impact of security breaches",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "incident_2",
                        "question": "Are security monitoring and alerting systems implemented?",
                        "description": "Monitoring enables early detection of security threats",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "incident_3",
                        "question": "Is backup and recovery planning implemented for security incidents?",
                        "description": "Recovery planning ensures business continuity after incidents",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    }
                ]
            },
            "business_logic": {
                "title": "Business Logic Security",
                "description": "OWASP Top 10 A04 (Insecure Design) - Securing application business logic",
                "questions": [
                    {
                        "id": "logic_1",
                        "question": "How are business logic flaws identified and prevented?",
                        "description": "Business logic security prevents exploitation of application workflows",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "logic_2",
                        "question": "Are workflow integrity controls implemented?",
                        "description": "Workflow controls prevent manipulation of business processes",
                        "type": "radio",
                        "options": ["yes", "na", "no"]
                    },
                    {
                        "id": "logic_3",
                        "question": "Is transaction integrity validation implemented?",
                        "description": "Transaction validation prevents financial and data manipulation",
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
                        "description": "Service principals enable secure application authentication",
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
    
    # Get findings count (only analyst STRIDE findings)
    analyst_findings_count = conn.execute('''
        SELECT COUNT(*) as count FROM stride_analysis sa 
        JOIN security_reviews sr ON sa.review_id = sr.id 
        JOIN applications a ON sr.application_id = a.id 
        WHERE a.author_id = ?
    ''', (session['user_id'],)).fetchone()['count']
    
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
        'high_risk_findings': analyst_findings_count,
        'compliance': 'Good' if analyst_findings_count == 0 else ('Fair' if analyst_findings_count < 5 else 'Needs Attention')
    }
    
    return render_template('dashboard.html', stats=stats, recent_apps=recent_apps)

@app.route('/applications')
@login_required 
def web_applications():
    """Applications management page"""
    conn = get_db()
    apps = conn.execute('''
        SELECT a.*, 
               sr.security_level, 
               sr.status as review_status
        FROM applications a
        LEFT JOIN (
            SELECT application_id, 
                   security_level, 
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
            'data_classification': request.form.get('data_classification')
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
                                    data_classification, author_id, logical_architecture_file,
                                    physical_architecture_file, overview_document_file)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (app_id, data['name'], data['description'], data['technology_stack'],
              data['deployment_environment'], data['business_criticality'], 
              data['data_classification'], session['user_id'],
              file_paths.get('logical_architecture_file'),
              file_paths.get('physical_architecture_file'),
              file_paths.get('overview_document_file')))
        
        conn.commit()
        conn.close()
        
        flash('Application created successfully!', 'success')
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
    field_type = request.args.get('field', 'comprehensive_application')
    
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
        # Check for completed review first
        completed_review = conn.execute('''
            SELECT * FROM security_reviews 
            WHERE application_id = ? AND status IN ('submitted', 'completed') 
            ORDER BY created_at DESC LIMIT 1
        ''', (app_id,)).fetchone()
        
        # If completed review exists, redirect to results
        if completed_review:
            conn.close()
            # flash('Security review already completed for this application. Showing results.', 'info')  # Removed flash message
            return redirect(url_for('web_review_results', app_id=app_id))
        
        # Check for draft to load existing responses
        draft_review = conn.execute('''
            SELECT questionnaire_responses FROM security_reviews 
            WHERE application_id = ? AND status = 'draft' 
            ORDER BY created_at DESC LIMIT 1
        ''', (app_id,)).fetchone()
        
        if draft_review and draft_review['questionnaire_responses']:
            try:
                draft_data = json.loads(draft_review['questionnaire_responses'])
                existing_responses = draft_data.get('responses', {})
                existing_comments = draft_data.get('comments', {})
                existing_screenshots = draft_data.get('screenshots', {})
                saved_section = draft_data.get('current_section', 0)
            except:
                pass
    
    conn.close()
    
    # Determine questionnaire and field name based on field type
    if field_type in SECURITY_QUESTIONNAIRES:
        # Cloud security questionnaire (AWS, Azure, GCP)
        questionnaire_data = SECURITY_QUESTIONNAIRES[field_type]['categories']
        field_name = SECURITY_QUESTIONNAIRES[field_type]['name']
        review_type = SECURITY_QUESTIONNAIRES[field_type]['review_type']
    else:
        # Application security questionnaire (comprehensive)
        questionnaire_data = SECURITY_QUESTIONNAIRE
        field_name = 'Comprehensive OWASP Security Review'
        review_type = 'application_review'
        field_type = 'comprehensive_application'  # Normalize field type
    
    return render_template('questionnaire.html', 
                         application=app, 
                         questionnaire=questionnaire_data,
                         field=field_type,
                         field_name=field_name,
                         review_type=review_type,
                         existing_responses=existing_responses,
                         existing_comments=existing_comments,
                         existing_screenshots=existing_screenshots,
                         saved_section=saved_section)

# === SECURITY ANALYST ROUTES ===

@app.route('/analyst/dashboard')
@analyst_required
def analyst_dashboard():
    """Security Analyst Dashboard"""
    conn = get_db()
    
    # Get pending reviews (latest per application)
    pending_reviews = conn.execute('''
        SELECT sr.id, sr.application_id, sr.status, sr.created_at, sr.risk_score,
               a.name as app_name, a.business_criticality,
               u.first_name, u.last_name
        FROM security_reviews sr
        JOIN applications a ON sr.application_id = a.id
        JOIN users u ON a.author_id = u.id
        WHERE sr.status IN ('submitted', 'in_review')
        AND sr.id IN (
            SELECT MAX(id) FROM security_reviews 
            WHERE status IN ('submitted', 'in_review') 
            GROUP BY application_id
        )
        ORDER BY sr.created_at DESC
    ''').fetchall()
    
    # Get completed reviews (latest per application)
    completed_reviews = conn.execute('''
        SELECT sr.id, sr.application_id, sr.status, sr.analyst_reviewed_at, sr.risk_score,
               a.name as app_name, a.business_criticality,
               u.first_name, u.last_name
        FROM security_reviews sr
        JOIN applications a ON sr.application_id = a.id
        JOIN users u ON a.author_id = u.id
        WHERE sr.status = 'completed' AND sr.analyst_id = ?
        AND sr.id IN (
            SELECT MAX(id) FROM security_reviews 
            WHERE status = 'completed' AND analyst_id = ?
            GROUP BY application_id
        )
        ORDER BY sr.analyst_reviewed_at DESC
        LIMIT 10
    ''', (session['user_id'], session['user_id'])).fetchall()
    
    # Get statistics
    total_pending = len(pending_reviews)
    total_completed = len(completed_reviews)
    
    # Get severity counts from STRIDE analysis for all reviews
    severity_counts = conn.execute('''
        SELECT risk_level, COUNT(*) as count
        FROM stride_analysis sa
        JOIN security_reviews sr ON sa.review_id = sr.id
        GROUP BY risk_level
    ''').fetchall()
    
    # Initialize counts
    high_risk_count = 0
    medium_risk_count = 0
    low_risk_count = 0
    
    # Parse severity counts
    for severity_count in severity_counts:
        if severity_count['risk_level'] == 'High':
            high_risk_count = severity_count['count']
        elif severity_count['risk_level'] == 'Medium':
            medium_risk_count = severity_count['count']
        elif severity_count['risk_level'] == 'Low':
            low_risk_count = severity_count['count']
    
    conn.close()
    
    return render_template('analyst/dashboard.html', 
                         pending_reviews=pending_reviews,
                         completed_reviews=completed_reviews,
                         stats={
                             'total_pending': total_pending,
                             'total_completed': total_completed,
                             'high_risk_count': high_risk_count,
                             'medium_risk_count': medium_risk_count,
                             'low_risk_count': low_risk_count
                         })

@app.route('/analyst/review/<review_id>')
@analyst_required
def analyst_review_detail(review_id):
    """View detailed review for analysis"""
    conn = get_db()
    
    # Get review with application details
    review = conn.execute('''
        SELECT sr.id, sr.application_id, sr.questionnaire_responses, sr.security_level, 
               sr.recommendations, sr.status, sr.analyst_reviewed_at, sr.created_at,
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
    
    # Generate detailed analysis data - Show ALL questions (answered and unanswered)
    question_analysis = []
    
    for category_key, category in SECURITY_QUESTIONNAIRE.items():
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
                         questionnaire=SECURITY_QUESTIONNAIRE,  # Show ALL questions
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

@app.route('/auto-save-questionnaire/<app_id>', methods=['POST'])
@login_required 
def auto_save_questionnaire(app_id):
    """Auto-save questionnaire responses as draft"""
    try:
        data = request.get_json()
        responses = data.get('responses', {})
        comments = data.get('comments', {})
        screenshots = data.get('screenshots', {})
        
        # Compile draft data
        questionnaire_data = {
            'responses': responses,
            'comments': comments, 
            'screenshots': screenshots,
            'answered_questions': len([r for r in responses.values() if r]),
            'current_section': data.get('current_section', 0),
            'is_draft': True
        }
        
        conn = get_db()
        
        # Check if draft already exists
        existing_draft = conn.execute('''
            SELECT id FROM security_reviews 
            WHERE application_id = ? AND status = 'draft'
        ''', (app_id,)).fetchone()
        
        if existing_draft:
            # Update existing draft
            conn.execute('''
                UPDATE security_reviews 
                SET questionnaire_responses = ?
                WHERE id = ?
            ''', (json.dumps(questionnaire_data), existing_draft[0]))
        else:
            # Create new draft
            draft_id = str(uuid.uuid4())
            conn.execute('''
                INSERT INTO security_reviews (id, application_id, questionnaire_responses, 
                                             status, created_at)
                VALUES (?, ?, ?, ?, ?)
            ''', (draft_id, app_id, json.dumps(questionnaire_data), 'draft', 
                  datetime.now().isoformat()))
        
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Draft saved'})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/submit-questionnaire/<app_id>', methods=['POST'])
@login_required
def submit_questionnaire(app_id):
    """Submit comprehensive questionnaire responses with comments and screenshots"""
    responses = {}
    comments = {}
    screenshots = {}
    
    # Get disabled categories from form
    disabled_categories_str = request.form.get('disabled_categories', '[]')
    try:
        disabled_categories = json.loads(disabled_categories_str)
    except:
        disabled_categories = []
    
    # Count answered questions for completion tracking
    answered_questions = 0
    high_risk_answers = 0
    
    # Use comprehensive questionnaire covering all 14 security topics
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
    
    if high_risk_percentage <= 20:
        security_level = 'High'
    elif high_risk_percentage <= 50:
        security_level = 'Medium'
    else:
        security_level = 'Low'
    
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
    
    # Save to database
    review_id = str(uuid.uuid4())
    conn = get_db()
    
    # Delete any existing draft for this application
    conn.execute('DELETE FROM security_reviews WHERE application_id = ? AND status = "draft"', (app_id,))
    
    conn.execute('''
        INSERT INTO security_reviews (id, application_id, questionnaire_responses, 
                                     security_level, recommendations, 
                                     status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (review_id, app_id, json.dumps(questionnaire_data), security_level, 
          json.dumps(recommendations), 'submitted', datetime.now().isoformat()))
    
    conn.commit()
    conn.close()
    
    flash('Security assessment submitted successfully!', 'success')
    return redirect(url_for('web_review_results', app_id=app_id))

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
    
    # Get the latest submitted review (the one with findings), not draft reviews
    review = conn.execute('''SELECT * FROM security_reviews 
                            WHERE application_id = ? AND status IN ('submitted', 'completed', 'in_review') 
                            ORDER BY created_at DESC LIMIT 1''', 
                         (app_id,)).fetchone()
    
    # If no submitted review found, fall back to latest review
    if not review:
        review = conn.execute('SELECT * FROM security_reviews WHERE application_id = ? ORDER BY created_at DESC LIMIT 1', 
                             (app_id,)).fetchone()
    
    if not app or not review:
        conn.close()
        # Removed flash messages - silent redirect instead
        # if not app:
        #     flash('Application not found or you do not have permission to view it.', 'error')
        # else:
        #     flash('No security review found for this application. Please complete the security questionnaire first.', 'error')
        return redirect(url_for('web_applications'))
    
    # Parse the questionnaire data (now contains responses, comments, screenshots)
    questionnaire_data = json.loads(review['questionnaire_responses'])
    
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
    
    # Handle recommendations (might be None for older records)
    try:
        recommendations = json.loads(review['recommendations']) if review['recommendations'] else []
    except (json.JSONDecodeError, TypeError):
        recommendations = []
    
    # Only show analyst findings - no automatic findings from questionnaire responses
    findings = []
    
    # Get STRIDE findings created by analysts
    stride_findings = conn.execute('''
        SELECT threat_category, threat_description, risk_level, recommendations, question_id, created_at
        FROM stride_analysis 
        WHERE review_id = ?
        ORDER BY created_at DESC
    ''', (review['id'],)).fetchall()
    
    for stride_finding in stride_findings:
        # Get question details if question_id exists
        question_title = "General Security Finding"
        question_category = stride_finding['threat_category'].replace('_', ' ').title()
        
        if stride_finding['question_id']:
            for category_key, category in SECURITY_QUESTIONNAIRE.items():
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