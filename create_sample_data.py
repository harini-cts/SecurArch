#!/usr/bin/env python3
"""
Create Sample Data for SecureArch Portal
Adds sample applications, security reviews, and STRIDE analysis to demonstrate dashboard functionality
"""

import sqlite3
import uuid
from datetime import datetime, timedelta

def get_db():
    """Get database connection"""
    conn = sqlite3.connect('securearch_portal.db')
    conn.row_factory = sqlite3.Row
    return conn

def create_sample_applications():
    """Create sample applications with various statuses"""
    conn = get_db()
    
    # Get the demo user ID
    demo_user = conn.execute('SELECT id FROM users WHERE email = ?', ('user@demo.com',)).fetchone()
    if not demo_user:
        print("Demo user not found! Please run the main app first to create demo users.")
        return
    
    user_id = demo_user['id']
    
    # Sample applications data
    sample_apps = [
        {
            'name': 'E-Commerce Web Platform',
            'description': 'Customer-facing e-commerce platform with payment processing and user management',
            'technology_stack': 'React, Node.js, PostgreSQL, Redis, Docker',
            'deployment_environment': 'Production',
            'business_criticality': 'High',
            'data_classification': 'Confidential',
            'status': 'completed',
            'days_ago': 15
        },
        {
            'name': 'Mobile Banking API',
            'description': 'RESTful API for mobile banking application with transaction processing',
            'technology_stack': 'Java Spring Boot, MySQL, OAuth2, Kubernetes',
            'deployment_environment': 'Production',
            'business_criticality': 'Critical',
            'data_classification': 'Restricted',
            'status': 'in_review',
            'days_ago': 5
        },
        {
            'name': 'Internal HR Dashboard',
            'description': 'Employee management system for HR operations and payroll',
            'technology_stack': 'Angular, .NET Core, SQL Server, Azure',
            'deployment_environment': 'Production',
            'business_criticality': 'Medium',
            'data_classification': 'Internal',
            'status': 'submitted',
            'days_ago': 3
        },
        {
            'name': 'Data Analytics Platform',
            'description': 'Big data processing platform for business intelligence and reporting',
            'technology_stack': 'Python, Apache Spark, Elasticsearch, Kafka',
            'deployment_environment': 'Staging',
            'business_criticality': 'Medium',
            'data_classification': 'Internal',
            'status': 'draft',
            'days_ago': 1
        },
        {
            'name': 'Customer Support Portal',
            'description': 'Ticketing system for customer support with chat integration',
            'technology_stack': 'Vue.js, PHP Laravel, MariaDB, WebSocket',
            'deployment_environment': 'Production',
            'business_criticality': 'Medium',
            'data_classification': 'Internal',
            'status': 'completed',
            'days_ago': 30
        },
        {
            'name': 'IoT Device Management',
            'description': 'Platform for managing IoT sensors and telemetry data collection',
            'technology_stack': 'Python, MQTT, InfluxDB, Grafana, Docker',
            'deployment_environment': 'Cloud',
            'business_criticality': 'High',
            'data_classification': 'Confidential',
            'status': 'draft',
            'days_ago': 0
        }
    ]
    
    print("Creating sample applications...")
    created_apps = []
    
    for app_data in sample_apps:
        # Check if application already exists (by name)
        existing = conn.execute('SELECT id FROM applications WHERE name = ? AND author_id = ?', 
                              (app_data['name'], user_id)).fetchone()
        
        if existing:
            print(f"Application '{app_data['name']}' already exists, skipping...")
            created_apps.append({'id': existing['id'], **app_data})
            continue
        
        app_id = str(uuid.uuid4())
        created_at = (datetime.now() - timedelta(days=app_data['days_ago'])).isoformat()
        
        conn.execute('''
            INSERT INTO applications (
                id, name, description, technology_stack, deployment_environment,
                business_criticality, data_classification, author_id, status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            app_id,
            app_data['name'],
            app_data['description'], 
            app_data['technology_stack'],
            app_data['deployment_environment'],
            app_data['business_criticality'],
            app_data['data_classification'],
            user_id,
            app_data['status'],
            created_at
        ))
        
        created_apps.append({'id': app_id, **app_data})
        print(f"✅ Created: {app_data['name']} (Status: {app_data['status']})")
    
    conn.commit()
    conn.close()
    return created_apps

def create_sample_security_reviews(apps):
    """Create sample security reviews for completed applications"""
    conn = get_db()
    
    try:
        # Get the demo analyst ID
        analyst = conn.execute('SELECT id FROM users WHERE email = ?', ('analyst@demo.com',)).fetchone()
        if not analyst:
            print("Demo analyst not found!")
            return
        
        analyst_id = analyst['id']
        
        print("\nCreating sample security reviews...")
        
        # Create reviews for completed and in_review applications
        review_apps = [app for app in apps if app['status'] in ['completed', 'in_review']]
        
        for app in review_apps:
            # Check if review already exists
            existing = conn.execute('SELECT id FROM security_reviews WHERE application_id = ?', 
                                  (app['id'],)).fetchone()
            
            if existing:
                print(f"Review for '{app['name']}' already exists, skipping...")
                continue
            
            review_id = str(uuid.uuid4())
            review_status = 'completed' if app['status'] == 'completed' else 'in_review'
            created_at = (datetime.now() - timedelta(days=app['days_ago'] - 1)).isoformat()
            
            conn.execute('''
                INSERT INTO security_reviews (
                    id, application_id, analyst_id, status, field_type,
                    questionnaire_responses, additional_comments, risk_score, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                review_id,
                app['id'],
                analyst_id,
                review_status,
                'comprehensive',
                '{"security_assessment": "Completed security assessment", "criticality": "' + app["business_criticality"] + '"}',
                "Security review completed with OWASP ASVS Level 2 compliance check",
                7.5 if app['business_criticality'] == 'Critical' else 6.0 if app['business_criticality'] == 'High' else 4.5,
                created_at
            ))
            
            # Create STRIDE analysis for this review
            create_stride_analysis(conn, review_id, app)
            
            print(f"✅ Created review: {app['name']} (Status: {review_status})")
        
        conn.commit()
        
    except Exception as e:
        print(f"Error creating security reviews: {e}")
        conn.rollback()
    finally:
        conn.close()

def create_stride_analysis(conn, review_id, app):
    """Create sample STRIDE analysis data"""
    
    # Sample STRIDE threats based on application criticality
    threat_data = {
        'High': [
            {'category': 'Spoofing', 'description': 'Authentication bypass vulnerabilities', 'risk': 'High'},
            {'category': 'Tampering', 'description': 'Data integrity issues in API endpoints', 'risk': 'Medium'},
            {'category': 'Information Disclosure', 'description': 'Sensitive data exposure risks', 'risk': 'High'},
        ],
        'Critical': [
            {'category': 'Spoofing', 'description': 'Multi-factor authentication weaknesses', 'risk': 'High'},
            {'category': 'Elevation of Privilege', 'description': 'Privilege escalation vulnerabilities', 'risk': 'High'},
            {'category': 'Denial of Service', 'description': 'Rate limiting and DDoS protection gaps', 'risk': 'Medium'},
        ],
        'Medium': [
            {'category': 'Tampering', 'description': 'Input validation weaknesses', 'risk': 'Medium'},
            {'category': 'Information Disclosure', 'description': 'Logging and monitoring gaps', 'risk': 'Low'},
        ]
    }
    
    threats = threat_data.get(app['business_criticality'], threat_data['Medium'])
    
    for threat in threats:
        stride_id = str(uuid.uuid4())
        conn.execute('''
            INSERT INTO stride_analysis (
                id, review_id, threat_category, threat_description, 
                risk_level, mitigation_status, recommendations, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            stride_id,
            review_id,
            threat['category'],
            threat['description'],
            threat['risk'],
            'identified',
            f"Implement security controls for {threat['category']} threats",
            datetime.now().isoformat()
        ))

def main():
    """Main function to create all sample data"""
    print("🚀 Creating sample data for SecureArch Portal...")
    
    # Create applications
    apps = create_sample_applications()
    
    # Create security reviews and STRIDE analysis
    create_sample_security_reviews(apps)
    
    print("\n🎉 Sample data created successfully!")
    print("📊 Dashboard should now show:")
    print("   • Total Applications: 6")
    print("   • Under Review: 2 (submitted + in_review)")
    print("   • Completed: 2") 
    print("   • Drafts: 2")
    print("   • Security Reviews: Created for completed/in-review apps")
    print("   • STRIDE Analysis: Risk findings for threat modeling")
    print("\n🔄 Refresh your browser to see the updated dashboard!")
    print("👥 Try logging in as different users to see role-specific views:")
    print("   • user@demo.com / password123 (User dashboard)")
    print("   • analyst@demo.com / analyst123 (Analyst dashboard)")
    print("   • superadmin@demo.com / admin123 (Admin dashboard)")

if __name__ == '__main__':
    main() 