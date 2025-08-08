#!/usr/bin/env python3
"""
Simple Sample Data Creator for SecureArch Portal
Updates existing applications to have different statuses for dashboard demo
"""

import sqlite3
import uuid
from datetime import datetime, timedelta

def get_db():
    """Get database connection"""
    conn = sqlite3.connect('securearch_portal.db')
    conn.row_factory = sqlite3.Row
    return conn

def update_application_statuses():
    """Update some applications to have different statuses"""
    conn = get_db()
    
    try:
        # Get all applications for the demo user
        demo_user = conn.execute('SELECT id FROM users WHERE email = ?', ('user@demo.com',)).fetchone()
        if not demo_user:
            print("Demo user not found!")
            return
        
        user_id = demo_user['id']
        applications = conn.execute('SELECT id, name FROM applications WHERE author_id = ? ORDER BY created_at', (user_id,)).fetchall()
        
        if not applications:
            print("No applications found!")
            return
        
        print(f"Found {len(applications)} applications. Updating statuses...")
        
        # Update applications to have different statuses
        status_updates = [
            ('completed', 'E-Commerce Web Platform'),
            ('in_review', 'Mobile Banking API'), 
            ('submitted', 'Internal HR Dashboard'),
            ('completed', 'Customer Support Portal'),
            ('draft', 'Data Analytics Platform'),
            ('draft', 'IoT Device Management')
        ]
        
        for status, app_name in status_updates:
            app = next((app for app in applications if app_name in app['name']), None)
            if app:
                conn.execute('UPDATE applications SET status = ? WHERE id = ?', (status, app['id']))
                print(f"✅ Updated '{app['name']}' to status: {status}")
        
        conn.commit()
        print("\n🎉 Application statuses updated successfully!")
        print("📊 Dashboard should now show varied statistics!")
        
    except Exception as e:
        print(f"Error: {e}")
        conn.rollback()
    finally:
        conn.close()

def add_security_reviews():
    """Add security reviews for completed applications"""
    conn = get_db()
    
    try:
        # Get demo analyst
        analyst = conn.execute('SELECT id FROM users WHERE email = ?', ('analyst@demo.com',)).fetchone()
        if not analyst:
            print("Demo analyst not found!")
            return
        
        analyst_id = analyst['id']
        print(f"Found analyst: {analyst_id}")
        
        # Get completed applications
        completed_apps = conn.execute('''
            SELECT * FROM applications WHERE status = 'completed'
        ''').fetchall()
        
        print(f"Found {len(completed_apps)} completed applications.")
        
        for app in completed_apps:
            # Check if review already exists
            existing = conn.execute('SELECT id FROM security_reviews WHERE application_id = ?', (app['id'],)).fetchone()
            if existing:
                print(f"Review already exists for {app['name']}")
                continue
                
            review_id = str(uuid.uuid4())
            created_at = (datetime.now() - timedelta(days=2)).isoformat()
            
            conn.execute('''
                INSERT INTO security_reviews (
                    id, application_id, analyst_id, status, field_type,
                    questionnaire_responses, additional_comments, risk_score,
                    author_id, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                review_id, app['id'], analyst_id, 'completed', 'comprehensive',
                '{"security_assessment": "Comprehensive review completed", "owasp_compliance": "Level 2"}',
                f"Security review completed for {app['name']}. Application meets security requirements with moderate risk score.",
                6.5, analyst_id, created_at
            ))
            
            print(f"✅ Created security review for: {app['name']}")
        
        conn.commit()
        print("\n🎉 Security reviews created successfully!")
        print("🔄 The analyst dashboard should now show completed reviews!")
        
    except Exception as e:
        print(f"Error creating security reviews: {e}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == '__main__':
    update_application_statuses()
    print("\n" + "="*50)
    add_security_reviews() 