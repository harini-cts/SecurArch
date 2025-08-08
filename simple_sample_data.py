#!/usr/bin/env python3
"""
Simple Sample Data Creator for SecureArch Portal
Updates existing applications to have different statuses for dashboard demo
"""

import sqlite3

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

if __name__ == '__main__':
    update_application_statuses() 