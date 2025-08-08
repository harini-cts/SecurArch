"""
Admin Blueprint
Routes and functionality for administrators (role: 'admin')
- System-wide user management
- Application oversight and management
- Security review management and reassignment
- System monitoring and reporting
"""

from flask import Blueprint, render_template, request, redirect, url_for, session, flash, jsonify
from app.decorators import login_required, admin_required
from app.database import get_db
import uuid
from datetime import datetime

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

@admin_bp.route('/dashboard')
@login_required
@admin_required
def dashboard():
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
    
    return render_template('dashboard.html', 
                         role='admin',
                         stats=stats, 
                         recent_applications=recent_applications)

@admin_bp.route('/users')
@login_required
@admin_required
def users():
    """Admin User Management"""
    conn = get_db()
    
    # Get all users with additional information
    users = conn.execute('''
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
    
    return render_template('admin/users.html', users=users)

@admin_bp.route('/users/<user_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(user_id):
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
            return redirect(url_for('admin.users'))
            
        except Exception as e:
            flash(f'Error updating user: {str(e)}', 'error')
    
    # Get user details
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('admin.users'))
    
    return render_template('admin/edit_user.html', user=user)

@admin_bp.route('/users/<user_id>/toggle-status', methods=['POST'])
@login_required
@admin_required
def toggle_user_status(user_id):
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
    return redirect(url_for('admin.users'))

@admin_bp.route('/applications')
@login_required
@admin_required
def applications():
    """Admin Application Management"""
    conn = get_db()
    
    # Get all applications with user information
    applications = conn.execute('''
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
    
    return render_template('admin/applications.html', applications=applications)

@admin_bp.route('/applications/<app_id>/change-status', methods=['POST'])
@login_required
@admin_required
def change_application_status(app_id):
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
    return redirect(url_for('admin.applications'))

@admin_bp.route('/applications/<app_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_application(app_id):
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
    return redirect(url_for('admin.applications'))

@admin_bp.route('/reviews')
@login_required
@admin_required
def reviews():
    """Admin Security Review Management"""
    conn = get_db()
    
    # Get all security reviews with application and user information
    reviews = conn.execute('''
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
    analysts = conn.execute('''
        SELECT id, first_name, last_name, email 
        FROM users 
        WHERE role IN ('security_analyst', 'admin') AND is_active = 1
        ORDER BY first_name, last_name
    ''').fetchall()
    
    conn.close()
    
    return render_template('admin/reviews.html', reviews=reviews, analysts=analysts)

@admin_bp.route('/reviews/<review_id>/reassign', methods=['POST'])
@login_required
@admin_required
def reassign_review(review_id):
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
    return redirect(url_for('admin.reviews'))

@admin_bp.route('/audit-logs')
@login_required
@admin_required
def audit_logs():
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

@admin_bp.route('/settings')
@login_required
@admin_required
def settings():
    """System configuration settings"""
    return render_template('admin/settings.html')

@admin_bp.route('/reports')
@login_required
@admin_required
def reports():
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