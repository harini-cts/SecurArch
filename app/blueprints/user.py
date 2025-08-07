"""
User Blueprint
Routes and functionality for regular users (role: 'user')
- Application creation and management
- Security assessments
- Profile management
"""

from flask import Blueprint, render_template, request, redirect, url_for, session, flash, jsonify
from app.decorators import login_required, user_required
from app.database import get_db
from app.workflow import workflow_engine
import uuid
from datetime import datetime

user_bp = Blueprint('user', __name__, url_prefix='/user')

@user_bp.route('/dashboard')
@login_required
@user_required
def dashboard():
    """User dashboard - overview of applications and activities"""
    conn = get_db()
    
    # Get user's applications
    user_applications = conn.execute('''
        SELECT * FROM applications 
        WHERE author_id = ? 
        ORDER BY created_at DESC
    ''', (session['user_id'],)).fetchall()
    
    # Get application statistics
    app_stats = {
        'total': len(user_applications),
        'draft': len([app for app in user_applications if app['status'] == 'draft']),
        'submitted': len([app for app in user_applications if app['status'] == 'submitted']),
        'in_review': len([app for app in user_applications if app['status'] == 'in_review']),
        'completed': len([app for app in user_applications if app['status'] == 'completed']),
        'rejected': len([app for app in user_applications if app['status'] == 'rejected'])
    }
    
    # Get recent activity
    recent_activity = conn.execute('''
        SELECT a.name, a.status, a.created_at
        FROM applications a
        WHERE a.author_id = ?
        ORDER BY a.created_at DESC
        LIMIT 5
    ''', (session['user_id'],)).fetchall()
    
    conn.close()
    
    return render_template('user/dashboard.html', 
                         applications=user_applications,
                         app_stats=app_stats,
                         recent_activity=recent_activity)

@user_bp.route('/applications')
@login_required
@user_required
def applications():
    """List user's applications"""
    conn = get_db()
    
    user_applications = conn.execute('''
        SELECT a.*, 
               sr.status as review_status,
               sr.created_at as review_created_at
        FROM applications a
        LEFT JOIN security_reviews sr ON a.id = sr.application_id
        WHERE a.author_id = ? 
        ORDER BY a.created_at DESC
    ''', (session['user_id'],)).fetchall()
    
    conn.close()
    
    return render_template('user/applications.html', applications=user_applications)

@user_bp.route('/applications/create', methods=['GET', 'POST'])
@login_required
@user_required
def create_application():
    """Create new application"""
    if request.method == 'POST':
        # Create application logic
        app_id = str(uuid.uuid4())
        name = request.form.get('name')
        description = request.form.get('description')
        technology_stack = request.form.get('technology_stack')
        deployment_environment = request.form.get('deployment_environment')
        business_criticality = request.form.get('business_criticality', 'Medium')
        data_classification = request.form.get('data_classification', 'Internal')
        
        conn = get_db()
        conn.execute('''
            INSERT INTO applications (
                id, name, description, technology_stack, deployment_environment,
                business_criticality, data_classification, author_id, status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (app_id, name, description, technology_stack, deployment_environment,
              business_criticality, data_classification, session['user_id'], 'draft', 
              datetime.now().isoformat()))
        conn.commit()
        conn.close()
        
        flash(f'Application "{name}" created successfully!', 'success')
        return redirect(url_for('user.security_assessment', app_id=app_id))
    
    return render_template('user/create_application.html')

@user_bp.route('/applications/<app_id>/assessment')
@login_required
@user_required
def security_assessment(app_id):
    """Security assessment for application"""
    conn = get_db()
    
    # Verify user owns this application
    app = conn.execute('''
        SELECT * FROM applications 
        WHERE id = ? AND author_id = ?
    ''', (app_id, session['user_id'])).fetchone()
    
    if not app:
        flash('Application not found or access denied', 'error')
        return redirect(url_for('user.applications'))
    
    # Get existing reviews
    reviews = conn.execute('''
        SELECT * FROM security_reviews 
        WHERE application_id = ?
        ORDER BY created_at DESC
    ''', (app_id,)).fetchall()
    
    conn.close()
    
    return render_template('user/security_assessment.html', 
                         application=app, 
                         reviews=reviews)

@user_bp.route('/applications/<app_id>/results')
@login_required
@user_required
def review_results(app_id):
    """View security review results"""
    conn = get_db()
    
    # Verify user owns this application and it's not draft
    app = conn.execute('''
        SELECT * FROM applications 
        WHERE id = ? AND author_id = ?
    ''', (app_id, session['user_id'])).fetchone()
    
    if not app:
        flash('Application not found or access denied', 'error')
        return redirect(url_for('user.applications'))
    
    if app['status'] == 'draft':
        flash('Review results are not available for draft applications. Please submit your application for review first.', 'warning')
        return redirect(url_for('user.security_assessment', app_id=app_id))
    
    # Get reviews and STRIDE analysis
    reviews = conn.execute('''
        SELECT * FROM security_reviews 
        WHERE application_id = ? AND status IN ('submitted', 'completed', 'in_review')
        ORDER BY field_type, created_at DESC
    ''', (app_id,)).fetchall()
    
    stride_analysis = conn.execute('''
        SELECT sa.* FROM stride_analysis sa
        JOIN security_reviews sr ON sa.review_id = sr.id
        WHERE sr.application_id = ?
        ORDER BY sa.threat_category, sa.risk_level DESC
    ''', (app_id,)).fetchall()
    
    conn.close()
    
    if not reviews:
        flash('No review results available yet. Please complete the security assessment first.', 'info')
        return redirect(url_for('user.security_assessment', app_id=app_id))
    
    return render_template('user/review_results.html', 
                         application=app, 
                         reviews=reviews,
                         stride_analysis=stride_analysis)

@user_bp.route('/profile')
@login_required
@user_required
def profile():
    """User profile page"""
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    conn.close()
    
    return render_template('user/profile.html', user=user)

@user_bp.route('/profile/edit', methods=['GET', 'POST'])
@login_required
@user_required
def edit_profile():
    """Edit user profile"""
    if request.method == 'POST':
        # Update profile logic
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        organization_name = request.form.get('organization_name')
        job_title = request.form.get('job_title')
        
        conn = get_db()
        conn.execute('''
            UPDATE users 
            SET first_name = ?, last_name = ?, organization_name = ?, job_title = ?
            WHERE id = ?
        ''', (first_name, last_name, organization_name, job_title, session['user_id']))
        conn.commit()
        conn.close()
        
        # Update session
        session['user_name'] = f"{first_name} {last_name}"
        
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('user.profile'))
    
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    conn.close()
    
    return render_template('user/edit_profile.html', user=user)

@user_bp.route('/change-password', methods=['GET', 'POST'])
@login_required
@user_required
def change_password():
    """Change user password"""
    if request.method == 'POST':
        # Password change logic
        pass
    
    return render_template('user/change_password.html') 