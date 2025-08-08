"""
User Blueprint
Routes and functionality for regular users (role: 'user')
- Application creation and management
- Security assessments
- Profile management
"""

import os
import json
from flask import Blueprint, render_template, request, redirect, url_for, session, flash, jsonify, current_app
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash, generate_password_hash
from app.decorators import login_required, user_required
from app.database import get_db
from app.workflow import workflow_engine
import uuid
from datetime import datetime

user_bp = Blueprint('user', __name__, url_prefix='/user')

def allowed_file(filename, file_type):
    """Check if uploaded file has allowed extension"""
    allowed_extensions = current_app.config['ALLOWED_EXTENSIONS']
    if file_type in allowed_extensions:
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions[file_type]
    return False

def save_uploaded_file(file, file_type):
    """Save uploaded file and return the file path"""
    if file and allowed_file(file.filename, file_type):
        filename = secure_filename(file.filename)
        # Add timestamp to avoid conflicts
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_')
        filename = timestamp + filename
        
        upload_path = os.path.join(current_app.config['UPLOAD_FOLDER'], file_type)
        file_path = os.path.join(upload_path, filename)
        file.save(file_path)
        
        # Return relative path for storage in database
        return os.path.join('uploads', file_type, filename).replace('\\', '/')
    return None

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
    
    return render_template('dashboard.html', 
                         role='user',
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
    
    return render_template('applications.html', applications=user_applications)

@user_bp.route('/applications/create', methods=['GET', 'POST'])
@login_required
@user_required
def create_application():
    """Create new application"""
    if request.method == 'POST':
        # Get form data
        app_id = str(uuid.uuid4())
        name = request.form.get('name')
        description = request.form.get('description')
        technology_stack = request.form.get('technology_stack')
        deployment_environment = request.form.get('deployment_environment')
        business_criticality = request.form.get('business_criticality', 'Medium')
        data_classification = request.form.get('data_classification', 'Internal')
        
        # Handle file uploads
        logical_architecture_file = None
        physical_architecture_file = None
        overview_document_file = None
        
        if 'logical_architecture' in request.files:
            file = request.files['logical_architecture']
            if file.filename:
                logical_architecture_file = save_uploaded_file(file, 'architecture')
        
        if 'physical_architecture' in request.files:
            file = request.files['physical_architecture']
            if file.filename:
                physical_architecture_file = save_uploaded_file(file, 'architecture')
        
        if 'overview_document' in request.files:
            file = request.files['overview_document']
            if file.filename:
                overview_document_file = save_uploaded_file(file, 'document')
        
        conn = get_db()
        conn.execute('''
            INSERT INTO applications (
                id, name, description, technology_stack, deployment_environment,
                business_criticality, data_classification, author_id, status, 
                logical_architecture_file, physical_architecture_file, overview_document_file,
                created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (app_id, name, description, technology_stack, deployment_environment,
              business_criticality, data_classification, session['user_id'], 'draft',
              logical_architecture_file, physical_architecture_file, overview_document_file,
              datetime.now().isoformat()))
        conn.commit()
        conn.close()
        
        flash(f'Application "{name}" created successfully!', 'success')
        return redirect(url_for('user.security_assessment', app_id=app_id))
    
    return render_template('create_application.html')

@user_bp.route('/applications/<app_id>/delete', methods=['DELETE', 'POST'])
@login_required
@user_required
def delete_application(app_id):
    """Delete application"""
    conn = get_db()
    
    # Verify user owns this application
    app = conn.execute('''
        SELECT * FROM applications 
        WHERE id = ? AND author_id = ?
    ''', (app_id, session['user_id'])).fetchone()
    
    if not app:
        flash('Application not found or access denied', 'error')
        return redirect(url_for('user.applications'))
    
    if app['status'] not in ['draft', 'rejected']:
        flash('Cannot delete applications that are submitted or under review', 'error')
        return redirect(url_for('user.applications'))
    
    # Delete related records first
    conn.execute('DELETE FROM security_reviews WHERE application_id = ?', (app_id,))
    conn.execute('DELETE FROM notifications WHERE application_id = ?', (app_id,))
    conn.execute('DELETE FROM applications WHERE id = ?', (app_id,))
    conn.commit()
    conn.close()
    
    flash('Application deleted successfully', 'success')
    return redirect(url_for('user.applications'))

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
    
    return render_template('security_assessment.html', 
                         application=app, 
                         reviews=reviews)

@user_bp.route('/field-selection')
@user_bp.route('/field-selection/<app_id>')
@login_required
@user_required
def field_selection(app_id=None):
    """Field selection for security assessment"""
    if app_id:
        conn = get_db()
        app = conn.execute('''
            SELECT * FROM applications 
            WHERE id = ? AND author_id = ?
        ''', (app_id, session['user_id'])).fetchone()
        conn.close()
        
        if not app:
            flash('Application not found or access denied', 'error')
            return redirect(url_for('user.applications'))
    else:
        app = None
    
    return render_template('field_selection.html', application=app)

@user_bp.route('/questionnaire/<app_id>')
@login_required
@user_required
def questionnaire(app_id):
    """Security questionnaire for application"""
    conn = get_db()
    
    # Verify user owns this application
    app = conn.execute('''
        SELECT * FROM applications 
        WHERE id = ? AND author_id = ?
    ''', (app_id, session['user_id'])).fetchone()
    
    if not app:
        flash('Application not found or access denied', 'error')
        return redirect(url_for('user.applications'))
    
    field_type = request.args.get('field', 'application_review')
    
    # Get existing review for this field
    existing_review = conn.execute('''
        SELECT * FROM security_reviews 
        WHERE application_id = ? AND field_type = ?
    ''', (app_id, field_type)).fetchone()
    
    conn.close()
    
    return render_template('questionnaire.html', 
                         application=app,
                         field_type=field_type,
                         existing_review=existing_review)

@user_bp.route('/auto-save-questionnaire/<app_id>', methods=['POST'])
@login_required
@user_required
def auto_save_questionnaire(app_id):
    """Auto-save questionnaire responses"""
    conn = get_db()
    
    # Verify user owns this application
    app = conn.execute('''
        SELECT * FROM applications 
        WHERE id = ? AND author_id = ?
    ''', (app_id, session['user_id'])).fetchone()
    
    if not app:
        return jsonify({'success': False, 'error': 'Access denied'})
    
    field_type = request.json.get('field_type', 'application_review')
    responses = request.json.get('responses', {})
    additional_comments = request.json.get('additional_comments', '')
    
    # Check if review exists
    existing_review = conn.execute('''
        SELECT id FROM security_reviews 
        WHERE application_id = ? AND field_type = ?
    ''', (app_id, field_type)).fetchone()
    
    if existing_review:
        # Update existing review
        conn.execute('''
            UPDATE security_reviews 
            SET questionnaire_responses = ?, additional_comments = ?
            WHERE id = ?
        ''', (json.dumps(responses), additional_comments, existing_review['id']))
    else:
        # Create new review
        review_id = str(uuid.uuid4())
        conn.execute('''
            INSERT INTO security_reviews (
                id, application_id, field_type, questionnaire_responses, 
                additional_comments, author_id, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (review_id, app_id, field_type, json.dumps(responses), 
              additional_comments, session['user_id'], datetime.now().isoformat()))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@user_bp.route('/submit-questionnaire/<app_id>', methods=['POST'])
@login_required
@user_required
def submit_questionnaire(app_id):
    """Submit questionnaire for review"""
    conn = get_db()
    
    # Verify user owns this application
    app = conn.execute('''
        SELECT * FROM applications 
        WHERE id = ? AND author_id = ?
    ''', (app_id, session['user_id'])).fetchone()
    
    if not app:
        flash('Application not found or access denied', 'error')
        return redirect(url_for('user.applications'))
    
    field_type = request.form.get('field_type', 'application_review')
    responses = request.form.get('responses', '{}')
    additional_comments = request.form.get('additional_comments', '')
    
    # Check if review exists
    existing_review = conn.execute('''
        SELECT id FROM security_reviews 
        WHERE application_id = ? AND field_type = ?
    ''', (app_id, field_type)).fetchone()
    
    if existing_review:
        # Update existing review
        conn.execute('''
            UPDATE security_reviews 
            SET questionnaire_responses = ?, additional_comments = ?, status = 'submitted'
            WHERE id = ?
        ''', (responses, additional_comments, existing_review['id']))
        review_id = existing_review['id']
    else:
        # Create new review
        review_id = str(uuid.uuid4())
        conn.execute('''
            INSERT INTO security_reviews (
                id, application_id, field_type, questionnaire_responses, 
                additional_comments, status, author_id, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (review_id, app_id, field_type, responses, 
              additional_comments, 'submitted', session['user_id'], datetime.now().isoformat()))
    
    # Update application status
    conn.execute('UPDATE applications SET status = ? WHERE id = ?', ('submitted', app_id))
    
    conn.commit()
    conn.close()
    
    flash('Security assessment submitted successfully!', 'success')
    return redirect(url_for('user.review_results', app_id=app_id))

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
    
    return render_template('review_results.html', 
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
    
    return render_template('profile.html', user=user)

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
    
    return render_template('edit_profile.html', user=user)

@user_bp.route('/change-password', methods=['GET', 'POST'])
@login_required
@user_required
def change_password():
    """Change user password"""
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Validation
        if new_password != confirm_password:
            flash('New passwords do not match', 'error')
            return render_template('change_password.html')
        
        if len(new_password) < 8:
            flash('New password must be at least 8 characters long', 'error')
            return render_template('change_password.html')
        
        conn = get_db()
        user = conn.execute('SELECT password_hash FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        
        if not check_password_hash(user['password_hash'], current_password):
            flash('Current password is incorrect', 'error')
            conn.close()
            return render_template('change_password.html')
        
        # Update password
        new_password_hash = generate_password_hash(new_password)
        conn.execute('UPDATE users SET password_hash = ? WHERE id = ?', (new_password_hash, session['user_id']))
        conn.commit()
        conn.close()
        
        flash('Password changed successfully!', 'success')
        return redirect(url_for('user.profile'))
    
    return render_template('change_password.html') 