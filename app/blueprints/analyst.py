"""
Analyst Blueprint
Routes and functionality for security analysts (role: 'security_analyst')
- Review assigned applications
- Perform STRIDE analysis
- Manage review workload
"""

from flask import Blueprint, render_template, request, redirect, url_for, session, flash, jsonify
from app.decorators import login_required, analyst_required
from app.database import get_db
from app.workflow import workflow_engine
import uuid
from datetime import datetime

analyst_bp = Blueprint('analyst', __name__, url_prefix='/analyst')

@analyst_bp.route('/dashboard')
@login_required
@analyst_required
def dashboard():
    """Analyst dashboard - review workload and statistics"""
    conn = get_db()
    
    # Get applications for analyst review using workflow engine
    todo_applications = workflow_engine.get_analyst_applications(session['user_id'], 'todo')
    in_review_applications = workflow_engine.get_analyst_applications(session['user_id'], 'in_review')
    completed_applications = workflow_engine.get_analyst_applications(session['user_id'], 'completed')
    
    # Get pending reviews with detailed information including technology stack
    pending_reviews = conn.execute('''
        SELECT sr.id as review_id, sr.application_id, sr.status, sr.created_at,
               sr.field_type, a.name as app_name, a.business_criticality,
               a.technology_stack, a.description, a.deployment_model,
               a.data_classification, a.user_base_size,
               u.first_name, u.last_name, u.email
        FROM security_reviews sr
        JOIN applications a ON sr.application_id = a.id
        JOIN users u ON a.author_id = u.id
        WHERE sr.analyst_id = ? AND sr.status IN ('submitted', 'in_review')
        ORDER BY CASE 
            WHEN a.business_criticality = 'critical' THEN 1
            WHEN a.business_criticality = 'high' THEN 2
            WHEN a.business_criticality = 'medium' THEN 3
            ELSE 4
        END, sr.created_at ASC
    ''', (session['user_id'],)).fetchall()
    
    # Get completed reviews with detailed information
    completed_reviews = conn.execute('''
        SELECT sr.id as review_id, sr.application_id, sr.status, sr.created_at,
               sr.completed_at, sr.field_type, a.name as app_name, a.business_criticality,
               a.technology_stack, a.description, a.deployment_model,
               u.first_name, u.last_name, u.email
        FROM security_reviews sr
        JOIN applications a ON sr.application_id = a.id
        JOIN users u ON a.author_id = u.id
        WHERE sr.analyst_id = ? AND sr.status = 'completed'
        ORDER BY sr.completed_at DESC
        LIMIT 10
    ''', (session['user_id'],)).fetchall()
    
    # Get security issue counts from STRIDE analysis
    security_issues = conn.execute('''
        SELECT sa.risk_level, COUNT(*) as count
        FROM stride_analysis sa
        JOIN security_reviews sr ON sa.review_id = sr.id
        WHERE sr.analyst_id = ?
        GROUP BY sa.risk_level
    ''', (session['user_id'],)).fetchall()
    
    # Convert findings to dictionary for easy access
    issues_dict = {row['risk_level']: row['count'] for row in security_issues}
    
    # Get total issues count
    total_issues = conn.execute('''
        SELECT COUNT(*) as count
        FROM stride_analysis sa
        JOIN security_reviews sr ON sa.review_id = sr.id
        WHERE sr.analyst_id = ?
    ''', (session['user_id'],)).fetchone()['count']
    
    # Get in-review applications with details
    in_review_detailed = conn.execute('''
        SELECT sr.id as review_id, sr.application_id, sr.status, sr.created_at,
               sr.field_type, a.name as app_name, a.business_criticality,
               a.technology_stack, a.description,
               u.first_name, u.last_name, u.email
        FROM security_reviews sr
        JOIN applications a ON sr.application_id = a.id
        JOIN users u ON a.author_id = u.id
        WHERE sr.analyst_id = ? AND sr.status = 'in_review'
        ORDER BY sr.created_at ASC
    ''', (session['user_id'],)).fetchall()
    
    # Calculate review status statistics
    review_stats = {
        'pending': len(pending_reviews),
        'in_review': len(in_review_detailed),
        'completed': len(completed_reviews)
    }
    
    # Calculate security issue statistics
    issue_stats = {
        'critical': issues_dict.get('Critical', 0),
        'high': issues_dict.get('High', 0),
        'medium': issues_dict.get('Medium', 0),
        'low': issues_dict.get('Low', 0),
        'total': total_issues
    }
    
    # Overall statistics for backward compatibility
    stats = {
        'todo': review_stats['pending'],
        'in_review': review_stats['in_review'],
        'completed': review_stats['completed'],
        'total_assigned': review_stats['pending'] + review_stats['in_review'] + review_stats['completed'],
        'total_pending': review_stats['pending'],
        'total_completed': review_stats['completed'],
        'high_risk_count': issue_stats['high'],
        'medium_risk_count': issue_stats['medium'],
        'low_risk_count': issue_stats['low'],
        'critical_risk_count': issue_stats['critical'],
        'total_findings': issue_stats['total']
    }
    
    # Get recent activity
    recent_reviews = conn.execute('''
        SELECT sr.*, a.name as app_name, a.business_criticality
        FROM security_reviews sr
        JOIN applications a ON sr.application_id = a.id
        WHERE sr.analyst_id = ?
        ORDER BY sr.created_at DESC
        LIMIT 5
    ''', (session['user_id'],)).fetchall()
    
    conn.close()
    
    return render_template('analyst/dashboard.html',
                         pending_reviews=pending_reviews,
                         in_review_applications=in_review_detailed,
                         completed_reviews=completed_reviews,
                         review_stats=review_stats,
                         issue_stats=issue_stats,
                         stats=stats,
                         recent_reviews=recent_reviews)

@analyst_bp.route('/reviews')
@login_required
@analyst_required
def reviews():
    """List all reviews assigned to analyst"""
    conn = get_db()
    
    # Get all applications and their reviews, grouped by application
    applications_data = conn.execute('''
        SELECT 
            a.id as application_id,
            a.name as application_name, 
            a.description,
            a.technology_stack,
            a.business_criticality,
            a.deployment_model,
            a.data_classification,
            u.first_name, 
            u.last_name, 
            u.email,
            GROUP_CONCAT(sr.field_type, '|') as review_types,
            GROUP_CONCAT(sr.id, '|') as review_ids,
            GROUP_CONCAT(sr.status, '|') as review_statuses,
            GROUP_CONCAT(sr.created_at, '|') as review_dates,
            COUNT(sr.id) as review_count,
            MIN(sr.created_at) as first_review_date
        FROM applications a
        JOIN security_reviews sr ON a.id = sr.application_id
        JOIN users u ON a.author_id = u.id
        WHERE sr.analyst_id = ?
        GROUP BY a.id, a.name, a.description, a.technology_stack, a.business_criticality, 
                 a.deployment_model, a.data_classification, u.first_name, u.last_name, u.email
        ORDER BY MIN(sr.created_at) DESC
    ''', (session['user_id'],)).fetchall()
    
    # Transform data to match template expectations
    applications = []
    for app_data in applications_data:
        review_types = app_data['review_types'].split('|') if app_data['review_types'] else []
        review_ids = app_data['review_ids'].split('|') if app_data['review_ids'] else []
        review_statuses = app_data['review_statuses'].split('|') if app_data['review_statuses'] else []
        review_dates = app_data['review_dates'].split('|') if app_data['review_dates'] else []
        
        reviews = []
        for i in range(len(review_types)):
            reviews.append({
                'id': review_ids[i],
                'field_type': review_types[i],
                'status': review_statuses[i],
                'created_at': review_dates[i]
            })
        
        applications.append({
            'id': app_data['application_id'],
            'name': app_data['application_name'],
            'description': app_data['description'],
            'technology_stack': app_data['technology_stack'],
            'business_criticality': app_data['business_criticality'],
            'deployment_model': app_data['deployment_model'],
            'data_classification': app_data['data_classification'],
            'author_name': f"{app_data['first_name']} {app_data['last_name']}",
            'author_email': app_data['email'],
            'review_count': app_data['review_count'],
            'first_review_date': app_data['first_review_date'],
            'reviews': reviews
        })
    
    conn.close()
    
    return render_template('analyst/reviews.html', applications=applications)

@analyst_bp.route('/reviews/<review_id>')
@login_required
@analyst_required
def review_detail(review_id):
    """Detailed view of a specific review"""
    conn = get_db()
    
    # Get review details
    review = conn.execute('''
        SELECT sr.*, a.*, u.first_name, u.last_name, u.email
        FROM security_reviews sr
        JOIN applications a ON sr.application_id = a.id
        JOIN users u ON a.author_id = u.id
        WHERE sr.id = ? AND sr.analyst_id = ?
    ''', (review_id, session['user_id'])).fetchone()
    
    if not review:
        flash('Review not found or access denied', 'error')
        return redirect(url_for('analyst.reviews'))
    
    # Get existing STRIDE analysis
    stride_analysis = conn.execute('''
        SELECT * FROM stride_analysis 
        WHERE review_id = ?
        ORDER BY threat_category, risk_level DESC
    ''', (review_id,)).fetchall()
    
    conn.close()
    
    return render_template('analyst/review_detail.html', 
                         review=review,
                         stride_analysis=stride_analysis)

@analyst_bp.route('/reviews/<review_id>/stride', methods=['GET', 'POST'])
@login_required
@analyst_required
def stride_analysis(review_id):
    """Perform STRIDE threat analysis"""
    if request.method == 'POST':
        # Process STRIDE analysis submission
        threat_category = request.form.get('threat_category')
        threat_description = request.form.get('threat_description')
        risk_level = request.form.get('risk_level')
        mitigation_strategy = request.form.get('mitigation_strategy')
        
        conn = get_db()
        
        # Verify analyst owns this review
        review = conn.execute('''
            SELECT * FROM security_reviews 
            WHERE id = ? AND analyst_id = ?
        ''', (review_id, session['user_id'])).fetchone()
        
        if not review:
            flash('Review not found or access denied', 'error')
            return redirect(url_for('analyst.reviews'))
        
        # Insert STRIDE analysis
        analysis_id = str(uuid.uuid4())
        conn.execute('''
            INSERT INTO stride_analysis (
                id, review_id, threat_category, threat_description,
                risk_level, mitigation_strategy, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (analysis_id, review_id, threat_category, threat_description,
              risk_level, mitigation_strategy, datetime.now().isoformat()))
        
        conn.commit()
        conn.close()
        
        flash('STRIDE analysis added successfully!', 'success')
        return redirect(url_for('analyst.review_detail', review_id=review_id))
    
    conn = get_db()
    
    # Get review details
    review = conn.execute('''
        SELECT sr.*, a.name as app_name
        FROM security_reviews sr
        JOIN applications a ON sr.application_id = a.id
        WHERE sr.id = ? AND sr.analyst_id = ?
    ''', (review_id, session['user_id'])).fetchone()
    
    if not review:
        flash('Review not found or access denied', 'error')
        return redirect(url_for('analyst.reviews'))
    
    conn.close()
    
    return render_template('analyst/stride_analysis.html', review=review)

@analyst_bp.route('/reviews/<review_id>/complete', methods=['POST'])
@login_required
@analyst_required
def complete_review(review_id):
    """Mark review as completed"""
    conn = get_db()
    
    # Verify analyst owns this review
    review = conn.execute('''
        SELECT * FROM security_reviews 
        WHERE id = ? AND analyst_id = ?
    ''', (review_id, session['user_id'])).fetchone()
    
    if not review:
        flash('Review not found or access denied', 'error')
        return redirect(url_for('analyst.reviews'))
    
    # Update review status using workflow engine
    success, error = workflow_engine.update_application_status(
        review['application_id'], 
        'completed', 
        session.get('user_role', 'security_analyst')
    )
    
    if success:
        # Also update the review status
        conn.execute('''
            UPDATE security_reviews 
            SET status = 'completed' 
            WHERE id = ?
        ''', (review_id,))
        conn.commit()
        flash('Review completed successfully!', 'success')
    else:
        flash(f'Error completing review: {error}', 'error')
    
    conn.close()
    return redirect(url_for('analyst.reviews'))

@analyst_bp.route('/workload')
@login_required
@analyst_required
def workload():
    """Analyst workload overview"""
    conn = get_db()
    
    # Get workload statistics
    workload_stats = conn.execute('''
        SELECT 
            COUNT(*) as total_reviews,
            COUNT(CASE WHEN sr.status = 'submitted' THEN 1 END) as pending_reviews,
            COUNT(CASE WHEN sr.status = 'in_review' THEN 1 END) as active_reviews,
            COUNT(CASE WHEN sr.status = 'completed' THEN 1 END) as completed_reviews
        FROM security_reviews sr
        WHERE sr.analyst_id = ?
    ''', (session['user_id'],)).fetchone()
    
    # Get applications by criticality
    criticality_breakdown = conn.execute('''
        SELECT a.business_criticality, COUNT(*) as count
        FROM security_reviews sr
        JOIN applications a ON sr.application_id = a.id
        WHERE sr.analyst_id = ? AND sr.status IN ('submitted', 'in_review')
        GROUP BY a.business_criticality
    ''', (session['user_id'],)).fetchall()
    
    # Get overdue reviews (older than 7 days)
    overdue_reviews = conn.execute('''
        SELECT sr.*, a.name as app_name, a.business_criticality
        FROM security_reviews sr
        JOIN applications a ON sr.application_id = a.id
        WHERE sr.analyst_id = ? 
        AND sr.status IN ('submitted', 'in_review')
        AND datetime(sr.created_at) < datetime('now', '-7 days')
        ORDER BY sr.created_at ASC
    ''', (session['user_id'],)).fetchall()
    
    conn.close()
    
    return render_template('analyst/workload.html',
                         workload_stats=workload_stats,
                         criticality_breakdown=criticality_breakdown,
                         overdue_reviews=overdue_reviews)

@analyst_bp.route('/profile')
@login_required
@analyst_required
def profile():
    """Analyst profile page"""
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    
    # Get analyst statistics
    analyst_stats = conn.execute('''
        SELECT 
            COUNT(*) as total_reviews,
            COUNT(CASE WHEN sr.status = 'completed' THEN 1 END) as completed_reviews,
            AVG(CASE WHEN sr.status = 'completed' THEN 
                JULIANDAY(datetime('now')) - JULIANDAY(sr.created_at) 
            END) as avg_completion_days
        FROM security_reviews sr
        WHERE sr.analyst_id = ?
    ''', (session['user_id'],)).fetchone()
    
    conn.close()
    
    return render_template('analyst/profile.html', 
                         user=user, 
                         analyst_stats=analyst_stats) 