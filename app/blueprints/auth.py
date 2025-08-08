"""
Authentication Blueprint
Common authentication routes for all user roles
"""

from flask import Blueprint, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import check_password_hash, generate_password_hash
from app.database import get_db
import uuid
from datetime import datetime

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/')
def home():
    """Home page - redirects based on login status"""
    if 'user_id' in session:
        user_role = session.get('user_role', 'user')
        if user_role == 'admin':
            return redirect(url_for('admin.dashboard'))
        elif user_role == 'security_analyst':
            return redirect(url_for('analyst.dashboard'))
        else:
            return redirect(url_for('user.dashboard'))
    return render_template('home.html')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
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
                return redirect(url_for('auth.onboarding'))
            else:
                if user['role'] == 'admin':
                    return redirect(url_for('admin.dashboard'))
                elif user['role'] == 'security_analyst':
                    return redirect(url_for('analyst.dashboard'))
                else:
                    return redirect(url_for('user.dashboard'))
        else:
            conn.close()
            flash('Invalid email or password. Try demo: user@demo.com / password123', 'error')
    
    return render_template('login.html')

@auth_bp.route('/logout')
def logout():
    """User logout"""
    session.clear()
    flash('You have been logged out successfully', 'success')
    return redirect(url_for('auth.home'))

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
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
        return redirect(url_for('auth.onboarding'))
    
    return render_template('register.html')

@auth_bp.route('/onboarding', methods=['GET', 'POST'])
def onboarding():
    """User onboarding process"""
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))
    
    if request.method == 'POST':
        # Complete onboarding
        conn = get_db()
        conn.execute(
            'UPDATE users SET onboarding_completed = 1 WHERE id = ?',
            (session['user_id'],)
        )
        conn.commit()
        conn.close()
        
        # Redirect based on role
        user_role = session.get('user_role', 'user')
        if user_role == 'admin':
            return redirect(url_for('admin.dashboard'))
        elif user_role == 'security_analyst':
            return redirect(url_for('analyst.dashboard'))
        else:
            return redirect(url_for('user.dashboard'))
    
    return render_template('onboarding.html')

# API routes for notifications (keeping for compatibility)
@auth_bp.route('/api/notifications')
def api_notifications():
    """Get notifications for current user"""
    if 'user_id' not in session:
        return jsonify({'error': 'Authentication required'}), 401
    
    limit = int(request.args.get('limit', 15))
    user_role = session.get('user_role', 'user')
    
    conn = get_db()
    notifications = conn.execute('''
        SELECT * FROM notifications 
        WHERE user_id = ? 
        ORDER BY created_at DESC 
        LIMIT ?
    ''', (session['user_id'], limit)).fetchall()
    conn.close()
    
    notifications_list = [dict(notif) for notif in notifications]
    return jsonify({'notifications': notifications_list})

@auth_bp.route('/api/notifications/unread-count')
def api_notification_count():
    """Get unread notification count"""
    if 'user_id' not in session:
        return jsonify({'error': 'Authentication required'}), 401
    
    conn = get_db()
    count = conn.execute('''
        SELECT COUNT(*) as count FROM notifications 
        WHERE user_id = ? AND read = 0
    ''', (session['user_id'],)).fetchone()['count']
    conn.close()
    
    return jsonify({'count': count})

@auth_bp.route('/api/notifications/<notification_id>/read', methods=['POST'])
def api_mark_notification_read(notification_id):
    """Mark notification as read"""
    if 'user_id' not in session:
        return jsonify({'error': 'Authentication required'}), 401
    
    conn = get_db()
    conn.execute('''
        UPDATE notifications 
        SET read = 1 
        WHERE id = ? AND user_id = ?
    ''', (notification_id, session['user_id']))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@auth_bp.route('/api/notifications/mark-all-read', methods=['POST'])
def api_mark_all_read():
    """Mark all notifications as read"""
    if 'user_id' not in session:
        return jsonify({'error': 'Authentication required'}), 401
    
    conn = get_db()
    conn.execute('''
        UPDATE notifications 
        SET read = 1 
        WHERE user_id = ?
    ''', (session['user_id'],))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True}) 