"""
Authentication Blueprint
Common authentication routes for all user roles
"""

from flask import Blueprint, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import check_password_hash
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
    return render_template('auth/home.html')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        conn = get_db()
        user = conn.execute(
            'SELECT * FROM users WHERE email = ? AND is_active = 1',
            (email,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['user_role'] = user['role']
            session['user_name'] = f"{user['first_name']} {user['last_name']}"
            
            # Update last login
            conn = get_db()
            conn.execute(
                'UPDATE users SET last_login_at = ? WHERE id = ?',
                (datetime.now().isoformat(), user['id'])
            )
            conn.commit()
            conn.close()
            
            # Redirect based on role and onboarding status
            if not user['onboarding_completed']:
                return redirect(url_for('auth.onboarding'))
            elif user['role'] == 'admin':
                return redirect(url_for('admin.dashboard'))
            elif user['role'] == 'security_analyst':
                return redirect(url_for('analyst.dashboard'))
            else:
                return redirect(url_for('user.dashboard'))
        else:
            flash('Invalid email or password', 'error')
    
    return render_template('auth/login.html')

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
        # Registration logic here
        pass
    return render_template('auth/register.html')

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
    
    return render_template('auth/onboarding.html') 