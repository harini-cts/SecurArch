"""
Role-based Access Control Decorators
Provides decorators for enforcing role-based access to routes
"""

from functools import wraps
from flask import session, redirect, url_for, flash, request, jsonify
from app.database import get_db

def login_required(f):
    """Decorator to require login for routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            if request.is_json:
                return jsonify({'error': 'Authentication required', 'code': 401}), 401
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function

def user_required(f):
    """Decorator to require regular user role (users can create applications)"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('auth.login'))
        
        # Allow users and admins (admins can do everything users can do)
        user_role = session.get('user_role', 'user')
        if user_role not in ['user', 'admin']:
            flash('Access denied. This area is for application creators only.', 'error')
            return redirect(url_for('auth.home'))
        
        return f(*args, **kwargs)
    return decorated_function

def analyst_required(f):
    """Decorator to require Security Analyst role or higher"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('auth.login'))
        
        # Check if user has analyst role or admin
        user_role = session.get('user_role', 'user')
        if user_role not in ['security_analyst', 'admin']:
            flash('Access denied. Security analyst privileges required.', 'error')
            return redirect(url_for('auth.home'))
        
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to require Admin role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('auth.login'))
        
        # Check if user has admin role
        user_role = session.get('user_role', 'user')
        if user_role != 'admin':
            flash('Access denied. Administrator privileges required.', 'error')
            return redirect(url_for('auth.home'))
        
        return f(*args, **kwargs)
    return decorated_function

def role_required(*allowed_roles):
    """Decorator to require specific roles (flexible)"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('auth.login'))
            
            user_role = session.get('user_role', 'user')
            if user_role not in allowed_roles:
                flash(f'Access denied. Required roles: {", ".join(allowed_roles)}', 'error')
                return redirect(url_for('auth.home'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator 