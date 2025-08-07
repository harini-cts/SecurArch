"""
Security middleware and utilities for SecureArch Portal
Handles authentication, rate limiting, and security monitoring
"""

import jwt
import time
import hashlib
import logging
from datetime import datetime, timedelta
from functools import wraps
from flask import request, session, jsonify, current_app, g
from werkzeug.security import check_password_hash, generate_password_hash
from app.database import get_db, log_user_action

logger = logging.getLogger(__name__)

class SecurityManager:
    """Central security management class"""
    
    @staticmethod
    def hash_password(password):
        """Hash password with strong algorithm"""
        return generate_password_hash(
            password, 
            method='pbkdf2:sha256:100000',  # 100,000 iterations
            salt_length=16
        )
    
    @staticmethod
    def verify_password(password, password_hash):
        """Verify password against hash"""
        return check_password_hash(password_hash, password)
    
    @staticmethod
    def generate_jwt_token(user_id, user_role):
        """Generate JWT token for API authentication"""
        payload = {
            'user_id': user_id,
            'user_role': user_role,
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + current_app.config['JWT_ACCESS_TOKEN_EXPIRES']
        }
        
        return jwt.encode(
            payload,
            current_app.config['JWT_SECRET'],
            algorithm='HS256'
        )
    
    @staticmethod
    def verify_jwt_token(token):
        """Verify and decode JWT token"""
        try:
            payload = jwt.decode(
                token,
                current_app.config['JWT_SECRET'],
                algorithms=['HS256']
            )
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None

class LoginAttemptTracker:
    """Track and limit login attempts to prevent brute force attacks"""
    
    MAX_ATTEMPTS = 5
    LOCKOUT_DURATION = timedelta(minutes=30)
    
    @classmethod
    def is_account_locked(cls, email):
        """Check if account is locked due to failed attempts"""
        conn = get_db()
        user = conn.execute(
            'SELECT failed_login_attempts, account_locked_until FROM users WHERE email = ?',
            (email,)
        ).fetchone()
        
        if not user:
            return False
        
        if user['account_locked_until']:
            lockout_time = datetime.fromisoformat(user['account_locked_until'])
            if datetime.now() < lockout_time:
                return True
            else:
                # Unlock account if lockout period has passed
                cls.reset_login_attempts(email)
        
        return user['failed_login_attempts'] >= cls.MAX_ATTEMPTS
    
    @classmethod
    def record_failed_attempt(cls, email):
        """Record a failed login attempt"""
        conn = get_db()
        
        # Get current attempt count
        user = conn.execute(
            'SELECT failed_login_attempts FROM users WHERE email = ?',
            (email,)
        ).fetchone()
        
        if user:
            new_count = user['failed_login_attempts'] + 1
            
            # Lock account if max attempts reached
            if new_count >= cls.MAX_ATTEMPTS:
                lockout_until = datetime.now() + cls.LOCKOUT_DURATION
                conn.execute(
                    'UPDATE users SET failed_login_attempts = ?, account_locked_until = ? WHERE email = ?',
                    (new_count, lockout_until.isoformat(), email)
                )
                logger.warning(f"Account locked for email: {email}")
            else:
                conn.execute(
                    'UPDATE users SET failed_login_attempts = ? WHERE email = ?',
                    (new_count, email)
                )
            
            conn.commit()
    
    @classmethod
    def reset_login_attempts(cls, email):
        """Reset login attempts after successful login"""
        conn = get_db()
        conn.execute(
            'UPDATE users SET failed_login_attempts = 0, account_locked_until = NULL WHERE email = ?',
            (email,)
        )
        conn.commit()

class RateLimiter:
    """Rate limiting implementation for API endpoints"""
    
    def __init__(self, redis_client=None):
        self.redis = redis_client or current_app.redis
    
    def is_rate_limited(self, key, limit, window):
        """Check if request is rate limited"""
        if not self.redis:
            return False  # Skip rate limiting if Redis is not available
        
        try:
            current_time = int(time.time())
            window_start = current_time - window
            
            # Remove old entries
            self.redis.zremrangebyscore(key, 0, window_start)
            
            # Count current requests
            current_count = self.redis.zcard(key)
            
            if current_count >= limit:
                return True
            
            # Add current request
            self.redis.zadd(key, {str(current_time): current_time})
            self.redis.expire(key, window)
            
            return False
            
        except Exception as e:
            logger.error(f"Rate limiting error: {e}")
            return False  # Fail open for availability

def get_client_ip():
    """Get client IP address, handling proxies"""
    if request.headers.getlist("X-Forwarded-For"):
        return request.headers.getlist("X-Forwarded-For")[0].split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    else:
        return request.remote_addr

def get_user_agent():
    """Get user agent string"""
    return request.headers.get('User-Agent', '')[:500]  # Limit length

def login_required(f):
    """Decorator to require login for routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            if request.is_json:
                return jsonify({'error': 'Authentication required', 'code': 401}), 401
            return jsonify({'error': 'Authentication required'}), 401
        
        # Load user info into g for easy access
        conn = get_db()
        user = conn.execute(
            'SELECT id, email, role, is_active FROM users WHERE id = ?',
            (session['user_id'],)
        ).fetchone()
        
        if not user or not user['is_active']:
            session.clear()
            return jsonify({'error': 'Account inactive', 'code': 401}), 401
        
        g.current_user = dict(user)
        return f(*args, **kwargs)
    
    return decorated_function

def jwt_required(f):
    """Decorator for JWT-based API authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = None
        
        # Check for token in Authorization header
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
        
        if not token:
            return jsonify({'error': 'Token missing', 'code': 401}), 401
        
        # Verify token
        payload = SecurityManager.verify_jwt_token(token)
        if not payload:
            return jsonify({'error': 'Invalid or expired token', 'code': 401}), 401
        
        # Load user info
        conn = get_db()
        user = conn.execute(
            'SELECT id, email, role, is_active FROM users WHERE id = ?',
            (payload['user_id'],)
        ).fetchone()
        
        if not user or not user['is_active']:
            return jsonify({'error': 'Account inactive', 'code': 401}), 401
        
        g.current_user = dict(user)
        return f(*args, **kwargs)
    
    return decorated_function

def role_required(*allowed_roles):
    """Decorator to require specific roles"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not hasattr(g, 'current_user'):
                return jsonify({'error': 'Authentication required', 'code': 401}), 401
            
            user_role = g.current_user.get('role')
            if user_role not in allowed_roles:
                log_user_action(
                    g.current_user['id'],
                    'unauthorized_access_attempt',
                    details=f"Required roles: {allowed_roles}, User role: {user_role}",
                    ip_address=get_client_ip(),
                    user_agent=get_user_agent()
                )
                return jsonify({'error': 'Insufficient permissions', 'code': 403}), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def rate_limit(limit=100, window=3600, per='ip'):
    """Decorator for rate limiting endpoints"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Determine rate limit key
            if per == 'ip':
                key = f"rate_limit:{get_client_ip()}:{request.endpoint}"
            elif per == 'user' and hasattr(g, 'current_user'):
                key = f"rate_limit:user:{g.current_user['id']}:{request.endpoint}"
            else:
                key = f"rate_limit:global:{request.endpoint}"
            
            # Check rate limit
            rate_limiter = RateLimiter()
            if rate_limiter.is_rate_limited(key, limit, window):
                logger.warning(f"Rate limit exceeded for {key}")
                return jsonify({
                    'error': 'Rate limit exceeded',
                    'code': 429,
                    'retry_after': window
                }), 429
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def audit_action(action_type, resource_type=None):
    """Decorator to audit user actions"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Execute the function
            result = f(*args, **kwargs)
            
            # Log the action if user is authenticated
            if hasattr(g, 'current_user'):
                # Try to extract resource ID from kwargs or result
                resource_id = kwargs.get('id') or kwargs.get('app_id') or kwargs.get('review_id')
                
                log_user_action(
                    user_id=g.current_user['id'],
                    action=action_type,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    ip_address=get_client_ip(),
                    user_agent=get_user_agent()
                )
            
            return result
        return decorated_function
    return decorator

def validate_csrf_token():
    """Validate CSRF token for form submissions"""
    if request.method in ['POST', 'PUT', 'DELETE', 'PATCH']:
        token = request.form.get('csrf_token') or request.headers.get('X-CSRFToken')
        
        if not token:
            return False
        
        try:
            # Use Flask-WTF's built-in CSRF validation
            from flask_wtf.csrf import validate_csrf
            validate_csrf(token)
            return True
        except Exception:
            return False
    
    return True

def secure_headers():
    """Add security headers to responses"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            response = f(*args, **kwargs)
            
            # Add security headers if response is a Flask response object
            if hasattr(response, 'headers'):
                response.headers['X-Content-Type-Options'] = 'nosniff'
                response.headers['X-Frame-Options'] = 'DENY'
                response.headers['X-XSS-Protection'] = '1; mode=block'
                response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
                
                if current_app.config.get('PREFERRED_URL_SCHEME') == 'https':
                    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
            
            return response
        return decorated_function
    return decorator

def check_password_strength(password):
    """Check password strength and return score and feedback"""
    score = 0
    feedback = []
    
    if len(password) >= 8:
        score += 1
    else:
        feedback.append("Password must be at least 8 characters long")
    
    if any(c.islower() for c in password):
        score += 1
    else:
        feedback.append("Password must contain lowercase letters")
    
    if any(c.isupper() for c in password):
        score += 1
    else:
        feedback.append("Password must contain uppercase letters")
    
    if any(c.isdigit() for c in password):
        score += 1
    else:
        feedback.append("Password must contain numbers")
    
    if any(c in '@$!%*?&' for c in password):
        score += 1
    else:
        feedback.append("Password must contain special characters (@$!%*?&)")
    
    # Additional strength checks
    if len(password) >= 12:
        score += 1
    
    if len(set(password)) / len(password) > 0.7:  # Character diversity
        score += 1
    
    strength_levels = {
        0: 'Very Weak',
        1: 'Very Weak',
        2: 'Weak',
        3: 'Fair',
        4: 'Good',
        5: 'Strong',
        6: 'Very Strong',
        7: 'Excellent'
    }
    
    return {
        'score': score,
        'max_score': 7,
        'strength': strength_levels.get(score, 'Unknown'),
        'feedback': feedback,
        'is_strong': score >= 4
    } 