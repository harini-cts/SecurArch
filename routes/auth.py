"""
Authentication Routes for SecureArch Portal
JWT-based authentication with role-based access control
"""

from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import (
    create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity, get_jwt
)
from marshmallow import Schema, fields, ValidationError, validate
from werkzeug.security import check_password_hash
import structlog
import uuid

from models import User, Organization, db

# Initialize logger
logger = structlog.get_logger(__name__)

# Create Blueprint
auth_bp = Blueprint('auth', __name__)

# Validation Schemas
class RegisterSchema(Schema):
    email = fields.Email(required=True)
    password = fields.Str(required=True, validate=validate.Length(min=8))
    first_name = fields.Str(required=True, validate=validate.Length(min=1))
    last_name = fields.Str(required=True, validate=validate.Length(min=1))
    organization_name = fields.Str(allow_none=True)

class LoginSchema(Schema):
    email = fields.Email(required=True)
    password = fields.Str(required=True, validate=validate.Length(min=1))

class RefreshSchema(Schema):
    refresh_token = fields.Str(required=True)

# Utility Functions
def get_user_permissions(role):
    """Get permissions based on user role"""
    role_permissions = {
        'admin': [
            'user:read', 'user:create', 'user:update', 'user:delete',
            'review:read', 'review:create', 'review:update', 'review:delete',
            'application:read', 'application:create', 'application:update', 'application:delete',
            'owasp:read', 'owasp:update',
            'dashboard:read', 'dashboard:admin',
        ],
        'expert': [
            'review:read', 'review:create', 'review:update',
            'application:read',
            'owasp:read',
            'dashboard:read',
            'finding:create', 'finding:update',
        ],
        'user': [
            'review:read', 'review:create',
            'application:read', 'application:create', 'application:update',
            'dashboard:read',
        ],
        'viewer': [
            'review:read',
            'application:read',
            'dashboard:read',
        ],
    }
    return role_permissions.get(role, role_permissions['viewer'])

@auth_bp.route('/register', methods=['POST'])
def register():
    """Register a new user"""
    schema = RegisterSchema()
    
    try:
        # Validate input
        data = schema.load(request.json)
    except ValidationError as err:
        logger.warning("Registration validation failed", errors=err.messages)
        return jsonify({
            'error': 'Validation failed',
            'code': 'VALIDATION_ERROR',
            'details': err.messages
        }), 400
    
    try:
        # Check if user already exists
        existing_user = User.query.filter_by(email=data['email']).first()
        if existing_user:
            logger.warning("Registration attempt with existing email", email=data['email'])
            return jsonify({
                'error': 'User already exists',
                'code': 'USER_EXISTS'
            }), 409
        
        # Create organization if provided
        organization_id = None
        if data.get('organization_name'):
            organization = Organization(
                id=uuid.uuid4(),
                name=data['organization_name']
            )
            db.session.add(organization)
            db.session.flush()  # Get the ID without committing
            organization_id = organization.id
        
        # Create user
        user = User(
            id=uuid.uuid4(),
            email=data['email'],
            first_name=data['first_name'],
            last_name=data['last_name'],
            organization_id=organization_id,
            role='user',
            permissions=get_user_permissions('user')
        )
        user.set_password(data['password'])
        
        db.session.add(user)
        db.session.commit()
        
        logger.info("User registered successfully", 
                   user_id=str(user.id), 
                   email=user.email,
                   organization_id=str(organization_id) if organization_id else None)
        
        # Generate tokens
        access_token = create_access_token(
            identity=str(user.id),
            additional_claims={
                'email': user.email,
                'role': user.role,
                'permissions': user.permissions,
                'organization_id': str(user.organization_id) if user.organization_id else None
            }
        )
        refresh_token = create_refresh_token(identity=str(user.id))
        
        return jsonify({
            'message': 'User registered successfully',
            'user': user.to_dict(),
            'tokens': {
                'access_token': access_token,
                'refresh_token': refresh_token,
                'token_type': 'Bearer',
                'expires_in': int(current_app.config['JWT_ACCESS_TOKEN_EXPIRES'].total_seconds())
            }
        }), 201
        
    except Exception as e:
        db.session.rollback()
        logger.error("Registration failed", error=str(e))
        return jsonify({
            'error': 'Registration failed',
            'code': 'REGISTRATION_ERROR'
        }), 500

@auth_bp.route('/login', methods=['POST'])
def login():
    """Authenticate user and return JWT tokens"""
    schema = LoginSchema()
    
    try:
        # Validate input
        data = schema.load(request.json)
    except ValidationError as err:
        logger.warning("Login validation failed", errors=err.messages)
        return jsonify({
            'error': 'Validation failed',
            'code': 'VALIDATION_ERROR',
            'details': err.messages
        }), 400
    
    try:
        # Get user
        user = User.query.filter_by(email=data['email'], is_active=True).first()
        
        if not user or not user.check_password(data['password']):
            logger.warning("Login failed", 
                          email=data['email'],
                          ip=request.environ.get('REMOTE_ADDR'))
            return jsonify({
                'error': 'Invalid credentials',
                'code': 'INVALID_CREDENTIALS'
            }), 401
        
        # Check if account is locked
        if user.locked_until and user.locked_until > datetime.utcnow():
            logger.warning("Login attempt on locked account", 
                          user_id=str(user.id),
                          locked_until=user.locked_until.isoformat())
            return jsonify({
                'error': 'Account is temporarily locked',
                'code': 'ACCOUNT_LOCKED'
            }), 423
        
        # Update login info
        user.last_login_at = datetime.utcnow()
        user.login_count += 1
        user.failed_login_attempts = 0
        user.locked_until = None
        
        # Get user permissions
        permissions = get_user_permissions(user.role)
        user.permissions = permissions
        
        db.session.commit()
        
        logger.info("User logged in successfully", 
                   user_id=str(user.id),
                   email=user.email,
                   ip=request.environ.get('REMOTE_ADDR'))
        
        # Generate tokens
        access_token = create_access_token(
            identity=str(user.id),
            additional_claims={
                'email': user.email,
                'role': user.role,
                'permissions': permissions,
                'organization_id': str(user.organization_id) if user.organization_id else None
            }
        )
        refresh_token = create_refresh_token(identity=str(user.id))
        
        return jsonify({
            'message': 'Login successful',
            'user': user.to_dict(),
            'tokens': {
                'access_token': access_token,
                'refresh_token': refresh_token,
                'token_type': 'Bearer',
                'expires_in': int(current_app.config['JWT_ACCESS_TOKEN_EXPIRES'].total_seconds())
            }
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error("Login failed", error=str(e))
        return jsonify({
            'error': 'Login failed',
            'code': 'LOGIN_ERROR'
        }), 500

@auth_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    """Refresh access token using refresh token"""
    try:
        # Get user from refresh token
        user_id = get_jwt_identity()
        user = User.query.filter_by(id=user_id, is_active=True).first()
        
        if not user:
            logger.warning("Refresh token used for non-existent user", user_id=user_id)
            return jsonify({
                'error': 'Invalid refresh token',
                'code': 'INVALID_REFRESH_TOKEN'
            }), 401
        
        # Get current permissions
        permissions = get_user_permissions(user.role)
        
        # Generate new access token
        access_token = create_access_token(
            identity=str(user.id),
            additional_claims={
                'email': user.email,
                'role': user.role,
                'permissions': permissions,
                'organization_id': str(user.organization_id) if user.organization_id else None
            }
        )
        
        logger.info("Token refreshed", user_id=str(user.id))
        
        return jsonify({
            'access_token': access_token,
            'token_type': 'Bearer',
            'expires_in': int(current_app.config['JWT_ACCESS_TOKEN_EXPIRES'].total_seconds())
        })
        
    except Exception as e:
        logger.error("Token refresh failed", error=str(e))
        return jsonify({
            'error': 'Token refresh failed',
            'code': 'REFRESH_ERROR'
        }), 500

@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    """Logout user (mainly for audit trail)"""
    try:
        user_id = get_jwt_identity()
        jti = get_jwt()['jti']  # JWT ID for potential blacklisting
        
        logger.info("User logged out", user_id=user_id, jti=jti)
        
        return jsonify({
            'message': 'Logged out successfully'
        })
        
    except Exception as e:
        logger.error("Logout error", error=str(e))
        return jsonify({
            'error': 'Logout failed',
            'code': 'LOGOUT_ERROR'
        }), 500

@auth_bp.route('/me', methods=['GET'])
@jwt_required()
def get_current_user():
    """Get current user profile"""
    try:
        user_id = get_jwt_identity()
        user = User.query.filter_by(id=user_id, is_active=True).first()
        
        if not user:
            return jsonify({
                'error': 'User not found',
                'code': 'USER_NOT_FOUND'
            }), 404
        
        return jsonify({
            'user': user.to_dict(include_sensitive=True)
        })
        
    except Exception as e:
        logger.error("Get current user failed", error=str(e))
        return jsonify({
            'error': 'Failed to get user profile',
            'code': 'PROFILE_ERROR'
        }), 500

@auth_bp.route('/verify-token', methods=['POST'])
@jwt_required()
def verify_token():
    """Verify if current token is valid"""
    try:
        user_id = get_jwt_identity()
        claims = get_jwt()
        
        return jsonify({
            'valid': True,
            'user_id': user_id,
            'expires_at': claims.get('exp'),
            'role': claims.get('role'),
            'permissions': claims.get('permissions', [])
        })
        
    except Exception as e:
        logger.error("Token verification failed", error=str(e))
        return jsonify({
            'error': 'Token verification failed',
            'code': 'TOKEN_VERIFICATION_ERROR'
        }), 500 