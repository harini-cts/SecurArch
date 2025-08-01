"""
SecureArch Portal - Database Models
SQLAlchemy models for PostgreSQL database
"""

import uuid
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import Text, String
from sqlalchemy import Index

# Will be initialized by app
db = None
bcrypt = Bcrypt()

class BaseModel(db.Model):
    """Base model with common fields"""
    __abstract__ = True
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_active = db.Column(db.Boolean, nullable=False, default=True)

class Organization(BaseModel):
    """Organization model for multi-tenancy"""
    __tablename__ = 'organizations'
    
    name = db.Column(db.String(255), nullable=False)
    domain = db.Column(db.String(255), unique=True)
    industry = db.Column(db.String(100))
    size = db.Column(db.String(50))  # startup, small, medium, large, enterprise
    country = db.Column(db.String(100))
    settings = db.Column(db.Text, default='{}')
    
    # Relationships
    users = db.relationship('User', backref='organization', lazy='dynamic')
    applications = db.relationship('Application', backref='organization', lazy='dynamic')
    
    def __repr__(self):
        return f'<Organization {self.name}>'

class User(BaseModel):
    """User model with role-based access control"""
    __tablename__ = 'users'
    
    # Basic Info
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    
    # Role & Permissions
    role = db.Column(db.String(50), nullable=False, default='user')  # admin, expert, user, viewer
    permissions = db.Column(db.Text, default='[]')
    
    # Organization
    organization_id = db.Column(db.String(36), db.ForeignKey('organizations.id'))
    
    # Profile
    title = db.Column(db.String(100))
    department = db.Column(db.String(100))
    phone = db.Column(db.String(20))
    timezone = db.Column(db.String(50), default='UTC')
    avatar_url = db.Column(db.String(500))
    
    # Security
    email_verified = db.Column(db.Boolean, default=False)
    two_factor_enabled = db.Column(db.Boolean, default=False)
    last_login_at = db.Column(db.DateTime)
    login_count = db.Column(db.Integer, default=0)
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)
    
    # Preferences
    notification_preferences = db.Column(db.Text, default='{"email_notifications": true, "review_assignments": true, "security_alerts": true}')
    
    # Relationships
    authored_applications = db.relationship('Application', foreign_keys='Application.author_id', backref='author', lazy='dynamic')
    assigned_reviews = db.relationship('Review', foreign_keys='Review.reviewer_id', backref='reviewer', lazy='dynamic')
    findings = db.relationship('Finding', backref='author', lazy='dynamic')
    
    def set_password(self, password):
        """Hash and set password"""
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    
    def check_password(self, password):
        """Check password against hash"""
        return bcrypt.check_password_hash(self.password_hash, password)
    
    def has_permission(self, permission):
        """Check if user has specific permission"""
        if self.role == 'admin':
            return True
        return permission in (self.permissions or [])
    
    def has_role(self, role):
        """Check if user has specific role"""
        return self.role == role or self.role == 'admin'
    
    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}"
    
    def to_dict(self, include_sensitive=False):
        """Convert user to dictionary"""
        data = {
            'id': str(self.id),
            'email': self.email,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'full_name': self.full_name,
            'role': self.role,
            'title': self.title,
            'department': self.department,
            'organization_id': str(self.organization_id) if self.organization_id else None,
            'last_login_at': self.last_login_at.isoformat() if self.last_login_at else None,
            'created_at': self.created_at.isoformat(),
            'is_active': self.is_active
        }
        
        if include_sensitive:
            data.update({
                'permissions': self.permissions,
                'email_verified': self.email_verified,
                'two_factor_enabled': self.two_factor_enabled,
                'notification_preferences': self.notification_preferences
            })
        
        return data
    
    def __repr__(self):
        return f'<User {self.email}>'

class Application(BaseModel):
    """Application model for security architecture submissions"""
    __tablename__ = 'applications'
    
    # Basic Info
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    version = db.Column(db.String(50))
    
    # Classification
    business_criticality = db.Column(db.String(20), nullable=False)  # critical, high, medium, low
    data_classification = db.Column(db.String(20), nullable=False)   # public, internal, confidential, restricted
    environment = db.Column(db.String(20))  # development, staging, production
    
    # Architecture
    architecture_type = db.Column(db.String(50))  # web, mobile, api, microservices, etc.
    technology_stack = db.Column(JSONB, default=[])
    deployment_model = db.Column(db.String(50))  # cloud, on-premise, hybrid
    cloud_provider = db.Column(db.String(50))   # aws, azure, gcp, etc.
    
    # Compliance Requirements
    compliance_frameworks = db.Column(JSONB, default=[])  # PCI-DSS, HIPAA, SOX, etc.
    regulatory_requirements = db.Column(JSONB, default=[])
    
    # Documents & Assets
    architecture_documents = db.Column(JSONB, default=[])  # file paths/URLs
    threat_model = db.Column(JSONB, default={})
    data_flow_diagrams = db.Column(JSONB, default=[])
    
    # Review Status
    status = db.Column(db.String(20), nullable=False, default='draft')  # draft, submitted, in_review, approved, rejected
    submission_date = db.Column(db.DateTime)
    review_deadline = db.Column(db.DateTime)
    
    # Relationships
    author_id = db.Column(UUID(as_uuid=True), db.ForeignKey('users.id'), nullable=False)
    organization_id = db.Column(UUID(as_uuid=True), db.ForeignKey('organizations.id'), nullable=False)
    reviews = db.relationship('Review', backref='application', lazy='dynamic', cascade='all, delete-orphan')
    
    # Metadata
    metadata = db.Column(JSONB, default={})
    
    def to_dict(self, include_relations=False):
        """Convert application to dictionary"""
        data = {
            'id': str(self.id),
            'name': self.name,
            'description': self.description,
            'version': self.version,
            'business_criticality': self.business_criticality,
            'data_classification': self.data_classification,
            'environment': self.environment,
            'architecture_type': self.architecture_type,
            'technology_stack': self.technology_stack,
            'deployment_model': self.deployment_model,
            'cloud_provider': self.cloud_provider,
            'compliance_frameworks': self.compliance_frameworks,
            'status': self.status,
            'submission_date': self.submission_date.isoformat() if self.submission_date else None,
            'review_deadline': self.review_deadline.isoformat() if self.review_deadline else None,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'author_id': str(self.author_id),
            'organization_id': str(self.organization_id)
        }
        
        if include_relations:
            data.update({
                'author': self.author.to_dict() if self.author else None,
                'organization': {'id': str(self.organization.id), 'name': self.organization.name} if self.organization else None,
                'reviews_count': self.reviews.count()
            })
        
        return data
    
    def __repr__(self):
        return f'<Application {self.name}>'

class Review(BaseModel):
    """Security review model"""
    __tablename__ = 'reviews'
    
    # Basic Info
    title = db.Column(db.String(255), nullable=False)
    review_type = db.Column(db.String(50), nullable=False)  # architecture, code, infrastructure, compliance
    
    # OWASP Assessment
    owasp_asvs_level = db.Column(db.Integer)  # 1, 2, or 3
    owasp_top10_assessment = db.Column(JSONB, default={})
    proactive_controls_assessment = db.Column(JSONB, default={})
    
    # Review Details
    scope = db.Column(db.Text)
    methodology = db.Column(db.Text)
    tools_used = db.Column(JSONB, default=[])
    
    # Status & Timeline
    status = db.Column(db.String(20), nullable=False, default='pending')  # pending, in_progress, completed, cancelled
    priority = db.Column(db.String(20), default='medium')  # critical, high, medium, low
    estimated_hours = db.Column(db.Float)
    actual_hours = db.Column(db.Float)
    
    # Dates
    assigned_date = db.Column(db.DateTime, default=datetime.utcnow)
    started_date = db.Column(db.DateTime)
    completed_date = db.Column(db.DateTime)
    due_date = db.Column(db.DateTime)
    
    # Results
    overall_risk_score = db.Column(db.Float)  # 0-10 scale
    security_posture = db.Column(db.String(20))  # excellent, good, fair, poor, critical
    compliance_status = db.Column(db.String(20))  # compliant, partial, non_compliant
    
    # Relationships
    application_id = db.Column(UUID(as_uuid=True), db.ForeignKey('applications.id'), nullable=False)
    reviewer_id = db.Column(UUID(as_uuid=True), db.ForeignKey('users.id'))
    
    # Review Data
    findings = db.relationship('Finding', backref='review', lazy='dynamic', cascade='all, delete-orphan')
    recommendations = db.Column(JSONB, default=[])
    executive_summary = db.Column(db.Text)
    
    def to_dict(self, include_relations=False):
        """Convert review to dictionary"""
        data = {
            'id': str(self.id),
            'title': self.title,
            'review_type': self.review_type,
            'owasp_asvs_level': self.owasp_asvs_level,
            'scope': self.scope,
            'status': self.status,
            'priority': self.priority,
            'overall_risk_score': self.overall_risk_score,
            'security_posture': self.security_posture,
            'compliance_status': self.compliance_status,
            'assigned_date': self.assigned_date.isoformat() if self.assigned_date else None,
            'completed_date': self.completed_date.isoformat() if self.completed_date else None,
            'due_date': self.due_date.isoformat() if self.due_date else None,
            'created_at': self.created_at.isoformat(),
            'application_id': str(self.application_id),
            'reviewer_id': str(self.reviewer_id) if self.reviewer_id else None
        }
        
        if include_relations:
            data.update({
                'application': self.application.to_dict() if self.application else None,
                'reviewer': self.reviewer.to_dict() if self.reviewer else None,
                'findings_count': self.findings.count()
            })
        
        return data
    
    def __repr__(self):
        return f'<Review {self.title}>'

class Finding(BaseModel):
    """Security finding model"""
    __tablename__ = 'findings'
    
    # Basic Info
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(100))  # OWASP category, CWE, etc.
    
    # Risk Assessment
    severity = db.Column(db.String(20), nullable=False)  # critical, high, medium, low, info
    likelihood = db.Column(db.String(20))  # very_high, high, medium, low, very_low
    impact = db.Column(db.String(20))     # very_high, high, medium, low, very_low
    risk_score = db.Column(db.Float)      # calculated risk score
    
    # OWASP Mapping
    owasp_top10_mapping = db.Column(JSONB, default=[])  # A01, A02, etc.
    asvs_mapping = db.Column(JSONB, default=[])         # ASVS requirement IDs
    cwe_mapping = db.Column(JSONB, default=[])          # CWE IDs
    
    # Details
    location = db.Column(db.String(500))  # file, component, or system location
    evidence = db.Column(db.Text)
    proof_of_concept = db.Column(db.Text)
    
    # Remediation
    recommendation = db.Column(db.Text)
    remediation_effort = db.Column(db.String(20))  # low, medium, high
    remediation_priority = db.Column(db.String(20))  # immediate, short_term, long_term
    
    # Status
    status = db.Column(db.String(20), nullable=False, default='open')  # open, in_progress, resolved, accepted, false_positive
    resolution_notes = db.Column(db.Text)
    resolved_date = db.Column(db.DateTime)
    
    # Relationships
    review_id = db.Column(UUID(as_uuid=True), db.ForeignKey('reviews.id'), nullable=False)
    author_id = db.Column(UUID(as_uuid=True), db.ForeignKey('users.id'), nullable=False)
    
    def to_dict(self, include_relations=False):
        """Convert finding to dictionary"""
        data = {
            'id': str(self.id),
            'title': self.title,
            'description': self.description,
            'category': self.category,
            'severity': self.severity,
            'likelihood': self.likelihood,
            'impact': self.impact,
            'risk_score': self.risk_score,
            'owasp_top10_mapping': self.owasp_top10_mapping,
            'asvs_mapping': self.asvs_mapping,
            'location': self.location,
            'recommendation': self.recommendation,
            'status': self.status,
            'created_at': self.created_at.isoformat(),
            'resolved_date': self.resolved_date.isoformat() if self.resolved_date else None,
            'review_id': str(self.review_id),
            'author_id': str(self.author_id)
        }
        
        if include_relations:
            data.update({
                'review': self.review.to_dict() if self.review else None,
                'author': self.author.to_dict() if self.author else None
            })
        
        return data
    
    def __repr__(self):
        return f'<Finding {self.title}>'

# Database Indexes for Performance
Index('idx_users_email', User.email)
Index('idx_users_organization', User.organization_id)
Index('idx_applications_author', Application.author_id)
Index('idx_applications_organization', Application.organization_id)
Index('idx_applications_status', Application.status)
Index('idx_reviews_application', Review.application_id)
Index('idx_reviews_reviewer', Review.reviewer_id)
Index('idx_reviews_status', Review.status)
Index('idx_findings_review', Finding.review_id)
Index('idx_findings_severity', Finding.severity)
Index('idx_findings_status', Finding.status) 