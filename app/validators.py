"""
Input validation schemas for SecureArch Portal
Prevents XSS, injection attacks, and ensures data integrity
"""

import re
import html
from marshmallow import Schema, fields, validate, validates, validates_schema, ValidationError, post_load
from bleach import clean
from urllib.parse import urlparse

# Allowed HTML tags and attributes for sanitization
ALLOWED_TAGS = ['p', 'br', 'strong', 'em', 'ul', 'ol', 'li', 'a']
ALLOWED_ATTRIBUTES = {'a': ['href']}

def sanitize_html(value):
    """Sanitize HTML content to prevent XSS"""
    if not value:
        return value
    return clean(value, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRIBUTES, strip=True)

def validate_no_sql_injection(value):
    """Basic SQL injection pattern detection"""
    if not value:
        return value
    
    # Common SQL injection patterns
    sql_patterns = [
        r"(\b(select|insert|update|delete|drop|create|alter|exec|execute)\b)",
        r"(\b(union|having|order\s+by|group\s+by)\b)",
        r"(--|#|/\*|\*/)",
        r"(\b(or|and)\s+\d+\s*=\s*\d+)",
        r"('\s*(or|and)\s*')",
    ]
    
    value_lower = value.lower()
    for pattern in sql_patterns:
        if re.search(pattern, value_lower, re.IGNORECASE):
            raise ValidationError("Invalid characters detected")
    
    return value

def validate_filename(value):
    """Validate filename for security"""
    if not value:
        return value
    
    # Remove path traversal attempts
    if '..' in value or '/' in value or '\\' in value:
        raise ValidationError("Invalid filename format")
    
    # Check for valid filename characters
    if not re.match(r'^[a-zA-Z0-9._-]+$', value):
        raise ValidationError("Filename contains invalid characters")
    
    return value

class SecureStringField(fields.String):
    """Custom string field with built-in sanitization"""
    
    def _deserialize(self, value, attr, data, **kwargs):
        value = super()._deserialize(value, attr, data, **kwargs)
        if value:
            # HTML escape for basic XSS prevention
            value = html.escape(value)
            # Additional SQL injection check
            validate_no_sql_injection(value)
        return value

class SecureTextField(fields.String):
    """Custom text field with HTML sanitization"""
    
    def _deserialize(self, value, attr, data, **kwargs):
        value = super()._deserialize(value, attr, data, **kwargs)
        if value:
            # Sanitize HTML content
            value = sanitize_html(value)
            # SQL injection check
            validate_no_sql_injection(value)
        return value

class UserRegistrationSchema(Schema):
    """User registration validation schema"""
    
    email = fields.Email(
        required=True,
        validate=[
            validate.Length(max=255),
            validate.Regexp(
                r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
                error="Invalid email format"
            )
        ]
    )
    
    password = fields.String(
        required=True,
        validate=[
            validate.Length(min=8, max=128),
            validate.Regexp(
                r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]',
                error="Password must contain uppercase, lowercase, number, and special character"
            )
        ]
    )
    
    first_name = SecureStringField(
        required=True,
        validate=[
            validate.Length(min=1, max=100),
            validate.Regexp(r'^[a-zA-Z\s-]+$', error="First name contains invalid characters")
        ]
    )
    
    last_name = SecureStringField(
        required=True,
        validate=[
            validate.Length(min=1, max=100),
            validate.Regexp(r'^[a-zA-Z\s-]+$', error="Last name contains invalid characters")
        ]
    )
    
    organization_name = SecureStringField(
        validate=[
            validate.Length(max=255),
            validate.Regexp(r'^[a-zA-Z0-9\s.,&-]+$', error="Organization name contains invalid characters")
        ]
    )
    
    job_title = SecureStringField(
        validate=[
            validate.Length(max=100),
            validate.Regexp(r'^[a-zA-Z0-9\s.,&-]+$', error="Job title contains invalid characters")
        ]
    )

class UserLoginSchema(Schema):
    """User login validation schema"""
    
    email = fields.Email(required=True, validate=validate.Length(max=255))
    password = fields.String(required=True, validate=validate.Length(min=1, max=128))

class ApplicationSchema(Schema):
    """Application creation/update validation schema"""
    
    name = SecureStringField(
        required=True,
        validate=[
            validate.Length(min=1, max=255),
            validate.Regexp(r'^[a-zA-Z0-9\s._-]+$', error="Application name contains invalid characters")
        ]
    )
    
    description = SecureTextField(
        validate=validate.Length(max=2000)
    )
    
    technology_stack = SecureTextField(
        validate=validate.Length(max=500)
    )
    
    deployment_environment = fields.String(
        validate=validate.OneOf(['development', 'staging', 'production', 'hybrid'])
    )
    
    business_criticality = fields.String(
        required=True,
        validate=validate.OneOf(['Low', 'Medium', 'High', 'Critical'])
    )
    
    data_classification = fields.String(
        required=True,
        validate=validate.OneOf(['Public', 'Internal', 'Confidential', 'Restricted'])
    )

class SecurityReviewSchema(Schema):
    """Security review validation schema"""
    
    field_type = fields.String(
        required=True,
        validate=validate.OneOf(['application_review', 'cloud_review', 'mobile_review'])
    )
    
    questionnaire_responses = fields.Dict(
        validate=validate.Length(max=50)  # Limit number of responses
    )
    
    additional_comments = SecureTextField(
        validate=validate.Length(max=5000)
    )
    
    @validates('questionnaire_responses')
    def validate_questionnaire_responses(self, value):
        """Validate questionnaire responses structure"""
        if not isinstance(value, dict):
            raise ValidationError("Questionnaire responses must be a dictionary")
        
        # Validate each response
        for key, response in value.items():
            if not isinstance(key, str) or len(key) > 100:
                raise ValidationError("Invalid question key")
            
            if isinstance(response, str):
                if len(response) > 1000:
                    raise ValidationError("Response too long")
                # Sanitize response
                validate_no_sql_injection(response)
            elif isinstance(response, dict):
                # Handle structured responses
                for sub_key, sub_value in response.items():
                    if isinstance(sub_value, str) and len(sub_value) > 1000:
                        raise ValidationError("Response too long")

class FileUploadSchema(Schema):
    """File upload validation schema"""
    
    filename = fields.String(
        required=True,
        validate=[
            validate.Length(min=1, max=255),
            validate_filename
        ]
    )
    
    file_type = fields.String(
        required=True,
        validate=validate.OneOf(['architecture', 'document'])
    )
    
    @validates('filename')
    def validate_file_extension(self, value):
        """Validate file extension"""
        if '.' not in value:
            raise ValidationError("File must have an extension")
        
        extension = value.split('.')[-1].lower()
        
        allowed_extensions = {
            'architecture': {'pdf', 'png', 'jpg', 'jpeg', 'svg', 'vsdx', 'drawio'},
            'document': {'pdf', 'doc', 'docx', 'txt', 'md'}
        }
        
        # We'll check against all allowed extensions since file_type might not be available yet
        all_allowed = set()
        for exts in allowed_extensions.values():
            all_allowed.update(exts)
        
        if extension not in all_allowed:
            raise ValidationError(f"File extension '{extension}' not allowed")

class NotificationSchema(Schema):
    """Notification validation schema"""
    
    title = SecureStringField(
        required=True,
        validate=validate.Length(min=1, max=255)
    )
    
    message = SecureTextField(
        required=True,
        validate=validate.Length(min=1, max=1000)
    )
    
    notification_type = fields.String(
        validate=validate.OneOf(['info', 'warning', 'error', 'success'])
    )

class STRIDEAnalysisSchema(Schema):
    """STRIDE threat analysis validation schema"""
    
    threat_category = fields.String(
        required=True,
        validate=validate.OneOf([
            'spoofing', 'tampering', 'repudiation', 
            'information_disclosure', 'denial_of_service', 'elevation_of_privilege'
        ])
    )
    
    threat_description = SecureTextField(
        required=True,
        validate=validate.Length(min=1, max=1000)
    )
    
    risk_level = fields.String(
        required=True,
        validate=validate.OneOf(['Low', 'Medium', 'High', 'Critical'])
    )
    
    mitigation_status = fields.String(
        validate=validate.OneOf(['pending', 'in_progress', 'completed', 'not_applicable'])
    )
    
    recommendations = SecureTextField(
        validate=validate.Length(max=2000)
    )

class PasswordChangeSchema(Schema):
    """Password change validation schema"""
    
    current_password = fields.String(required=True)
    
    new_password = fields.String(
        required=True,
        validate=[
            validate.Length(min=8, max=128),
            validate.Regexp(
                r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]',
                error="Password must contain uppercase, lowercase, number, and special character"
            )
        ]
    )
    
    confirm_password = fields.String(required=True)
    
    @validates_schema
    def validate_passwords_match(self, data, **kwargs):
        """Ensure new password and confirmation match"""
        if data.get('new_password') != data.get('confirm_password'):
            raise ValidationError("New passwords do not match")

def validate_request_data(schema_class, data):
    """Helper function to validate request data"""
    try:
        schema = schema_class()
        result = schema.load(data)
        return result, None
    except ValidationError as e:
        return None, e.messages

def sanitize_user_input(data):
    """General purpose input sanitization"""
    if isinstance(data, str):
        # HTML escape
        data = html.escape(data)
        # Basic XSS prevention
        data = re.sub(r'<script[^>]*>.*?</script>', '', data, flags=re.IGNORECASE | re.DOTALL)
        data = re.sub(r'javascript:', '', data, flags=re.IGNORECASE)
        data = re.sub(r'on\w+\s*=', '', data, flags=re.IGNORECASE)
    
    elif isinstance(data, dict):
        return {key: sanitize_user_input(value) for key, value in data.items()}
    
    elif isinstance(data, list):
        return [sanitize_user_input(item) for item in data]
    
    return data 