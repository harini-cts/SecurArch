# API Specification - SecureArch Portal

## 1. API Overview

### 1.1 Base URL and Versioning

```
Production: https://api.securearch.com/v1
Staging: https://staging-api.securearch.com/v1
Development: https://dev-api.securearch.com/v1
```

### 1.2 API Design Principles

- **RESTful**: Follow REST architectural principles
- **Resource-based**: URLs represent resources, not actions
- **Stateless**: Each request contains all necessary information
- **Consistent**: Uniform interface across all endpoints
- **Versioned**: Support multiple API versions simultaneously
- **Secure**: Authentication and authorization on all endpoints

### 1.3 Content Types

```
Request Content-Type: application/json
Response Content-Type: application/json
File Upload: multipart/form-data
```

## 2. Authentication & Authorization

### 2.1 Authentication Flow

```typescript
// JWT Token Structure
interface JWTPayload {
  sub: string;           // User ID
  email: string;         // User email
  org_id: string;        // Organization ID
  role: string;          // User role
  permissions: string[]; // Specific permissions
  iat: number;          // Issued at
  exp: number;          // Expires at
  jti: string;          // JWT ID
}

// Authentication Headers
Authorization: Bearer <jwt_token>
X-Organization-ID: <organization_id>
X-Request-ID: <unique_request_id>
```

### 2.2 Authentication Endpoints

#### POST /auth/login
```yaml
Description: Authenticate user and receive tokens
Content-Type: application/json

Request:
  email: string (required)
  password: string (required)
  remember_me: boolean (optional, default: false)
  mfa_code: string (optional, required if MFA enabled)

Response (200):
  access_token: string
  refresh_token: string
  token_type: "Bearer"
  expires_in: number (seconds)
  user:
    id: string
    email: string
    first_name: string
    last_name: string
    role: string
    organization_id: string
    permissions: string[]

Errors:
  400: Invalid request format
  401: Invalid credentials
  403: Account locked or disabled
  429: Too many login attempts
```

#### POST /auth/refresh
```yaml
Description: Refresh access token using refresh token
Content-Type: application/json

Request:
  refresh_token: string (required)

Response (200):
  access_token: string
  token_type: "Bearer"
  expires_in: number

Errors:
  400: Invalid refresh token
  401: Refresh token expired
```

#### POST /auth/logout
```yaml
Description: Logout and invalidate tokens
Authorization: Required

Request: {}

Response (204): No content

Errors:
  401: Invalid or expired token
```

## 3. Core API Endpoints

### 3.1 User Management

#### GET /users/profile
```yaml
Description: Get current user profile
Authorization: Required

Response (200):
  id: string
  email: string
  first_name: string
  last_name: string
  title: string
  phone: string
  avatar_url: string
  role: string
  organization_id: string
  specializations: string[]
  certifications: string[]
  timezone: string
  language: string
  notification_preferences: object
  two_factor_enabled: boolean
  last_login_at: string (ISO 8601)
  created_at: string (ISO 8601)
```

#### PUT /users/profile
```yaml
Description: Update user profile
Authorization: Required
Content-Type: application/json

Request:
  first_name: string (optional)
  last_name: string (optional)
  title: string (optional)
  phone: string (optional)
  timezone: string (optional)
  language: string (optional)
  notification_preferences: object (optional)

Response (200):
  # Updated user object (same as GET /users/profile)

Errors:
  400: Invalid request data
  401: Unauthorized
  422: Validation errors
```

#### GET /users
```yaml
Description: List organization users (admin only)
Authorization: Required (admin role)
Query Parameters:
  page: number (default: 1)
  limit: number (default: 20, max: 100)
  role: string (optional filter)
  search: string (optional, search by name/email)
  sort: string (optional, default: "created_at:desc")

Response (200):
  data: User[]
  pagination:
    page: number
    limit: number
    total: number
    total_pages: number
    has_next: boolean
    has_prev: boolean

Errors:
  401: Unauthorized
  403: Insufficient permissions
```

### 3.2 Review Management

#### POST /reviews
```yaml
Description: Create new architecture review
Authorization: Required
Content-Type: application/json

Request:
  title: string (required, max: 255)
  description: string (optional)
  project_type: enum (required) # 'web_app', 'mobile_app', 'api', 'infrastructure'
  business_criticality: enum (required) # 'low', 'medium', 'high', 'critical'
  target_asvs_level: number (required) # 1, 2, or 3
  technology_stack: object (optional)
    frontend: string[]
    backend: string[]
    database: string[]
    cloud: string[]
    other: string[]
  compliance_requirements: string[] (optional)
  security_requirements: string[] (optional)
  due_date: string (optional, ISO 8601)
  tags: string[] (optional)

Response (201):
  id: string
  title: string
  status: "submitted"
  created_at: string (ISO 8601)
  submission_url: string # URL to upload documents

Errors:
  400: Invalid request format
  401: Unauthorized
  422: Validation errors
  429: Rate limit exceeded
```

#### GET /reviews
```yaml
Description: List reviews
Authorization: Required
Query Parameters:
  page: number (default: 1)
  limit: number (default: 20, max: 100)
  status: string (optional filter)
  priority: string (optional filter)
  assigned_to: string (optional, user ID filter)
  submitter: string (optional, user ID filter)
  created_after: string (optional, ISO 8601)
  created_before: string (optional, ISO 8601)
  search: string (optional, search title/description)
  sort: string (optional, default: "created_at:desc")

Response (200):
  data: ReviewSummary[]
  pagination: PaginationInfo
  filters:
    available_statuses: string[]
    available_priorities: string[]

ReviewSummary:
  id: string
  title: string
  status: string
  priority: string
  business_criticality: string
  target_asvs_level: number
  overall_score: number (optional)
  risk_level: string (optional)
  submitter:
    id: string
    name: string
    email: string
  assigned_expert:
    id: string
    name: string
    email: string
  due_date: string (optional, ISO 8601)
  created_at: string (ISO 8601)
  updated_at: string (ISO 8601)
```

#### GET /reviews/{id}
```yaml
Description: Get detailed review information
Authorization: Required
Path Parameters:
  id: string (required, review UUID)

Response (200):
  id: string
  title: string
  description: string
  project_type: string
  business_criticality: string
  target_asvs_level: number
  actual_asvs_level: number (optional)
  status: string
  priority: string
  
  # Relationships
  submitter: UserSummary
  organization: OrganizationSummary
  assigned_expert: UserSummary (optional)
  
  # Configuration
  technology_stack: object
  compliance_requirements: string[]
  security_requirements: string[]
  
  # Timeline
  submitted_at: string (ISO 8601)
  assigned_at: string (optional, ISO 8601)
  review_started_at: string (optional, ISO 8601)
  completed_at: string (optional, ISO 8601)
  due_date: string (optional, ISO 8601)
  
  # Assessment
  overall_score: number (optional)
  risk_level: string (optional)
  
  # Documents and findings counts
  documents_count: number
  findings_count: number
  high_risk_findings: number
  medium_risk_findings: number
  low_risk_findings: number
  
  # Metadata
  tags: string[]
  external_references: object
  
  created_at: string (ISO 8601)
  updated_at: string (ISO 8601)

Errors:
  401: Unauthorized
  403: Insufficient permissions
  404: Review not found
```

#### PUT /reviews/{id}
```yaml
Description: Update review (limited fields)
Authorization: Required (owner or admin)
Path Parameters:
  id: string (required, review UUID)
Content-Type: application/json

Request:
  title: string (optional)
  description: string (optional)
  priority: enum (optional) # 'low', 'normal', 'high', 'urgent'
  due_date: string (optional, ISO 8601)
  tags: string[] (optional)

Response (200):
  # Updated review object (same as GET /reviews/{id})

Errors:
  400: Invalid request format
  401: Unauthorized
  403: Insufficient permissions
  404: Review not found
  422: Validation errors
```

#### POST /reviews/{id}/assign
```yaml
Description: Assign expert to review (admin/expert role)
Authorization: Required (admin or expert with assignment permissions)
Path Parameters:
  id: string (required, review UUID)
Content-Type: application/json

Request:
  expert_id: string (required, user UUID)
  assignment_reason: string (optional)
  estimated_hours: number (optional)

Response (200):
  message: "Expert assigned successfully"
  assignment:
    expert: UserSummary
    assigned_at: string (ISO 8601)
    estimated_hours: number

Errors:
  400: Invalid expert ID
  401: Unauthorized
  403: Insufficient permissions
  404: Review not found
  409: Review already assigned or invalid status
```

### 3.3 Document Management

#### POST /reviews/{id}/documents
```yaml
Description: Upload architecture documents
Authorization: Required (review owner or assigned expert)
Path Parameters:
  id: string (required, review UUID)
Content-Type: multipart/form-data

Request:
  files: File[] (required, max 10 files)
  document_type: enum (required) # 'architecture', 'threat_model', 'requirements', 'supporting'
  description: string (optional)

Response (201):
  uploaded_documents: UploadedDocument[]

UploadedDocument:
  id: string
  filename: string
  file_size: number
  mime_type: string
  document_type: string
  processing_status: "pending"
  uploaded_at: string (ISO 8601)

Errors:
  400: Invalid file format or size
  401: Unauthorized
  403: Insufficient permissions
  404: Review not found
  413: File too large
  415: Unsupported media type
  422: Validation errors
```

#### GET /reviews/{id}/documents
```yaml
Description: List review documents
Authorization: Required
Path Parameters:
  id: string (required, review UUID)

Response (200):
  documents: Document[]

Document:
  id: string
  filename: string
  original_filename: string
  file_size: number
  mime_type: string
  document_type: string
  document_category: string
  version: string
  page_count: number (optional)
  processing_status: string
  uploaded_by: UserSummary
  uploaded_at: string (ISO 8601)
  download_url: string (optional, if user has access)

Errors:
  401: Unauthorized
  403: Insufficient permissions
  404: Review not found
```

#### GET /documents/{id}/download
```yaml
Description: Download document file
Authorization: Required
Path Parameters:
  id: string (required, document UUID)

Response (200):
  Content-Type: <original mime type>
  Content-Disposition: attachment; filename="<original filename>"
  Content-Length: <file size>
  # File content as binary stream

Errors:
  401: Unauthorized
  403: Insufficient permissions
  404: Document not found
```

### 3.4 Security Findings

#### GET /reviews/{id}/findings
```yaml
Description: List security findings for review
Authorization: Required
Path Parameters:
  id: string (required, review UUID)
Query Parameters:
  risk_level: string[] (optional filter)
  status: string[] (optional filter)
  owasp_category: string[] (optional filter)
  assigned_to: string (optional, user ID filter)
  sort: string (optional, default: "risk_score:desc")

Response (200):
  findings: Finding[]
  summary:
    total_count: number
    by_risk_level:
      critical: number
      high: number
      medium: number
      low: number
      info: number
    by_status:
      open: number
      in_progress: number
      resolved: number
      accepted_risk: number

Finding:
  id: string
  finding_number: string # H1, M2, L3, etc.
  title: string
  risk_level: string
  risk_score: number
  owasp_top10_category: string
  affected_components: string[]
  status: string
  identified_by: UserSummary
  assigned_to: UserSummary (optional)
  created_at: string (ISO 8601)
  due_date: string (optional, ISO 8601)
```

#### POST /reviews/{id}/findings
```yaml
Description: Create new security finding (expert only)
Authorization: Required (expert role)
Path Parameters:
  id: string (required, review UUID)
Content-Type: application/json

Request:
  title: string (required, max: 255)
  description: string (required)
  risk_level: enum (required) # 'info', 'low', 'medium', 'high', 'critical'
  likelihood: enum (optional) # 'unlikely', 'possible', 'likely', 'almost_certain'
  impact: enum (optional) # 'negligible', 'minor', 'moderate', 'major', 'catastrophic'
  owasp_top10_category: string (optional) # 'A01', 'A02', etc.
  asvs_references: string[] (optional)
  cwe_references: string[] (optional)
  affected_components: string[] (required)
  technical_details: string (optional)
  remediation_guidance: string (required)
  remediation_priority: enum (optional) # 'low', 'medium', 'high', 'critical'
  short_term_mitigation: string (optional)
  long_term_solution: string (optional)
  tags: string[] (optional)

Response (201):
  id: string
  finding_number: string
  title: string
  risk_level: string
  status: "open"
  created_at: string (ISO 8601)

Errors:
  400: Invalid request format
  401: Unauthorized
  403: Insufficient permissions
  404: Review not found
  422: Validation errors
```

#### GET /findings/{id}
```yaml
Description: Get detailed finding information
Authorization: Required
Path Parameters:
  id: string (required, finding UUID)

Response (200):
  id: string
  review_id: string
  finding_number: string
  title: string
  description: string
  
  # Risk assessment
  risk_level: string
  risk_score: number
  likelihood: string
  impact: string
  
  # Classifications
  owasp_top10_category: string
  asvs_references: string[]
  cwe_references: string[]
  capec_references: string[]
  
  # Technical details
  affected_components: string[]
  attack_vectors: string[]
  prerequisites: string[]
  technical_details: string
  proof_of_concept: string
  
  # Remediation
  remediation_guidance: string
  remediation_priority: string
  remediation_effort: string
  remediation_cost: string
  short_term_mitigation: string
  long_term_solution: string
  
  # Status and assignment
  status: string
  identified_by: UserSummary
  assigned_to: UserSummary (optional)
  verified_by: UserSummary (optional)
  
  # Timeline
  identified_at: string (ISO 8601)
  due_date: string (optional, ISO 8601)
  resolved_at: string (optional, ISO 8601)
  verified_at: string (optional, ISO 8601)
  
  # Metadata
  tags: string[]
  external_references: object
  attachments_count: number
  
  created_at: string (ISO 8601)
  updated_at: string (ISO 8601)
```

### 3.5 OWASP Assessment

#### GET /reviews/{id}/asvs-assessment
```yaml
Description: Get ASVS compliance assessment for review
Authorization: Required
Path Parameters:
  id: string (required, review UUID)

Response (200):
  review_id: string
  target_level: number
  overall_score: number
  category_scores:
    V1:
      category_name: "Architecture, Design and Threat Modeling"
      score: number
      total_requirements: number
      compliant_requirements: number
      findings: Finding[]
    V2:
      category_name: "Authentication"
      # ... similar structure
    # ... all categories V1-V14
  
  recommendations:
    immediate: Recommendation[]
    short_term: Recommendation[]
    long_term: Recommendation[]
  
  next_steps: string[]
  assessed_at: string (ISO 8601)

Recommendation:
  requirement_id: string
  priority: string
  effort: string
  description: string
  implementation_guidance: string
```

#### GET /reviews/{id}/owasp-top10-risk
```yaml
Description: Get OWASP Top 10 risk assessment
Authorization: Required
Path Parameters:
  id: string (required, review UUID)

Response (200):
  review_id: string
  overall_risk: string # 'low', 'medium', 'high', 'critical'
  risk_score: number # 0-10
  category_assessments:
    A01:
      category: "Broken Access Control"
      risk_level: string
      risk_score: number
      likelihood: string
      impact: string
      findings_count: number
      mitigation_status: string
      recommendations: string[]
    A02:
      category: "Cryptographic Failures"
      # ... similar structure
    # ... all categories A01-A10
  
  trends:
    improving: string[] # categories getting better
    worsening: string[] # categories getting worse
    stable: string[]    # categories unchanged
  
  assessed_at: string (ISO 8601)
```

## 4. Analytics and Reporting

### 4.1 Dashboard APIs

#### GET /analytics/dashboard
```yaml
Description: Get dashboard analytics data
Authorization: Required
Query Parameters:
  period: enum (optional, default: "30d") # '7d', '30d', '90d', '1y'
  organization_id: string (optional, admin only)

Response (200):
  period: string
  summary:
    total_reviews: number
    active_reviews: number
    completed_reviews: number
    avg_completion_time_hours: number
    avg_score: number
  
  reviews_by_status:
    submitted: number
    queued: number
    in_progress: number
    expert_review: number
    completed: number
    rejected: number
  
  risk_distribution:
    critical: number
    high: number
    medium: number
    low: number
    info: number
  
  owasp_top10_trends:
    - category: "A01"
      findings_count: number
      trend: "increasing" | "decreasing" | "stable"
    # ... for all categories
  
  asvs_compliance:
    level_1: number # percentage
    level_2: number
    level_3: number
  
  expert_workload:
    - expert: UserSummary
      active_reviews: number
      avg_completion_time: number
      satisfaction_rating: number
  
  recent_activity: Activity[]

Activity:
  type: string
  description: string
  timestamp: string (ISO 8601)
  user: UserSummary
  related_review: ReviewSummary (optional)
```

### 4.2 Report Generation

#### POST /reports/generate
```yaml
Description: Generate custom reports
Authorization: Required
Content-Type: application/json

Request:
  report_type: enum (required) # 'compliance', 'executive', 'detailed', 'trend'
  format: enum (required) # 'pdf', 'excel', 'json'
  parameters:
    period_start: string (required, ISO 8601)
    period_end: string (required, ISO 8601)
    organization_id: string (optional, admin only)
    include_findings: boolean (optional, default: true)
    include_remediation: boolean (optional, default: true)
    group_by: string[] (optional) # 'risk_level', 'owasp_category', 'month'

Response (202):
  report_id: string
  status: "queued"
  estimated_completion: string (ISO 8601)
  download_url: string # URL to check status and download

Errors:
  400: Invalid parameters
  401: Unauthorized
  422: Validation errors
```

#### GET /reports/{id}/status
```yaml
Description: Check report generation status
Authorization: Required
Path Parameters:
  id: string (required, report UUID)

Response (200):
  report_id: string
  status: string # 'queued', 'processing', 'completed', 'failed'
  progress: number # 0-100
  estimated_completion: string (optional, ISO 8601)
  download_url: string (optional, available when completed)
  error_message: string (optional, if failed)
  created_at: string (ISO 8601)
  completed_at: string (optional, ISO 8601)
```

## 5. Integration APIs

### 5.1 Webhook Configuration

#### POST /webhooks
```yaml
Description: Create webhook endpoint
Authorization: Required (admin)
Content-Type: application/json

Request:
  url: string (required, valid HTTPS URL)
  events: string[] (required) # ['review.created', 'review.completed', 'finding.created']
  secret: string (optional, for signature verification)
  is_active: boolean (optional, default: true)

Response (201):
  id: string
  url: string
  events: string[]
  secret: string (masked)
  is_active: boolean
  created_at: string (ISO 8601)

Available Events:
  - review.created
  - review.assigned
  - review.completed
  - review.status_changed
  - finding.created
  - finding.resolved
  - finding.status_changed
  - user.assigned
```

### 5.2 CI/CD Integration

#### POST /integrations/cicd/scan
```yaml
Description: Trigger security scan from CI/CD pipeline
Authorization: Required (API key authentication)
Content-Type: application/json

Request:
  project_name: string (required)
  repository_url: string (optional)
  commit_hash: string (optional)
  branch: string (optional)
  architecture_files: string[] (required, file URLs or base64 content)
  scan_type: enum (optional, default: "quick") # 'quick', 'standard', 'comprehensive'
  callback_url: string (optional, webhook URL for results)

Response (202):
  scan_id: string
  status: "queued"
  estimated_completion: string (ISO 8601)
  results_url: string

Errors:
  400: Invalid request format
  401: Invalid API key
  422: Validation errors
  429: Rate limit exceeded
```

## 6. Error Handling

### 6.1 Standard Error Response

```typescript
interface ErrorResponse {
  error: {
    code: string;           // Machine-readable error code
    message: string;        // Human-readable error message
    details?: any;          // Additional error details
    timestamp: string;      // ISO 8601 timestamp
    request_id: string;     // Unique request identifier
    documentation_url?: string; // Link to relevant documentation
  };
}

// Example error responses
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Request validation failed",
    "details": {
      "field_errors": {
        "email": ["Email address is required"],
        "password": ["Password must be at least 8 characters"]
      }
    },
    "timestamp": "2024-01-15T10:30:00Z",
    "request_id": "req_1234567890abcdef",
    "documentation_url": "https://docs.securearch.com/api/errors#validation"
  }
}
```

### 6.2 HTTP Status Codes

| Code | Description | Usage |
|------|-------------|-------|
| 200 | OK | Successful GET, PUT requests |
| 201 | Created | Successful POST requests |
| 202 | Accepted | Async processing started |
| 204 | No Content | Successful DELETE requests |
| 400 | Bad Request | Invalid request format |
| 401 | Unauthorized | Missing or invalid authentication |
| 403 | Forbidden | Insufficient permissions |
| 404 | Not Found | Resource doesn't exist |
| 409 | Conflict | Resource state conflict |
| 413 | Payload Too Large | File upload too large |
| 415 | Unsupported Media Type | Invalid file format |
| 422 | Unprocessable Entity | Validation errors |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Server Error | Server-side error |
| 503 | Service Unavailable | Temporary unavailability |

## 7. Rate Limiting

### 7.1 Rate Limit Headers

```
X-RateLimit-Limit: 1000        # Requests per hour
X-RateLimit-Remaining: 999     # Remaining requests
X-RateLimit-Reset: 1641975600  # Reset timestamp (Unix)
X-RateLimit-Scope: user        # user, organization, global
```

### 7.2 Rate Limit Tiers

| Endpoint Category | Limit | Scope |
|------------------|-------|-------|
| Authentication | 10/minute | IP address |
| File Upload | 5/15 minutes | User |
| API Calls | 1000/hour | User |
| Report Generation | 5/hour | Organization |
| Webhook Delivery | 100/minute | Endpoint |

This comprehensive API specification provides a solid foundation for integrating with the SecureArch Portal, ensuring consistent, secure, and scalable access to all platform functionality. 