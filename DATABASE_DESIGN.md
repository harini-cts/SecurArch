# Database Design - SecureArch Portal

## 1. Database Architecture Overview

### 1.1 Multi-Database Strategy

```
┌─────────────────────────────────────────────────────────────────┐
│                    Database Architecture                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │   PostgreSQL    │  │      Redis      │  │ Elasticsearch   │ │
│  │  (Primary DB)   │  │   (Cache/Session)  │  (Search/Analytics) │ │
│  │                 │  │                 │  │                 │ │
│  │ • User Data     │  │ • User Sessions │  │ • Document Index│ │
│  │ • Reviews       │  │ • Rate Limiting │  │ • Search Data   │ │
│  │ • Findings      │  │ • Temp Storage  │  │ • Audit Logs    │ │
│  │ • OWASP Data    │  │ • Cache         │  │ • Analytics     │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
│                                                                 │
│  ┌─────────────────┐  ┌─────────────────┐                     │
│  │   File Storage  │  │  Message Queue  │                     │
│  │   (AWS S3/Blob) │  │ (RabbitMQ/SQS)  │                     │
│  │                 │  │                 │                     │
│  │ • Documents     │  │ • Async Tasks   │                     │
│  │ • Reports       │  │ • Notifications │                     │
│  │ • Templates     │  │ • Analysis Jobs │                     │
│  └─────────────────┘  └─────────────────┘                     │
└─────────────────────────────────────────────────────────────────┘
```

### 1.2 Database Selection Rationale

| Database | Use Case | Justification |
|----------|----------|---------------|
| PostgreSQL | Primary OLTP | ACID compliance, JSON support, complex queries |
| Redis | Caching/Sessions | High performance, TTL support, data structures |
| Elasticsearch | Search/Analytics | Full-text search, aggregations, scalability |
| S3/Blob Storage | File Storage | Cost-effective, scalable, integrated with cloud |

## 2. PostgreSQL Schema Design

### 2.1 Core Tables

#### 2.1.1 User Management

```sql
-- Organizations table
CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) UNIQUE NOT NULL,
    domain VARCHAR(255),
    industry VARCHAR(100),
    size VARCHAR(50), -- 'startup', 'small', 'medium', 'large', 'enterprise'
    subscription_type VARCHAR(50) DEFAULT 'basic',
    subscription_expires_at TIMESTAMP WITH TIME ZONE,
    settings JSONB DEFAULT '{}',
    billing_settings JSONB DEFAULT '{}',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Users table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255),
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    title VARCHAR(100),
    phone VARCHAR(20),
    avatar_url VARCHAR(500),
    role VARCHAR(50) DEFAULT 'user', -- 'admin', 'expert', 'user', 'viewer'
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    specializations TEXT[], -- for experts: ['web', 'mobile', 'cloud', 'iot']
    certifications TEXT[], -- security certifications
    experience_years INTEGER,
    timezone VARCHAR(50) DEFAULT 'UTC',
    language VARCHAR(10) DEFAULT 'en',
    notification_preferences JSONB DEFAULT '{}',
    two_factor_enabled BOOLEAN DEFAULT FALSE,
    two_factor_secret VARCHAR(255),
    email_verified BOOLEAN DEFAULT FALSE,
    email_verification_token VARCHAR(255),
    password_reset_token VARCHAR(255),
    password_reset_expires TIMESTAMP WITH TIME ZONE,
    last_login_at TIMESTAMP WITH TIME ZONE,
    login_count INTEGER DEFAULT 0,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- User roles and permissions
CREATE TABLE roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    permissions TEXT[] NOT NULL,
    is_system_role BOOLEAN DEFAULT FALSE,
    organization_id UUID REFERENCES organizations(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE user_roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
    granted_by UUID REFERENCES users(id),
    granted_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE,
    UNIQUE(user_id, role_id)
);
```

#### 2.1.2 Review Management

```sql
-- Architecture reviews
CREATE TABLE reviews (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title VARCHAR(255) NOT NULL,
    description TEXT,
    project_type VARCHAR(100) NOT NULL, -- 'web_app', 'mobile_app', 'api', 'infrastructure'
    business_criticality VARCHAR(50) NOT NULL, -- 'low', 'medium', 'high', 'critical'
    target_asvs_level INTEGER DEFAULT 2 CHECK (target_asvs_level IN (1, 2, 3)),
    actual_asvs_level INTEGER CHECK (actual_asvs_level IN (1, 2, 3)),
    status VARCHAR(50) DEFAULT 'submitted', -- 'submitted', 'queued', 'in_progress', 'expert_review', 'completed', 'rejected'
    priority VARCHAR(20) DEFAULT 'normal', -- 'low', 'normal', 'high', 'urgent'
    
    -- Relationships
    submitter_id UUID NOT NULL REFERENCES users(id),
    organization_id UUID NOT NULL REFERENCES organizations(id),
    assigned_expert_id UUID REFERENCES users(id),
    reviewer_id UUID REFERENCES users(id), -- QA reviewer
    
    -- Technology and requirements
    technology_stack JSONB DEFAULT '{}',
    compliance_requirements TEXT[],
    security_requirements TEXT[],
    business_requirements TEXT[],
    
    -- Timeline and SLA
    submitted_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    assigned_at TIMESTAMP WITH TIME ZONE,
    review_started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    due_date TIMESTAMP WITH TIME ZONE,
    estimated_hours INTEGER,
    actual_hours DECIMAL(5,2),
    
    -- Scoring and assessment
    overall_score DECIMAL(5,2),
    risk_level VARCHAR(20), -- 'low', 'medium', 'high', 'critical'
    
    -- Metadata
    tags TEXT[],
    external_references JSONB DEFAULT '{}', -- links to Jira, Confluence, etc.
    client_feedback_rating INTEGER CHECK (client_feedback_rating BETWEEN 1 AND 5),
    client_feedback_notes TEXT,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Review documents
CREATE TABLE review_documents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    review_id UUID NOT NULL REFERENCES reviews(id) ON DELETE CASCADE,
    filename VARCHAR(255) NOT NULL,
    original_filename VARCHAR(255) NOT NULL,
    file_path VARCHAR(500) NOT NULL,
    file_size BIGINT NOT NULL,
    mime_type VARCHAR(100) NOT NULL,
    checksum VARCHAR(64), -- SHA-256 hash
    document_type VARCHAR(50) NOT NULL, -- 'architecture', 'threat_model', 'requirements', 'supporting'
    document_category VARCHAR(50), -- 'diagram', 'specification', 'design', 'analysis'
    version VARCHAR(20) DEFAULT '1.0',
    page_count INTEGER,
    
    -- Processing status
    processing_status VARCHAR(50) DEFAULT 'pending', -- 'pending', 'processing', 'completed', 'failed'
    ocr_text TEXT, -- extracted text content
    parsed_metadata JSONB DEFAULT '{}',
    
    uploaded_by UUID NOT NULL REFERENCES users(id),
    uploaded_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    processed_at TIMESTAMP WITH TIME ZONE
);

-- Review timeline and status changes
CREATE TABLE review_status_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    review_id UUID NOT NULL REFERENCES reviews(id) ON DELETE CASCADE,
    previous_status VARCHAR(50),
    new_status VARCHAR(50) NOT NULL,
    changed_by UUID NOT NULL REFERENCES users(id),
    change_reason TEXT,
    metadata JSONB DEFAULT '{}',
    changed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Review assignments and workload
CREATE TABLE review_assignments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    review_id UUID NOT NULL REFERENCES reviews(id) ON DELETE CASCADE,
    expert_id UUID NOT NULL REFERENCES users(id),
    assignment_type VARCHAR(50) NOT NULL, -- 'primary', 'secondary', 'consultant'
    assigned_by UUID NOT NULL REFERENCES users(id),
    assignment_reason TEXT,
    estimated_hours DECIMAL(5,2),
    actual_hours DECIMAL(5,2),
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    status VARCHAR(50) DEFAULT 'assigned' -- 'assigned', 'accepted', 'in_progress', 'completed', 'declined'
);
```

#### 2.1.3 OWASP Standards Data

```sql
-- OWASP ASVS requirements
CREATE TABLE asvs_requirements (
    id VARCHAR(20) PRIMARY KEY, -- e.g., 'v4.0.3-1.1.1'
    version VARCHAR(10) NOT NULL,
    level INTEGER NOT NULL CHECK (level IN (1, 2, 3)),
    category_number INTEGER NOT NULL,
    category_name VARCHAR(100) NOT NULL,
    subcategory VARCHAR(100),
    requirement_number VARCHAR(10) NOT NULL,
    requirement TEXT NOT NULL,
    verification_guidance TEXT,
    since_version VARCHAR(10),
    cwe_references TEXT[],
    nist_references TEXT[],
    implementation_guidance TEXT,
    testing_guidance TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    UNIQUE(version, category_number, requirement_number)
);

-- OWASP Top 10 data
CREATE TABLE owasp_top10 (
    id VARCHAR(10) PRIMARY KEY, -- e.g., 'A01-2021'
    year INTEGER NOT NULL,
    rank INTEGER NOT NULL,
    category_id VARCHAR(10) NOT NULL, -- 'A01', 'A02', etc.
    title VARCHAR(200) NOT NULL,
    description TEXT NOT NULL,
    overview TEXT,
    prevalence VARCHAR(20),
    detectability VARCHAR(20),
    impact VARCHAR(20),
    cwe_mapping TEXT[],
    prevention_methods TEXT[],
    example_attack_scenarios TEXT[],
    references TEXT[],
    is_current BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    UNIQUE(year, rank),
    UNIQUE(year, category_id)
);

-- OWASP Proactive Controls
CREATE TABLE proactive_controls (
    id VARCHAR(10) PRIMARY KEY, -- e.g., 'C1-2024'
    version VARCHAR(10) NOT NULL,
    control_number INTEGER NOT NULL,
    title VARCHAR(200) NOT NULL,
    description TEXT NOT NULL,
    objective TEXT,
    implementation_guidance TEXT,
    owasp_top10_prevention TEXT[],
    asvs_mapping TEXT[],
    tools_and_frameworks TEXT[],
    references TEXT[],
    is_current BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    UNIQUE(version, control_number)
);

-- ASVS compliance tracking
CREATE TABLE asvs_assessments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    review_id UUID NOT NULL REFERENCES reviews(id) ON DELETE CASCADE,
    requirement_id VARCHAR(20) NOT NULL REFERENCES asvs_requirements(id),
    status VARCHAR(20) NOT NULL, -- 'compliant', 'non_compliant', 'not_applicable', 'needs_verification'
    compliance_level VARCHAR(20), -- 'full', 'partial', 'none'
    evidence TEXT,
    evidence_documents TEXT[], -- file paths or document IDs
    assessor_notes TEXT,
    verification_method VARCHAR(50), -- 'automated', 'manual', 'document_review', 'expert_assessment'
    confidence_level VARCHAR(20) DEFAULT 'medium', -- 'low', 'medium', 'high'
    
    assessed_by UUID REFERENCES users(id),
    assessed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    verified_by UUID REFERENCES users(id),
    verified_at TIMESTAMP WITH TIME ZONE,
    
    UNIQUE(review_id, requirement_id)
);
```

#### 2.1.4 Security Findings

```sql
-- Security findings and vulnerabilities
CREATE TABLE security_findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    review_id UUID NOT NULL REFERENCES reviews(id) ON DELETE CASCADE,
    finding_number VARCHAR(20) NOT NULL, -- H1, M1, L1, etc.
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    
    -- Risk assessment
    risk_level VARCHAR(20) NOT NULL, -- 'info', 'low', 'medium', 'high', 'critical'
    risk_score DECIMAL(3,1) CHECK (risk_score BETWEEN 0.0 AND 10.0),
    likelihood VARCHAR(20), -- 'unlikely', 'possible', 'likely', 'almost_certain'
    impact VARCHAR(20), -- 'negligible', 'minor', 'moderate', 'major', 'catastrophic'
    
    -- OWASP mappings
    owasp_top10_category VARCHAR(10), -- 'A01', 'A02', etc.
    asvs_references TEXT[],
    cwe_references TEXT[],
    capec_references TEXT[],
    
    -- Technical details
    affected_components TEXT[] NOT NULL,
    attack_vectors TEXT[],
    prerequisites TEXT[],
    technical_details TEXT,
    proof_of_concept TEXT,
    
    -- Remediation
    remediation_guidance TEXT NOT NULL,
    remediation_priority VARCHAR(20) DEFAULT 'medium', -- 'low', 'medium', 'high', 'critical'
    remediation_effort VARCHAR(20), -- 'trivial', 'minor', 'moderate', 'major', 'extreme'
    remediation_cost VARCHAR(20), -- 'low', 'medium', 'high'
    short_term_mitigation TEXT,
    long_term_solution TEXT,
    
    -- Status tracking
    status VARCHAR(50) DEFAULT 'open', -- 'open', 'in_progress', 'resolved', 'accepted_risk', 'false_positive'
    resolution_notes TEXT,
    retest_required BOOLEAN DEFAULT FALSE,
    retest_notes TEXT,
    
    -- Assignment and tracking
    identified_by UUID REFERENCES users(id),
    assigned_to UUID REFERENCES users(id),
    verified_by UUID REFERENCES users(id),
    
    -- External references
    external_references JSONB DEFAULT '{}',
    tags TEXT[],
    
    -- Timestamps
    identified_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    due_date TIMESTAMP WITH TIME ZONE,
    resolved_at TIMESTAMP WITH TIME ZONE,
    verified_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    UNIQUE(review_id, finding_number)
);

-- Finding attachments and evidence
CREATE TABLE finding_attachments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID NOT NULL REFERENCES security_findings(id) ON DELETE CASCADE,
    filename VARCHAR(255) NOT NULL,
    file_path VARCHAR(500) NOT NULL,
    file_size BIGINT NOT NULL,
    mime_type VARCHAR(100) NOT NULL,
    attachment_type VARCHAR(50) NOT NULL, -- 'evidence', 'screenshot', 'log', 'report'
    description TEXT,
    uploaded_by UUID NOT NULL REFERENCES users(id),
    uploaded_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Finding status history
CREATE TABLE finding_status_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID NOT NULL REFERENCES security_findings(id) ON DELETE CASCADE,
    previous_status VARCHAR(50),
    new_status VARCHAR(50) NOT NULL,
    changed_by UUID NOT NULL REFERENCES users(id),
    change_reason TEXT,
    metadata JSONB DEFAULT '{}',
    changed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

#### 2.1.5 Analysis and Automation

```sql
-- Automated analysis results
CREATE TABLE analysis_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    review_id UUID NOT NULL REFERENCES reviews(id) ON DELETE CASCADE,
    analysis_type VARCHAR(50) NOT NULL, -- 'document_parsing', 'pattern_matching', 'ml_analysis'
    engine_version VARCHAR(20) NOT NULL,
    
    -- Overall scoring
    overall_score DECIMAL(5,2),
    confidence_score DECIMAL(3,2) CHECK (confidence_score BETWEEN 0.0 AND 1.0),
    
    -- OWASP scoring breakdown
    asvs_level_1_score DECIMAL(5,2),
    asvs_level_2_score DECIMAL(5,2),
    asvs_level_3_score DECIMAL(5,2),
    owasp_top10_scores JSONB DEFAULT '{}',
    proactive_controls_scores JSONB DEFAULT '{}',
    
    -- Analysis details
    components_identified JSONB DEFAULT '{}',
    patterns_detected JSONB DEFAULT '{}',
    risk_factors JSONB DEFAULT '{}',
    recommendations TEXT[],
    
    -- Processing metadata
    processing_time_seconds INTEGER,
    resources_analyzed JSONB DEFAULT '{}',
    errors_encountered JSONB DEFAULT '{}',
    
    started_at TIMESTAMP WITH TIME ZONE NOT NULL,
    completed_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Pattern recognition rules
CREATE TABLE analysis_patterns (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(200) NOT NULL,
    pattern_type VARCHAR(50) NOT NULL, -- 'regex', 'keyword', 'semantic', 'visual'
    category VARCHAR(100) NOT NULL, -- OWASP category or security domain
    
    -- Pattern definition
    pattern_data JSONB NOT NULL, -- stores pattern rules, keywords, etc.
    search_scope TEXT[] NOT NULL, -- 'document_text', 'diagram_elements', 'metadata'
    
    -- Scoring and weighting
    confidence_weight DECIMAL(3,2) DEFAULT 1.0,
    risk_impact DECIMAL(3,2) DEFAULT 1.0,
    
    -- OWASP mappings
    owasp_categories TEXT[],
    asvs_requirements TEXT[],
    cwe_mappings TEXT[],
    
    -- Status and versioning
    version VARCHAR(20) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    effectiveness_rating DECIMAL(3,2), -- based on expert feedback
    
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Machine learning training data
CREATE TABLE ml_training_data (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    review_id UUID REFERENCES reviews(id),
    document_id UUID REFERENCES review_documents(id),
    
    -- Training labels
    security_classification JSONB NOT NULL,
    expert_annotations JSONB NOT NULL,
    ground_truth_labels JSONB NOT NULL,
    
    -- Feature extraction
    extracted_features JSONB NOT NULL,
    document_embeddings BYTEA, -- Vector embeddings
    
    -- Quality metrics
    annotation_quality DECIMAL(3,2),
    annotated_by UUID REFERENCES users(id),
    verified_by UUID REFERENCES users(id),
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

### 2.2 Advanced Features

#### 2.2.1 Audit and Compliance

```sql
-- Audit trail
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    table_name VARCHAR(100) NOT NULL,
    record_id UUID NOT NULL,
    operation VARCHAR(20) NOT NULL, -- 'INSERT', 'UPDATE', 'DELETE'
    old_values JSONB,
    new_values JSONB,
    changed_fields TEXT[],
    
    -- User context
    user_id UUID REFERENCES users(id),
    user_ip INET,
    user_agent TEXT,
    session_id VARCHAR(255),
    
    -- Request context
    request_id UUID,
    api_endpoint VARCHAR(255),
    http_method VARCHAR(10),
    
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Indexing for performance
    INDEX idx_audit_table_record (table_name, record_id),
    INDEX idx_audit_user_time (user_id, timestamp),
    INDEX idx_audit_timestamp (timestamp)
);

-- Compliance tracking
CREATE TABLE compliance_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id),
    report_type VARCHAR(50) NOT NULL, -- 'asvs', 'top10', 'custom'
    report_period_start DATE NOT NULL,
    report_period_end DATE NOT NULL,
    
    -- Compliance metrics
    total_reviews INTEGER NOT NULL,
    compliant_reviews INTEGER NOT NULL,
    compliance_percentage DECIMAL(5,2) NOT NULL,
    
    -- Detailed breakdown
    compliance_by_level JSONB NOT NULL,
    findings_summary JSONB NOT NULL,
    risk_distribution JSONB NOT NULL,
    trends JSONB,
    
    -- Report metadata
    generated_by UUID NOT NULL REFERENCES users(id),
    report_data JSONB NOT NULL,
    file_path VARCHAR(500), -- PDF report location
    
    generated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

#### 2.2.2 Performance Optimization

```sql
-- Indexes for performance
CREATE INDEX CONCURRENTLY idx_reviews_org_status ON reviews(organization_id, status);
CREATE INDEX CONCURRENTLY idx_reviews_assigned_expert ON reviews(assigned_expert_id) WHERE assigned_expert_id IS NOT NULL;
CREATE INDEX CONCURRENTLY idx_reviews_created_at ON reviews(created_at);
CREATE INDEX CONCURRENTLY idx_reviews_due_date ON reviews(due_date) WHERE due_date IS NOT NULL;

CREATE INDEX CONCURRENTLY idx_findings_review_risk ON security_findings(review_id, risk_level);
CREATE INDEX CONCURRENTLY idx_findings_status ON security_findings(status);
CREATE INDEX CONCURRENTLY idx_findings_owasp_category ON security_findings(owasp_top10_category);

CREATE INDEX CONCURRENTLY idx_asvs_assessments_review ON asvs_assessments(review_id);
CREATE INDEX CONCURRENTLY idx_asvs_assessments_requirement ON asvs_assessments(requirement_id);

CREATE INDEX CONCURRENTLY idx_users_org_role ON users(organization_id, role);
CREATE INDEX CONCURRENTLY idx_users_email_active ON users(email) WHERE is_active = TRUE;

-- Partitioning strategy for large tables
CREATE TABLE audit_logs_y2024m01 PARTITION OF audit_logs 
FOR VALUES FROM ('2024-01-01') TO ('2024-02-01');

-- Materialized views for analytics
CREATE MATERIALIZED VIEW review_analytics AS
SELECT 
    DATE_TRUNC('month', created_at) as month,
    organization_id,
    status,
    COUNT(*) as review_count,
    AVG(overall_score) as avg_score,
    AVG(EXTRACT(EPOCH FROM (completed_at - created_at))/3600) as avg_completion_hours
FROM reviews 
WHERE created_at >= CURRENT_DATE - INTERVAL '2 years'
GROUP BY DATE_TRUNC('month', created_at), organization_id, status;

CREATE UNIQUE INDEX ON review_analytics (month, organization_id, status);
```

## 3. Redis Cache Design

### 3.1 Cache Structure

```yaml
# Session Management
session:{user_id}:
  value: |
    {
      "user_id": "uuid",
      "email": "user@example.com",
      "role": "expert",
      "organization_id": "uuid",
      "permissions": ["review:read", "finding:create"],
      "last_activity": "2024-01-15T10:30:00Z"
    }
  ttl: 28800  # 8 hours

# Rate Limiting
rate_limit:api:{user_id}:
  value: 150  # requests made
  ttl: 3600   # per hour

rate_limit:upload:{user_id}:
  value: 5    # files uploaded
  ttl: 900    # per 15 minutes

# Review Caching
review:{review_id}:
  value: |
    {
      "id": "uuid",
      "title": "Banking API Review",
      "status": "in_progress",
      "score": 78.5,
      "findings_count": 12,
      "updated_at": "2024-01-15T10:30:00Z"
    }
  ttl: 3600   # 1 hour

# Analysis Results Caching
analysis:result:{review_id}:
  value: |
    {
      "overall_score": 78.5,
      "asvs_scores": {"L1": 85, "L2": 75, "L3": 65},
      "owasp_risks": {"A01": "medium", "A02": "low"},
      "processing_status": "completed"
    }
  ttl: 7200   # 2 hours

# OWASP Data Caching
owasp:asvs:requirements:
  value: |
    [
      {"id": "v4.0.3-1.1.1", "requirement": "..."},
      {"id": "v4.0.3-1.1.2", "requirement": "..."}
    ]
  ttl: 604800  # 1 week

# Real-time Notifications
notifications:{user_id}:
  value: |
    [
      {
        "id": "uuid",
        "type": "review_assigned",
        "message": "New review assigned",
        "timestamp": "2024-01-15T10:30:00Z",
        "read": false
      }
    ]
  ttl: 86400   # 24 hours
```

### 3.2 Cache Invalidation Strategy

```python
class CacheManager:
    def __init__(self, redis_client):
        self.redis = redis_client
        
    async def invalidate_review_cache(self, review_id: str):
        """Invalidate all cache entries related to a review"""
        patterns = [
            f"review:{review_id}",
            f"analysis:result:{review_id}",
            f"findings:review:{review_id}",
            f"asvs:assessment:{review_id}"
        ]
        
        for pattern in patterns:
            await self.redis.delete(pattern)
    
    async def invalidate_user_cache(self, user_id: str):
        """Invalidate user-related cache entries"""
        patterns = [
            f"session:{user_id}",
            f"notifications:{user_id}",
            f"reviews:user:{user_id}"
        ]
        
        for pattern in patterns:
            await self.redis.delete(pattern)
```

## 4. Elasticsearch Design

### 4.1 Index Structure

```json
// Document content index
{
  "mappings": {
    "properties": {
      "review_id": {"type": "keyword"},
      "document_id": {"type": "keyword"},
      "filename": {"type": "text"},
      "content": {
        "type": "text",
        "analyzer": "english",
        "fields": {
          "keyword": {"type": "keyword"}
        }
      },
      "document_type": {"type": "keyword"},
      "extracted_components": {
        "type": "nested",
        "properties": {
          "type": {"type": "keyword"},
          "name": {"type": "text"},
          "confidence": {"type": "float"}
        }
      },
      "security_patterns": {
        "type": "nested",
        "properties": {
          "pattern_id": {"type": "keyword"},
          "category": {"type": "keyword"},
          "confidence": {"type": "float"},
          "location": {"type": "text"}
        }
      },
      "created_at": {"type": "date"}
    }
  }
}

// Security findings index
{
  "mappings": {
    "properties": {
      "finding_id": {"type": "keyword"},
      "review_id": {"type": "keyword"},
      "organization_id": {"type": "keyword"},
      "title": {"type": "text"},
      "description": {"type": "text"},
      "risk_level": {"type": "keyword"},
      "risk_score": {"type": "float"},
      "owasp_category": {"type": "keyword"},
      "asvs_references": {"type": "keyword"},
      "cwe_references": {"type": "keyword"},
      "affected_components": {"type": "keyword"},
      "status": {"type": "keyword"},
      "created_at": {"type": "date"},
      "resolved_at": {"type": "date"}
    }
  }
}

// Analytics aggregation index
{
  "mappings": {
    "properties": {
      "date": {"type": "date"},
      "organization_id": {"type": "keyword"},
      "review_count": {"type": "integer"},
      "avg_score": {"type": "float"},
      "risk_distribution": {
        "type": "object",
        "properties": {
          "critical": {"type": "integer"},
          "high": {"type": "integer"},
          "medium": {"type": "integer"},
          "low": {"type": "integer"}
        }
      },
      "owasp_top10_stats": {"type": "object"},
      "asvs_compliance": {"type": "object"}
    }
  }
}
```

### 4.2 Search Queries

```python
class SearchService:
    def __init__(self, es_client):
        self.es = es_client
    
    async def search_findings(self, query: str, filters: dict):
        """Search security findings with filters"""
        search_body = {
            "query": {
                "bool": {
                    "must": [
                        {
                            "multi_match": {
                                "query": query,
                                "fields": ["title^2", "description", "affected_components"]
                            }
                        }
                    ],
                    "filter": []
                }
            },
            "aggs": {
                "risk_levels": {
                    "terms": {"field": "risk_level"}
                },
                "owasp_categories": {
                    "terms": {"field": "owasp_category"}
                }
            },
            "size": 20,
            "sort": [{"risk_score": {"order": "desc"}}]
        }
        
        # Add filters
        if filters.get('organization_id'):
            search_body["query"]["bool"]["filter"].append(
                {"term": {"organization_id": filters["organization_id"]}}
            )
        
        if filters.get('risk_level'):
            search_body["query"]["bool"]["filter"].append(
                {"terms": {"risk_level": filters["risk_level"]}}
            )
        
        return await self.es.search(
            index="security_findings",
            body=search_body
        )
```

## 5. Data Migration and Versioning

### 5.1 Database Migration Framework

```sql
-- Migration tracking table
CREATE TABLE schema_migrations (
    version VARCHAR(20) PRIMARY KEY,
    description TEXT NOT NULL,
    applied_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    applied_by VARCHAR(100) NOT NULL,
    checksum VARCHAR(64) NOT NULL
);

-- Example migration: 20240115_001_add_review_priority.sql
BEGIN;

-- Add priority column to reviews table
ALTER TABLE reviews 
ADD COLUMN priority VARCHAR(20) DEFAULT 'normal' 
CHECK (priority IN ('low', 'normal', 'high', 'urgent'));

-- Create index for priority queries
CREATE INDEX CONCURRENTLY idx_reviews_priority ON reviews(priority);

-- Update migration tracking
INSERT INTO schema_migrations (version, description, applied_by, checksum) 
VALUES ('20240115_001', 'Add priority column to reviews table', 'system', 'sha256_hash');

COMMIT;
```

### 5.2 Data Backup Strategy

```yaml
Backup Strategy:
  PostgreSQL:
    - Full backup: Daily at 2:00 AM UTC
    - Incremental backup: Every 6 hours
    - Point-in-time recovery: WAL archiving
    - Retention: 30 days full, 7 days incremental
    
  Redis:
    - RDB snapshots: Every 4 hours
    - AOF persistence: Enabled
    - Replication: Master-slave setup
    
  Elasticsearch:
    - Snapshot: Daily to S3
    - Retention: 14 days
    - Index lifecycle: Hot-warm-cold architecture
    
  File Storage:
    - Versioning: Enabled
    - Cross-region replication: Enabled
    - Retention: 7 years for compliance
```

This comprehensive database design provides a robust foundation for the SecureArch Portal, ensuring data integrity, performance, and scalability while supporting complex security analysis workflows. 