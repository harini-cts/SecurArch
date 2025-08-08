# System Architecture Design - SecureArch Portal

## 1. Architecture Overview

### 1.1 High-Level System Architecture

```
                            ┌─────────────────────────────────────────────────────────┐
                            │                    Internet/CDN                         │
                            └─────────────────────┬───────────────────────────────────┘
                                                  │
                                    ┌─────────────▼─────────────┐
                                    │      Load Balancer        │
                                    │    (AWS ALB/NGINX)       │
                                    └─────────────┬─────────────┘
                                                  │
                              ┌───────────────────┼───────────────────┐
                              │                   │                   │
                    ┌─────────▼─────────┐ ┌──────▼──────┐ ┌─────────▼─────────┐
                    │   Frontend Web    │ │  Mobile Web │ │   Admin Portal    │
                    │   (React.js)      │ │  (PWA)      │ │   (React.js)      │
                    └─────────┬─────────┘ └──────┬──────┘ └─────────┬─────────┘
                              │                   │                   │
                              └───────────────────┼───────────────────┘
                                                  │
                                    ┌─────────────▼─────────────┐
                                    │      API Gateway          │
                                    │    (Kong/AWS Gateway)     │
                                    │  - Rate Limiting          │
                                    │  - Authentication         │
                                    │  - Request Routing        │
                                    └─────────────┬─────────────┘
                                                  │
                        ┌─────────────────────────┼─────────────────────────┐
                        │                         │                         │
            ┌───────────▼───────────┐ ┌─────────▼─────────┐ ┌─────────▼─────────┐
            │    Auth Service       │ │   Review Service  │ │  Analysis Service │
            │   (Keycloak/Auth0)    │ │   (Node.js/TS)    │ │   (Node.js/TS)    │
            └───────────┬───────────┘ └─────────┬─────────┘ └─────────┬─────────┘
                        │                       │                     │
                        │             ┌─────────▼─────────┐           │
                        │             │  Workflow Service │           │
                        │             │   (Node.js/TS)    │           │
                        │             └─────────┬─────────┘           │
                        │                       │                     │
                        │             ┌─────────▼─────────┐           │
                        │             │ Notification Svc  │           │
                        │             │   (Node.js/TS)    │           │
                        │             └─────────┬─────────┘           │
                        │                       │                     │
                        └───────────────────────┼─────────────────────┘
                                                │
                                  ┌─────────────▼─────────────┐
                                  │     Message Queue         │
                                  │   (RabbitMQ/AWS SQS)     │
                                  └─────────────┬─────────────┘
                                                │
                        ┌───────────────────────┼───────────────────────┐
                        │                       │                       │
            ┌───────────▼───────────┐ ┌─────────▼─────────┐ ┌─────────▼─────────┐
            │   PostgreSQL DB       │ │     Redis Cache   │ │  Elasticsearch    │
            │  - User Data          │ │  - Session Store  │ │  - Search Index   │
            │  - Review Data        │ │  - Rate Limiting  │ │  - Analytics      │
            │  - OWASP Mappings     │ │  - Temp Storage   │ │  - Logging        │
            └───────────────────────┘ └───────────────────┘ └───────────────────┘
                        │
            ┌───────────▼───────────┐
            │    File Storage       │
            │   (AWS S3/Azure)      │
            │  - Architecture Docs  │
            │  - Reports            │
            │  - Templates          │
            └───────────────────────┘
```

### 1.2 Microservices Architecture

#### 1.2.1 Core Services

**1. Authentication Service**
- **Responsibility**: User authentication, authorization, session management
- **Technology**: Keycloak or Auth0
- **Features**: SSO, MFA, RBAC, OAuth 2.0/OIDC
- **Database**: User profiles, roles, permissions

**2. Review Management Service**
- **Responsibility**: Architecture review lifecycle management
- **Technology**: Node.js with TypeScript
- **Features**: Submission handling, status tracking, expert assignment
- **Database**: Review metadata, status, assignments

**3. Analysis Engine Service**
- **Responsibility**: Automated security analysis of architecture documents
- **Technology**: Node.js with TypeScript + Python (ML components)
- **Features**: Document parsing, pattern recognition, OWASP mapping
- **Database**: Analysis results, patterns, rules

**4. OWASP Integration Service**
- **Responsibility**: ASVS compliance checking, Top 10 mapping, risk scoring
- **Technology**: Node.js with TypeScript
- **Features**: Standards mapping, compliance tracking, scoring algorithms
- **Database**: OWASP standards, mappings, compliance data

**5. Workflow Service**
- **Responsibility**: Review workflow orchestration and state management
- **Technology**: Node.js with TypeScript
- **Features**: State machines, task routing, SLA monitoring
- **Database**: Workflow states, task assignments

**6. Notification Service**
- **Responsibility**: Multi-channel notifications and communications
- **Technology**: Node.js with TypeScript
- **Features**: Email, Slack, Teams, SMS notifications
- **Database**: Notification templates, delivery logs

**7. Reporting Service**
- **Responsibility**: Report generation and analytics
- **Technology**: Node.js with TypeScript
- **Features**: PDF generation, dashboards, trend analysis
- **Database**: Report templates, cached results

## 2. Detailed Service Specifications

### 2.1 Authentication Service

```yaml
Service: authentication-service
Port: 8001
Dependencies:
  - PostgreSQL (user data)
  - Redis (session storage)

Endpoints:
  - POST /auth/login
  - POST /auth/logout
  - POST /auth/refresh
  - GET  /auth/profile
  - POST /auth/register
  - POST /auth/mfa/setup
  - POST /auth/password/reset

Security:
  - JWT tokens (RS256)
  - MFA support (TOTP, SMS)
  - Rate limiting (10 requests/minute)
  - Session timeout (8 hours)

Configuration:
  JWT_SECRET: ${JWT_SECRET}
  MFA_ISSUER: SecureArch Portal
  SESSION_TIMEOUT: 28800
```

### 2.2 Review Management Service

```yaml
Service: review-service
Port: 8002
Dependencies:
  - PostgreSQL (review data)
  - Redis (caching)
  - File Storage (documents)
  - Message Queue (async processing)

Endpoints:
  - POST /reviews                 # Create new review
  - GET  /reviews                 # List reviews
  - GET  /reviews/{id}           # Get review details
  - PUT  /reviews/{id}           # Update review
  - POST /reviews/{id}/documents # Upload documents
  - GET  /reviews/{id}/status    # Get review status
  - POST /reviews/{id}/assign    # Assign expert

Business Logic:
  - Auto-assignment based on expertise
  - SLA tracking and alerts
  - Status transitions validation
  - Document version control

Database Schema:
  - reviews: id, title, description, status, created_at, updated_at
  - review_documents: id, review_id, filename, file_path, uploaded_at
  - review_assignments: id, review_id, expert_id, assigned_at
```

### 2.3 Analysis Engine Service

```yaml
Service: analysis-service
Port: 8003
Dependencies:
  - PostgreSQL (analysis results)
  - Elasticsearch (search/indexing)
  - File Storage (documents)
  - Message Queue (async processing)

Endpoints:
  - POST /analysis/start/{review_id}
  - GET  /analysis/status/{analysis_id}
  - GET  /analysis/results/{analysis_id}
  - POST /analysis/patterns/update

Processing Pipeline:
  1. Document parsing (PDF, Visio, images)
  2. Component extraction
  3. Security pattern matching
  4. OWASP risk mapping
  5. Vulnerability identification
  6. Risk scoring

AI/ML Components:
  - Document OCR (Tesseract)
  - Pattern recognition (TensorFlow)
  - NLP for requirements analysis
  - Risk scoring algorithms
```

## 3. Data Architecture

### 3.1 Database Design

#### 3.1.1 PostgreSQL Schema

```sql
-- Users and Authentication
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255),
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    role VARCHAR(50) DEFAULT 'user',
    organization_id UUID,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Organizations
CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    domain VARCHAR(255),
    subscription_type VARCHAR(50) DEFAULT 'basic',
    settings JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Architecture Reviews
CREATE TABLE reviews (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title VARCHAR(255) NOT NULL,
    description TEXT,
    project_type VARCHAR(100),
    business_criticality VARCHAR(50),
    target_asvs_level INTEGER DEFAULT 2,
    status VARCHAR(50) DEFAULT 'submitted',
    submitter_id UUID REFERENCES users(id),
    organization_id UUID REFERENCES organizations(id),
    assigned_expert_id UUID REFERENCES users(id),
    compliance_requirements TEXT[],
    technology_stack JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    due_date TIMESTAMP WITH TIME ZONE
);

-- Review Documents
CREATE TABLE review_documents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    review_id UUID REFERENCES reviews(id) ON DELETE CASCADE,
    filename VARCHAR(255) NOT NULL,
    file_path VARCHAR(500) NOT NULL,
    file_size BIGINT,
    mime_type VARCHAR(100),
    document_type VARCHAR(50), -- 'architecture', 'threat_model', 'requirements'
    uploaded_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- OWASP ASVS Requirements
CREATE TABLE asvs_requirements (
    id VARCHAR(20) PRIMARY KEY, -- e.g., 'v4.0.3-1.1.1'
    version VARCHAR(10) NOT NULL,
    level INTEGER NOT NULL,
    category VARCHAR(100) NOT NULL,
    subcategory VARCHAR(100),
    requirement TEXT NOT NULL,
    verification_notes TEXT,
    cwe_references TEXT[],
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Security Findings
CREATE TABLE security_findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    review_id UUID REFERENCES reviews(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    risk_level VARCHAR(20) NOT NULL, -- 'low', 'medium', 'high', 'critical'
    risk_score DECIMAL(3,1),
    owasp_category VARCHAR(50), -- e.g., 'A01', 'A02'
    asvs_references TEXT[],
    cwe_references TEXT[],
    affected_components TEXT[],
    remediation_guidance TEXT,
    status VARCHAR(50) DEFAULT 'open',
    created_by UUID REFERENCES users(id),
    assigned_to UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Analysis Results
CREATE TABLE analysis_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    review_id UUID REFERENCES reviews(id) ON DELETE CASCADE,
    analysis_type VARCHAR(50) NOT NULL, -- 'automated', 'expert', 'combined'
    overall_score DECIMAL(5,2),
    asvs_level_1_score DECIMAL(5,2),
    asvs_level_2_score DECIMAL(5,2),
    asvs_level_3_score DECIMAL(5,2),
    owasp_top10_scores JSONB,
    component_analysis JSONB,
    recommendations TEXT[],
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

#### 3.1.2 Redis Cache Structure

```yaml
Cache Keys:
  # Session Management
  session:{user_id}: "{ user data, roles, permissions }"
  
  # Rate Limiting
  rate_limit:{endpoint}:{user_id}: "request_count"
  
  # Review Cache
  review:{review_id}: "{ review data }"
  reviews:user:{user_id}: "[ review IDs ]"
  
  # Analysis Cache
  analysis:status:{analysis_id}: "{ status, progress }"
  
  # OWASP Data Cache
  asvs:requirements: "{ all ASVS requirements }"
  owasp:top10:current: "{ current top 10 data }"

TTL Settings:
  - Sessions: 8 hours
  - Rate limits: 1 hour
  - Review cache: 1 hour
  - Analysis status: 24 hours
  - OWASP data: 7 days
```

### 3.2 File Storage Structure

```
/secure-arch-portal/
├── organizations/
│   └── {org_id}/
│       └── reviews/
│           └── {review_id}/
│               ├── documents/
│               │   ├── architecture/
│               │   ├── threat_models/
│               │   └── requirements/
│               ├── analysis/
│               │   ├── automated/
│               │   └── expert/
│               └── reports/
│                   ├── summary.pdf
│                   └── detailed.pdf
├── templates/
│   ├── report_templates/
│   └── architecture_templates/
└── system/
    ├── owasp_data/
    └── backups/
```

## 4. Security Architecture

### 4.1 Security Layers

```
┌─────────────────────────────────────────────────────────────┐
│                        Security Layers                     │
├─────────────────────────────────────────────────────────────┤
│ 1. Network Security                                         │
│    - WAF (CloudFlare/AWS WAF)                              │
│    - DDoS Protection                                        │
│    - TLS 1.3 Encryption                                    │
│    - VPC/Network Segmentation                              │
├─────────────────────────────────────────────────────────────┤
│ 2. Application Security                                     │
│    - Input Validation                                       │
│    - Output Encoding                                        │
│    - CSRF Protection                                        │
│    - XSS Prevention                                         │
├─────────────────────────────────────────────────────────────┤
│ 3. Authentication & Authorization                           │
│    - Multi-Factor Authentication                            │
│    - Role-Based Access Control                              │
│    - JWT Token Security                                     │
│    - Session Management                                     │
├─────────────────────────────────────────────────────────────┤
│ 4. Data Security                                           │
│    - Encryption at Rest (AES-256)                         │
│    - Encryption in Transit (TLS 1.3)                      │
│    - Database Security                                      │
│    - File Storage Security                                  │
├─────────────────────────────────────────────────────────────┤
│ 5. Infrastructure Security                                  │
│    - Container Security                                     │
│    - Kubernetes Security                                    │
│    - Secrets Management                                     │
│    - Security Monitoring                                    │
└─────────────────────────────────────────────────────────────┘
```

### 4.2 Authentication Flow

```mermaid
sequenceDiagram
    participant U as User
    participant F as Frontend
    participant G as API Gateway
    participant A as Auth Service
    participant R as Redis
    participant S as Services

    U->>F: Login Request
    F->>G: POST /auth/login
    G->>A: Forward login request
    A->>A: Validate credentials
    A->>A: Generate JWT tokens
    A->>R: Store session data
    A->>G: Return tokens
    G->>F: Return tokens
    F->>F: Store tokens
    
    U->>F: Access protected resource
    F->>G: API request with JWT
    G->>G: Validate JWT
    G->>A: Verify token
    A->>R: Check session
    A->>G: Token valid
    G->>S: Forward request
    S->>G: Response
    G->>F: Response
    F->>U: Display data
```

## 5. Deployment Architecture

### 5.1 Kubernetes Deployment

```yaml
# Namespace Configuration
apiVersion: v1
kind: Namespace
metadata:
  name: securearch-portal

---
# ConfigMap for environment variables
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
  namespace: securearch-portal
data:
  NODE_ENV: "production"
  API_GATEWAY_URL: "https://api.securearch.com"
  REDIS_URL: "redis://redis-service:6379"
  DATABASE_URL: "postgresql://user:pass@postgres-service:5432/securearch"

---
# Secret for sensitive data
apiVersion: v1
kind: Secret
metadata:
  name: app-secrets
  namespace: securearch-portal
type: Opaque
data:
  JWT_SECRET: <base64-encoded-secret>
  DATABASE_PASSWORD: <base64-encoded-password>

---
# Review Service Deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: review-service
  namespace: securearch-portal
spec:
  replicas: 3
  selector:
    matchLabels:
      app: review-service
  template:
    metadata:
      labels:
        app: review-service
    spec:
      containers:
      - name: review-service
        image: securearch/review-service:latest
        ports:
        - containerPort: 8002
        env:
        - name: PORT
          value: "8002"
        envFrom:
        - configMapRef:
            name: app-config
        - secretRef:
            name: app-secrets
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8002
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8002
          initialDelaySeconds: 5
          periodSeconds: 5
```

### 5.2 Infrastructure as Code (Terraform)

```hcl
# VPC Configuration
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
  
  tags = {
    Name = "securearch-vpc"
  }
}

# EKS Cluster
resource "aws_eks_cluster" "cluster" {
  name     = "securearch-cluster"
  role_arn = aws_iam_role.cluster.arn
  version  = "1.28"

  vpc_config {
    subnet_ids = [
      aws_subnet.private_1.id,
      aws_subnet.private_2.id,
      aws_subnet.public_1.id,
      aws_subnet.public_2.id
    ]
    endpoint_private_access = true
    endpoint_public_access  = true
  }

  depends_on = [
    aws_iam_role_policy_attachment.cluster_policy,
    aws_iam_role_policy_attachment.vpc_resource_controller,
  ]
}

# RDS PostgreSQL
resource "aws_db_instance" "main" {
  identifier           = "securearch-db"
  engine               = "postgres"
  engine_version       = "14"
  instance_class       = "db.t3.medium"
  allocated_storage    = 100
  storage_encrypted    = true
  
  db_name  = "securearch"
  username = "admin"
  password = var.db_password
  
  vpc_security_group_ids = [aws_security_group.rds.id]
  db_subnet_group_name   = aws_db_subnet_group.main.name
  
  backup_retention_period = 7
  backup_window          = "03:00-04:00"
  maintenance_window     = "sun:04:00-sun:05:00"
  
  skip_final_snapshot = false
  final_snapshot_identifier = "securearch-final-snapshot"
  
  tags = {
    Name = "SecureArch Database"
  }
}

# ElastiCache Redis
resource "aws_elasticache_subnet_group" "main" {
  name       = "securearch-cache-subnet"
  subnet_ids = [aws_subnet.private_1.id, aws_subnet.private_2.id]
}

resource "aws_elasticache_replication_group" "main" {
  replication_group_id       = "securearch-redis"
  description                = "SecureArch Redis cluster"
  
  node_type                  = "cache.t3.micro"
  port                       = 6379
  parameter_group_name       = "default.redis7"
  
  num_cache_clusters         = 2
  automatic_failover_enabled = true
  multi_az_enabled          = true
  
  subnet_group_name = aws_elasticache_subnet_group.main.name
  security_group_ids = [aws_security_group.redis.id]
  
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
}
```

## 6. Performance and Scalability

### 6.1 Performance Targets

| Metric | Target | Measurement |
|--------|--------|-------------|
| Page Load Time | < 2 seconds | 95th percentile |
| API Response Time | < 500ms | 99th percentile |
| Database Query Time | < 100ms | Average |
| File Upload Time | < 30 seconds | 50MB file |
| Concurrent Users | 1000+ | Sustained load |
| Analysis Processing | < 10 minutes | Standard review |

### 6.2 Scaling Strategy

```yaml
Horizontal Scaling:
  Frontend:
    - CDN distribution (CloudFront/CloudFlare)
    - Auto-scaling based on traffic
    - Geographic distribution
  
  Backend Services:
    - Kubernetes HPA (2-10 replicas per service)
    - Load balancer distribution
    - Circuit breaker patterns
  
  Database:
    - Read replicas for reporting
    - Connection pooling
    - Query optimization
  
  Cache:
    - Redis cluster mode
    - Cache warming strategies
    - TTL optimization

Vertical Scaling:
  - Container resource limits
  - Database instance sizing
  - Storage optimization
  - Memory management
```

## 7. Monitoring and Observability

### 7.1 Monitoring Stack

```yaml
Infrastructure Monitoring:
  - Prometheus + Grafana
  - Node Exporter
  - Kubernetes metrics
  - Custom business metrics

Application Monitoring:
  - Application Performance Monitoring (APM)
  - Error tracking (Sentry)
  - Log aggregation (ELK Stack)
  - Distributed tracing (Jaeger)

Security Monitoring:
  - Web Application Firewall logs
  - Authentication events
  - API access patterns
  - File access auditing

Alerting:
  - PagerDuty integration
  - Slack notifications
  - Email alerts
  - SMS for critical issues
```

### 7.2 Health Check Endpoints

```typescript
// Health check implementation
interface HealthCheck {
  status: 'healthy' | 'unhealthy' | 'degraded';
  timestamp: string;
  services: {
    database: ServiceHealth;
    redis: ServiceHealth;
    queue: ServiceHealth;
    storage: ServiceHealth;
  };
}

// Service endpoints
GET /health      # Basic health check
GET /ready       # Readiness probe
GET /metrics     # Prometheus metrics
GET /status      # Detailed status
```

This comprehensive system architecture provides a solid foundation for building the SecureArch Portal with scalability, security, and maintainability in mind. The microservices approach allows for independent development and deployment while maintaining clear service boundaries and responsibilities. 