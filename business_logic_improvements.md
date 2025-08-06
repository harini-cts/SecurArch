# Business Logic Improvements for SecureArch Portal

## 1. Enhanced Workflow Management

### Current Issues:
- Simple status transitions without validation
- No deadline tracking or SLA management
- Missing workflow rules and constraints
- No approval chains or escalation

### Improvements Needed:

```python
from enum import Enum
from datetime import datetime, timedelta
import json

class ApplicationStatus(Enum):
    DRAFT = "draft"
    SUBMITTED = "submitted" 
    IN_REVIEW = "in_review"
    PENDING_CLARIFICATION = "pending_clarification"
    COMPLETED = "completed"
    REJECTED = "rejected"
    ARCHIVED = "archived"

class WorkflowEngine:
    """Enhanced workflow management with business rules"""
    
    VALID_TRANSITIONS = {
        ApplicationStatus.DRAFT: [ApplicationStatus.SUBMITTED, ApplicationStatus.ARCHIVED],
        ApplicationStatus.SUBMITTED: [ApplicationStatus.IN_REVIEW, ApplicationStatus.REJECTED],
        ApplicationStatus.IN_REVIEW: [
            ApplicationStatus.PENDING_CLARIFICATION, 
            ApplicationStatus.COMPLETED, 
            ApplicationStatus.REJECTED
        ],
        ApplicationStatus.PENDING_CLARIFICATION: [ApplicationStatus.IN_REVIEW, ApplicationStatus.REJECTED],
        ApplicationStatus.COMPLETED: [ApplicationStatus.ARCHIVED],
        ApplicationStatus.REJECTED: [ApplicationStatus.SUBMITTED, ApplicationStatus.ARCHIVED],
        ApplicationStatus.ARCHIVED: []  # Terminal state
    }
    
    SLA_HOURS = {
        ApplicationStatus.SUBMITTED: 24,      # Must start review within 24h
        ApplicationStatus.IN_REVIEW: 120,    # Must complete within 5 days
        ApplicationStatus.PENDING_CLARIFICATION: 72  # User has 3 days to respond
    }
    
    def can_transition(self, current_status, new_status, user_role, business_context=None):
        """Validate status transition with business rules"""
        current = ApplicationStatus(current_status)
        new = ApplicationStatus(new_status)
        
        # Check basic transition validity
        if new not in self.VALID_TRANSITIONS.get(current, []):
            return False, f"Invalid transition from {current.value} to {new.value}"
        
        # Role-based transition rules
        if new == ApplicationStatus.IN_REVIEW and user_role not in ['security_analyst', 'admin']:
            return False, "Only security analysts can start reviews"
        
        if new == ApplicationStatus.COMPLETED and user_role not in ['security_analyst', 'admin']:
            return False, "Only security analysts can complete reviews"
        
        # Business rule: High criticality apps need senior analyst
        if (business_context and 
            business_context.get('criticality') == 'Critical' and 
            new == ApplicationStatus.IN_REVIEW and
            not business_context.get('analyst_senior', False)):
            return False, "Critical applications require senior analyst assignment"
        
        return True, None
    
    def calculate_sla_deadline(self, status, created_at=None):
        """Calculate SLA deadline for current status"""
        if status not in self.SLA_HOURS:
            return None
        
        start_time = created_at or datetime.now()
        return start_time + timedelta(hours=self.SLA_HOURS[status])
    
    def get_overdue_applications(self):
        """Find applications that have exceeded SLA"""
        # Implementation would query database for overdue items
        pass

# Enhanced application management
class ApplicationManager:
    def __init__(self):
        self.workflow = WorkflowEngine()
    
    def submit_application(self, app_data, user_id):
        """Submit application with comprehensive validation"""
        
        # Validate required fields
        required_fields = ['name', 'description', 'technology_stack', 'business_criticality']
        missing_fields = [field for field in required_fields if not app_data.get(field)]
        
        if missing_fields:
            return False, f"Missing required fields: {', '.join(missing_fields)}"
        
        # Business rule: Critical apps need additional documentation
        if (app_data.get('business_criticality') == 'Critical' and 
            not app_data.get('architecture_documents')):
            return False, "Critical applications require architecture documentation"
        
        # Auto-assign based on complexity and availability
        assigned_analyst = self.auto_assign_analyst(app_data)
        
        # Calculate SLA deadline
        sla_deadline = self.workflow.calculate_sla_deadline(ApplicationStatus.SUBMITTED)
        
        # Create application with enhanced metadata
        app_id = self.create_application({
            **app_data,
            'status': ApplicationStatus.SUBMITTED.value,
            'assigned_analyst': assigned_analyst,
            'sla_deadline': sla_deadline,
            'workflow_history': self.create_workflow_entry('submitted', user_id)
        })
        
        return True, app_id
    
    def auto_assign_analyst(self, app_data):
        """Intelligent analyst assignment based on workload and expertise"""
        criticality = app_data.get('business_criticality', 'Medium')
        tech_stack = app_data.get('technology_stack', '').lower()
        
        # Get available analysts with their current workload
        analysts = self.get_available_analysts()
        
        # Scoring algorithm
        for analyst in analysts:
            score = 0
            
            # Workload factor (lower workload = higher score)
            workload_factor = max(0, 10 - analyst['current_workload'])
            score += workload_factor * 0.4
            
            # Expertise matching
            if any(tech in analyst['specializations'] for tech in tech_stack.split()):
                score += 5
            
            # Experience level for critical apps
            if criticality == 'Critical' and analyst['experience_level'] >= 3:
                score += 3
            
            analyst['assignment_score'] = score
        
        # Return analyst with highest score
        best_analyst = max(analysts, key=lambda x: x['assignment_score'])
        return best_analyst['id']
```

## 2. Enhanced Review Process

### Current Issues:
- Linear review process without flexibility
- No peer review or quality assurance
- Missing reviewer guidance and templates
- No conflict resolution process

### Improvements:

```python
class ReviewProcess:
    """Enhanced security review process with quality gates"""
    
    def __init__(self):
        self.quality_gates = {
            'initial_review': ['completeness_check', 'scope_validation'],
            'technical_review': ['architecture_analysis', 'threat_modeling', 'compliance_check'],
            'quality_assurance': ['peer_review', 'finding_validation', 'report_quality']
        }
    
    def start_review(self, review_id, analyst_id):
        """Start review with enhanced process tracking"""
        
        # Get review details
        review = self.get_review(review_id)
        
        # Determine review complexity and assign process
        complexity = self.assess_review_complexity(review)
        
        if complexity == 'high':
            # High complexity reviews need peer reviewer
            peer_reviewer = self.assign_peer_reviewer(analyst_id)
            review['peer_reviewer'] = peer_reviewer
        
        # Create review checklist based on application type
        checklist = self.generate_review_checklist(review)
        
        # Initialize review tracking
        review_tracking = {
            'started_at': datetime.now(),
            'complexity': complexity,
            'checklist': checklist,
            'quality_gates': {},
            'time_spent': 0,
            'milestones': []
        }
        
        return self.update_review_tracking(review_id, review_tracking)
    
    def generate_review_checklist(self, review):
        """Generate dynamic checklist based on application characteristics"""
        base_checklist = [
            'Authentication and Authorization',
            'Input Validation',
            'Data Protection',
            'Error Handling',
            'Logging and Monitoring'
        ]
        
        # Add technology-specific checks
        tech_stack = review.get('technology_stack', '').lower()
        
        if 'web' in tech_stack:
            base_checklist.extend([
                'Cross-Site Scripting (XSS)',
                'Cross-Site Request Forgery (CSRF)',
                'HTTP Security Headers'
            ])
        
        if 'api' in tech_stack:
            base_checklist.extend([
                'API Authentication',
                'Rate Limiting',
                'API Versioning Security'
            ])
        
        if 'cloud' in tech_stack:
            base_checklist.extend([
                'Cloud Configuration Security',
                'Container Security',
                'Infrastructure as Code Review'
            ])
        
        return base_checklist
    
    def validate_finding(self, finding_data):
        """Enhanced finding validation with templates"""
        
        # Risk score calculation
        risk_score = self.calculate_risk_score(
            finding_data.get('likelihood'),
            finding_data.get('impact'),
            finding_data.get('exploitability')
        )
        
        # OWASP mapping validation
        owasp_mapping = self.validate_owasp_mapping(finding_data)
        
        # Remediation guidance quality check
        remediation_quality = self.assess_remediation_quality(finding_data.get('remediation'))
        
        return {
            'risk_score': risk_score,
            'owasp_mapping': owasp_mapping,
            'remediation_quality': remediation_quality,
            'completeness_score': self.calculate_completeness_score(finding_data)
        }
```

## 3. SLA and Performance Tracking

### Implementation:

```python
class SLAManager:
    """Comprehensive SLA tracking and alerting"""
    
    def __init__(self):
        self.sla_targets = {
            'initial_response': timedelta(hours=4),
            'review_assignment': timedelta(hours=24),
            'review_completion': timedelta(days=5),
            'critical_review_completion': timedelta(days=2)
        }
    
    def track_sla_metrics(self):
        """Calculate and track SLA performance metrics"""
        metrics = {}
        
        # Average response times
        metrics['avg_response_time'] = self.calculate_average_response_time()
        metrics['avg_review_time'] = self.calculate_average_review_time()
        
        # SLA compliance rates
        metrics['sla_compliance_rate'] = self.calculate_sla_compliance_rate()
        metrics['critical_sla_compliance'] = self.calculate_critical_sla_compliance()
        
        # Workload distribution
        metrics['analyst_workload'] = self.calculate_analyst_workload_distribution()
        
        return metrics
    
    def generate_sla_alerts(self):
        """Generate alerts for SLA violations and risks"""
        alerts = []
        
        # Check for overdue reviews
        overdue_reviews = self.get_overdue_reviews()
        for review in overdue_reviews:
            alerts.append({
                'type': 'sla_violation',
                'severity': 'high' if review['criticality'] == 'Critical' else 'medium',
                'message': f"Review {review['id']} is overdue by {review['overdue_hours']} hours",
                'review_id': review['id']
            })
        
        # Check for at-risk reviews (75% of SLA consumed)
        at_risk_reviews = self.get_at_risk_reviews()
        for review in at_risk_reviews:
            alerts.append({
                'type': 'sla_warning',
                'severity': 'medium',
                'message': f"Review {review['id']} is at risk of SLA violation",
                'review_id': review['id']
            })
        
        return alerts
``` 