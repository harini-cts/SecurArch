"""
Enhanced Workflow Management for SecureArch Portal
Implements role-based status assignment and visibility logic
"""

from enum import Enum
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import logging

logger = logging.getLogger(__name__)

class ApplicationStatus(Enum):
    """Application status enumeration with clear definitions"""
    DRAFT = "draft"
    SUBMITTED = "submitted"
    IN_REVIEW = "in_review"
    PENDING_CLARIFICATION = "pending_clarification"
    COMPLETED = "completed"
    REJECTED = "rejected"
    ARCHIVED = "archived"

class AnalystStatus(Enum):
    """Analyst-facing status enumeration"""
    HIDDEN = "hidden"  # Draft applications - not visible to analysts
    TODO = "todo"      # Submitted applications - ready for analyst pickup
    IN_REVIEW = "in_review"  # Currently being reviewed by analyst
    COMPLETED = "completed"  # Review finished

class UserRole(Enum):
    """User role enumeration"""
    USER = "user"
    SECURITY_ANALYST = "security_analyst"
    ADMIN = "admin"

class WorkflowEngine:
    """Enhanced workflow management with role-based logic"""
    
    # Valid status transitions based on user role
    VALID_TRANSITIONS = {
        ApplicationStatus.DRAFT: {
            UserRole.USER: [ApplicationStatus.COMPLETED, ApplicationStatus.SUBMITTED, ApplicationStatus.ARCHIVED],
            UserRole.SECURITY_ANALYST: [],  # Analysts cannot modify draft applications
            UserRole.ADMIN: [ApplicationStatus.COMPLETED, ApplicationStatus.SUBMITTED, ApplicationStatus.ARCHIVED]
        },
        ApplicationStatus.SUBMITTED: {
            UserRole.USER: [],  # Users cannot change status once submitted (only after both reviews completed)
            UserRole.SECURITY_ANALYST: [ApplicationStatus.IN_REVIEW, ApplicationStatus.REJECTED],
            UserRole.ADMIN: [ApplicationStatus.IN_REVIEW, ApplicationStatus.REJECTED, ApplicationStatus.ARCHIVED]
        },
        ApplicationStatus.IN_REVIEW: {
            UserRole.USER: [],  # Users cannot change status during review
            UserRole.SECURITY_ANALYST: [
                ApplicationStatus.PENDING_CLARIFICATION, 
                ApplicationStatus.COMPLETED, 
                ApplicationStatus.REJECTED
            ],
            UserRole.ADMIN: [
                ApplicationStatus.PENDING_CLARIFICATION,
                ApplicationStatus.COMPLETED,
                ApplicationStatus.REJECTED,
                ApplicationStatus.ARCHIVED
            ]
        },
        ApplicationStatus.PENDING_CLARIFICATION: {
            UserRole.USER: [ApplicationStatus.IN_REVIEW],  # User provides clarification
            UserRole.SECURITY_ANALYST: [ApplicationStatus.IN_REVIEW, ApplicationStatus.REJECTED],
            UserRole.ADMIN: [ApplicationStatus.IN_REVIEW, ApplicationStatus.REJECTED, ApplicationStatus.ARCHIVED]
        },
        ApplicationStatus.COMPLETED: {
            UserRole.USER: [],  # Users cannot modify completed applications
            UserRole.SECURITY_ANALYST: [ApplicationStatus.ARCHIVED],
            UserRole.ADMIN: [ApplicationStatus.ARCHIVED, ApplicationStatus.REJECTED]  # Admin can reopen if needed
        },
        ApplicationStatus.REJECTED: {
            UserRole.USER: [ApplicationStatus.SUBMITTED],  # User can resubmit
            UserRole.SECURITY_ANALYST: [ApplicationStatus.SUBMITTED, ApplicationStatus.ARCHIVED],
            UserRole.ADMIN: [ApplicationStatus.SUBMITTED, ApplicationStatus.ARCHIVED]
        },
        ApplicationStatus.ARCHIVED: {
            UserRole.USER: [],  # Terminal state for users
            UserRole.SECURITY_ANALYST: [],  # Terminal state for analysts
            UserRole.ADMIN: [ApplicationStatus.SUBMITTED]  # Admin can restore if needed
        }
    }
    
    # Role-based visibility rules
    VISIBILITY_RULES = {
        UserRole.USER: {
            # Users can see all their own applications regardless of status
            ApplicationStatus.DRAFT: True,
            ApplicationStatus.SUBMITTED: True,
            ApplicationStatus.IN_REVIEW: True,
            ApplicationStatus.PENDING_CLARIFICATION: True,
            ApplicationStatus.COMPLETED: True,
            ApplicationStatus.REJECTED: True,
            ApplicationStatus.ARCHIVED: True
        },
        UserRole.SECURITY_ANALYST: {
            # Analysts cannot see draft applications
            ApplicationStatus.DRAFT: False,
            ApplicationStatus.SUBMITTED: True,
            ApplicationStatus.IN_REVIEW: True,
            ApplicationStatus.PENDING_CLARIFICATION: True,
            ApplicationStatus.COMPLETED: True,
            ApplicationStatus.REJECTED: True,
            ApplicationStatus.ARCHIVED: True
        },
        UserRole.ADMIN: {
            # Admins can see everything
            ApplicationStatus.DRAFT: True,
            ApplicationStatus.SUBMITTED: True,
            ApplicationStatus.IN_REVIEW: True,
            ApplicationStatus.PENDING_CLARIFICATION: True,
            ApplicationStatus.COMPLETED: True,
            ApplicationStatus.REJECTED: True,
            ApplicationStatus.ARCHIVED: True
        }
    }
    
    # Status mapping for analyst dashboard
    ANALYST_STATUS_MAPPING = {
        ApplicationStatus.DRAFT: AnalystStatus.HIDDEN,
        ApplicationStatus.SUBMITTED: AnalystStatus.TODO,
        ApplicationStatus.IN_REVIEW: AnalystStatus.IN_REVIEW,
        ApplicationStatus.PENDING_CLARIFICATION: AnalystStatus.IN_REVIEW,
        ApplicationStatus.COMPLETED: AnalystStatus.COMPLETED,
        ApplicationStatus.REJECTED: AnalystStatus.COMPLETED,
        ApplicationStatus.ARCHIVED: AnalystStatus.COMPLETED
    }
    
    # SLA deadlines (in hours)
    SLA_DEADLINES = {
        ApplicationStatus.SUBMITTED: 24,      # Must start review within 24h
        ApplicationStatus.IN_REVIEW: 120,    # Must complete within 5 days
        ApplicationStatus.PENDING_CLARIFICATION: 72  # User has 3 days to respond
    }
    
    def can_transition(self, current_status: str, new_status: str, user_role: str, 
                      business_context: Optional[Dict] = None) -> Tuple[bool, Optional[str]]:
        """
        Check if a status transition is valid for the given user role
        
        Args:
            current_status: Current application status
            new_status: Desired new status
            user_role: Role of the user attempting the transition
            business_context: Additional context (criticality, etc.)
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            current = ApplicationStatus(current_status)
            new = ApplicationStatus(new_status)
            role = UserRole(user_role)
        except ValueError as e:
            return False, f"Invalid status or role: {e}"
        
        # Allow same status (no change)
        if current == new:
            return True, None
        
        # Check if transition is valid for this role
        allowed_transitions = self.VALID_TRANSITIONS.get(current, {}).get(role, [])
        if new not in allowed_transitions:
            return False, f"User role '{user_role}' cannot transition from '{current_status}' to '{new_status}'"
        
        # Business rule validations
        if business_context:
            # Critical applications need senior analyst for review start
            if (new == ApplicationStatus.IN_REVIEW and 
                business_context.get('criticality') == 'Critical' and
                role == UserRole.SECURITY_ANALYST and
                not business_context.get('analyst_senior', False)):
                return False, "Critical applications require senior analyst assignment"
            
            # High-risk applications need additional approval
            if (new == ApplicationStatus.COMPLETED and
                business_context.get('risk_score', 0) > 7 and
                role == UserRole.SECURITY_ANALYST and
                not business_context.get('admin_approved', False)):
                return False, "High-risk applications require admin approval before completion"
        
        return True, None
    
    def is_visible_to_role(self, application_status: str, user_role: str, 
                          is_owner: bool = False) -> bool:
        """
        Check if an application is visible to a user based on their role
        
        Args:
            application_status: Status of the application
            user_role: Role of the user
            is_owner: Whether the user owns the application
            
        Returns:
            True if application should be visible
        """
        try:
            status = ApplicationStatus(application_status)
            role = UserRole(user_role)
        except ValueError:
            return False
        
        # Users can always see their own applications
        if is_owner and role == UserRole.USER:
            return True
        
        # Check role-based visibility rules
        return self.VISIBILITY_RULES.get(role, {}).get(status, False)
    
    def get_analyst_status(self, application_status: str) -> str:
        """
        Get the analyst-facing status for an application
        
        Args:
            application_status: Internal application status
            
        Returns:
            Analyst-facing status string
        """
        try:
            status = ApplicationStatus(application_status)
            return self.ANALYST_STATUS_MAPPING.get(status, AnalystStatus.HIDDEN).value
        except ValueError:
            return AnalystStatus.HIDDEN.value
    
    def get_applications_for_analyst(self, applications: List[Dict]) -> List[Dict]:
        """
        Filter and categorize applications for analyst dashboard
        
        Args:
            applications: List of application dictionaries
            
        Returns:
            List of applications with analyst_status field added
        """
        visible_applications = []
        
        for app in applications:
            app_status = app['status'] if app['status'] else ''
            
            # Check if visible to analyst
            if self.is_visible_to_role(app_status, UserRole.SECURITY_ANALYST.value, is_owner=False):
                # Add analyst-specific status
                app_copy = app.copy()
                app_copy['analyst_status'] = self.get_analyst_status(app_status)
                visible_applications.append(app_copy)
        
        return visible_applications
    
    def calculate_sla_deadline(self, status: str, created_at: Optional[datetime] = None) -> Optional[datetime]:
        """
        Calculate SLA deadline for current status
        
        Args:
            status: Current application status
            created_at: When the status was set (defaults to now)
            
        Returns:
            Deadline datetime or None if no SLA applies
        """
        try:
            app_status = ApplicationStatus(status)
        except ValueError:
            return None
        
        sla_hours = self.SLA_DEADLINES.get(app_status)
        if not sla_hours:
            return None
        
        start_time = created_at or datetime.now()
        return start_time + timedelta(hours=sla_hours)
    
    def get_overdue_applications(self, applications: List[Dict]) -> List[Dict]:
        """
        Find applications that have exceeded their SLA
        
        Args:
            applications: List of application dictionaries
            
        Returns:
            List of overdue applications with deadline info
        """
        overdue = []
        current_time = datetime.now()
        
        for app in applications:
            status = app['status'] if app['status'] else ''
            created_at_str = app['created_at'] if app['created_at'] else ''
            
            if not created_at_str:
                continue
            
            try:
                # Parse creation time (adjust format as needed)
                created_at = datetime.fromisoformat(created_at_str.replace('Z', '+00:00'))
                deadline = self.calculate_sla_deadline(status, created_at)
                
                if deadline and current_time > deadline:
                    app_copy = app.copy()
                    app_copy['sla_deadline'] = deadline
                    app_copy['overdue_hours'] = int((current_time - deadline).total_seconds() / 3600)
                    overdue.append(app_copy)
                    
            except (ValueError, TypeError) as e:
                logger.warning(f"Could not parse date for application {app.get('id')}: {e}")
                continue
        
        return overdue
    
    def get_status_summary(self, applications: List[Dict], user_role: str) -> Dict[str, int]:
        """
        Get status summary for dashboard
        
        Args:
            applications: List of applications
            user_role: Role of the requesting user
            
        Returns:
            Dictionary with status counts
        """
        summary = {}
        
        if user_role == UserRole.SECURITY_ANALYST.value:
            # Use analyst-specific statuses
            for app in applications:
                app_status = app['status'] if app['status'] else ''
                if self.is_visible_to_role(app_status, user_role, False):
                    analyst_status = self.get_analyst_status(app_status)
                    summary[analyst_status] = summary.get(analyst_status, 0) + 1
        else:
            # Use regular statuses for users and admins
            for app in applications:
                status = app['status'] if app['status'] else 'unknown'
                summary[status] = summary.get(status, 0) + 1
        
        return summary
    
    def get_analyst_applications(self, analyst_id: str, status_filter: str) -> List[Dict]:
        """
        Get applications for analyst dashboard filtered by status
        
        Args:
            analyst_id: ID of the analyst user
            status_filter: Filter by analyst status ('todo', 'in_review', 'completed')
            
        Returns:
            List of applications filtered by analyst status
        """
        import sqlite3
        
        # Get database connection
        conn = sqlite3.connect('securearch_portal.db')
        conn.row_factory = sqlite3.Row
        
        try:
            # Get applications that are ready for analyst review (all required reviews submitted)
            all_applications = conn.execute('''
                SELECT a.*, u.first_name, u.last_name, u.email,
                       COUNT(sr.id) as submitted_review_count
                FROM applications a
                JOIN users u ON a.author_id = u.id
                LEFT JOIN security_reviews sr ON a.id = sr.application_id AND sr.status = 'submitted'
                WHERE a.status = 'submitted'
                GROUP BY a.id, a.name, a.description, a.cloud_review_required, a.database_review_required,
                         u.first_name, u.last_name, u.email
                HAVING (a.cloud_review_required = 'no' AND a.database_review_required = 'no' AND COUNT(sr.id) >= 1) 
                    OR (a.cloud_review_required = 'yes' AND a.database_review_required = 'no' AND COUNT(sr.id) >= 2)
                    OR (a.cloud_review_required = 'no' AND a.database_review_required = 'yes' AND COUNT(sr.id) >= 2)
                    OR (a.cloud_review_required = 'yes' AND a.database_review_required = 'yes' AND COUNT(sr.id) >= 3)
                ORDER BY a.created_at DESC
            ''').fetchall()
            
            # Convert to list of dicts and filter through workflow engine
            applications_list = [dict(app) for app in all_applications]
            visible_applications = self.get_applications_for_analyst(applications_list)
            
            # Filter by requested status
            if status_filter == 'todo':
                return [app for app in visible_applications if app.get('analyst_status') == 'todo']
            elif status_filter == 'in_review':
                return [app for app in visible_applications if app.get('analyst_status') == 'in_review']
            elif status_filter == 'completed':
                return [app for app in visible_applications if app.get('analyst_status') == 'completed']
            else:
                return visible_applications
                
        finally:
            conn.close()

# Global workflow engine instance
workflow_engine = WorkflowEngine() 