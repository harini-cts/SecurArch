# Enhanced Status Assignment Logic - SecureArch Portal

## 🎯 Overview

This document describes the enhanced role-based status assignment logic implemented in the SecureArch Portal, based on the user requirements table:

| User Role | Action | User Status | Analyst Status |
|-----------|--------|-------------|----------------|
| User | Creates application | Draft | Application shouldn't be visible to analyst until it is submitted |
| User | Submits application for review | Submitted | To Do |
| Analyst | Starts Review | In Review | In Review |
| Analyst | Completes review | Completed / Rejected | Completed |

## 🔧 Implementation Details

### **New Workflow Engine** (`app/workflow.py`)

Created a comprehensive workflow management system with:

#### **Enhanced Status Enumerations**:
```python
class ApplicationStatus(Enum):
    DRAFT = "draft"
    SUBMITTED = "submitted"
    IN_REVIEW = "in_review"
    PENDING_CLARIFICATION = "pending_clarification"  # New status
    COMPLETED = "completed"
    REJECTED = "rejected"
    ARCHIVED = "archived"  # New terminal status

class AnalystStatus(Enum):
    HIDDEN = "hidden"    # Draft applications - not visible to analysts
    TODO = "todo"        # Submitted applications - ready for analyst pickup
    IN_REVIEW = "in_review"  # Currently being reviewed
    COMPLETED = "completed"  # Review finished
```

#### **Role-Based Visibility Rules**:
```python
VISIBILITY_RULES = {
    UserRole.SECURITY_ANALYST: {
        ApplicationStatus.DRAFT: False,  # ✅ Hidden from analysts
        ApplicationStatus.SUBMITTED: True,  # ✅ Visible as "To Do"
        ApplicationStatus.IN_REVIEW: True,
        # ... other statuses
    }
}
```

#### **Enhanced Status Transitions**:
```python
VALID_TRANSITIONS = {
    ApplicationStatus.DRAFT: {
        UserRole.USER: [ApplicationStatus.SUBMITTED, ApplicationStatus.ARCHIVED],
        UserRole.SECURITY_ANALYST: [],  # ✅ Analysts cannot modify drafts
        UserRole.ADMIN: [ApplicationStatus.SUBMITTED, ApplicationStatus.ARCHIVED]
    },
    ApplicationStatus.SUBMITTED: {
        UserRole.USER: [],  # ✅ Users cannot change once submitted
        UserRole.SECURITY_ANALYST: [ApplicationStatus.IN_REVIEW, ApplicationStatus.REJECTED],
        UserRole.ADMIN: [ApplicationStatus.IN_REVIEW, ApplicationStatus.REJECTED]
    }
    # ... other transitions
}
```

### **Status Mapping Implementation**

#### **Analyst Dashboard Status Mapping**:
```python
ANALYST_STATUS_MAPPING = {
    ApplicationStatus.DRAFT: AnalystStatus.HIDDEN,        # ✅ Not visible
    ApplicationStatus.SUBMITTED: AnalystStatus.TODO,      # ✅ Shows as "To Do"
    ApplicationStatus.IN_REVIEW: AnalystStatus.IN_REVIEW, # ✅ Shows as "In Review"
    ApplicationStatus.COMPLETED: AnalystStatus.COMPLETED, # ✅ Shows as "Completed"
    ApplicationStatus.REJECTED: AnalystStatus.COMPLETED   # ✅ Shows as "Completed"
}
```

## 🔄 **Enhanced Workflow Process**

### **1. User Creates Application**
- **Status**: `draft`
- **User View**: Application visible in their dashboard
- **Analyst View**: ❌ **Application completely hidden** from analyst dashboard
- **Action Available**: User can edit, submit, or delete

### **2. User Submits Application for Review**
- **Status**: `submitted`
- **User View**: Application shows as "Submitted" - no longer editable
- **Analyst View**: ✅ **Application appears in "To Do" section**
- **Action Available**: Analysts can pick up the review

### **3. Analyst Starts Review**
- **Status**: `in_review`
- **User View**: Application shows as "In Review"
- **Analyst View**: ✅ **Application moves to "In Review" section**
- **Automatic Assignment**: Analyst ID assigned to review
- **Notification**: User notified that review has started

### **4. Analyst Completes Review**
- **Status**: `completed` or `rejected`
- **User View**: Application shows final status with results
- **Analyst View**: ✅ **Application moves to "Completed" section**
- **Notification**: User notified of completion with results

## 🛡️ **Security & Business Rules**

### **Role-Based Permissions**:
```python
def can_transition(current_status, new_status, user_role, business_context):
    # Critical applications need senior analyst
    if (new_status == IN_REVIEW and 
        business_context.get('criticality') == 'Critical' and
        not business_context.get('analyst_senior', False)):
        return False, "Critical applications require senior analyst"
```

### **Audit Logging**:
```python
# Every status change is logged
log_user_action(
    user_id=user_id,
    action='status_change',
    resource_type='application',
    resource_id=app_id,
    details=f"Status changed from {current_status} to {new_status}"
)
```

## 📊 **Updated Dashboard Features**

### **Analyst Dashboard Enhancements**:

#### **Categorized Views**:
- **To Do** (`todo_applications`): Submitted applications ready for review
- **In Review** (`in_review_applications`): Applications currently being reviewed
- **Completed** (`completed_applications`): Finished reviews

#### **Enhanced Statistics**:
```python
stats = {
    'total_todo': len(todo_applications),
    'total_in_review': len(in_review_applications),
    'total_completed': len(completed_applications),
    # ... other metrics
}
```

#### **Visibility Filtering**:
```python
# Applications are automatically filtered based on role
visible_applications = workflow_engine.get_applications_for_analyst(all_applications)
```

## 🔍 **Key Implementation Changes**

### **1. Enhanced `update_application_status()` Function**:
```python
def update_application_status(app_id, new_status, conn, user_role='user', business_context=None):
    # Uses workflow engine for validation
    is_valid, error = workflow_engine.can_transition(current_status, new_status, user_role)
    # Includes audit logging
    # Returns success/error tuple
```

### **2. Updated Function Calls**:
- All status transitions now include user role
- Error handling for invalid transitions
- Proper feedback to users when transitions fail

### **3. Analyst Dashboard Query**:
```sql
-- New query excludes draft applications
SELECT a.*, sr.* FROM applications a 
LEFT JOIN security_reviews sr ON a.id = sr.application_id 
WHERE a.status != 'draft'  -- ✅ Drafts automatically hidden
ORDER BY a.created_at DESC
```

## 🎯 **Benefits of Enhanced Logic**

### **1. Clear Separation of Concerns**:
- ✅ Draft applications completely hidden from analysts
- ✅ Clear "To Do" queue for analysts
- ✅ Role-based permissions enforced

### **2. Improved User Experience**:
- ✅ Users see appropriate statuses for their role
- ✅ Analysts have organized workflow queues
- ✅ Clear action items and priorities

### **3. Enhanced Security**:
- ✅ Business rules automatically enforced
- ✅ Complete audit trail of all changes
- ✅ Role-based access controls

### **4. Scalability**:
- ✅ Easy to add new statuses or rules
- ✅ SLA tracking and deadline management ready
- ✅ Foundation for advanced workflow features

## 🚀 **Usage Examples**

### **Checking Visibility**:
```python
# Check if application is visible to analyst
is_visible = workflow_engine.is_visible_to_role('draft', 'security_analyst')
# Returns: False

is_visible = workflow_engine.is_visible_to_role('submitted', 'security_analyst') 
# Returns: True
```

### **Status Transitions**:
```python
# User submitting application
success, error = update_application_status(app_id, 'submitted', conn, 'user')

# Analyst starting review  
success, error = update_application_status(app_id, 'in_review', conn, 'security_analyst')
```

### **Dashboard Filtering**:
```python
# Get analyst-appropriate applications
visible_apps = workflow_engine.get_applications_for_analyst(all_applications)
todo_list = [app for app in visible_apps if app['analyst_status'] == 'todo']
```

## 📋 **Testing the Implementation**

### **Test Scenarios**:

1. **Create Draft Application**:
   - User creates application → Status: `draft`
   - Verify: Not visible in analyst dashboard ✅

2. **Submit Application**:
   - User submits → Status: `submitted`
   - Verify: Appears in analyst "To Do" list ✅

3. **Start Review**:
   - Analyst picks up review → Status: `in_review`
   - Verify: Moves to "In Review" section ✅

4. **Complete Review**:
   - Analyst finishes → Status: `completed`
   - Verify: Moves to "Completed" section ✅

5. **Invalid Transitions**:
   - Attempt invalid status change
   - Verify: Error message and no change ✅

## 🎉 **Summary**

The enhanced status assignment logic successfully implements the requested workflow:

- ✅ **Draft applications hidden from analysts**
- ✅ **"To Do" status for submitted applications**
- ✅ **Clear role-based transitions**
- ✅ **Comprehensive audit trail**
- ✅ **Enhanced security and validation**

The implementation is backward-compatible while adding powerful new workflow capabilities that can be extended for future requirements.

---

**Next Steps**: The workflow engine provides a foundation for advanced features like automatic analyst assignment, SLA management, and escalation workflows. 