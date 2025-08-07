# SecureArch Portal - Role-Based Structure

## Overview

The SecureArch Portal has been restructured into a role-based architecture using Flask blueprints to provide clear separation of concerns and better organization based on user roles.

## 🎯 **Role Definitions**

### 1. **User** (`role: 'user'`)
- **Purpose**: Application creators and submitters
- **Capabilities**:
  - Create and manage their own applications
  - Submit applications for security review
  - View their application status and results
  - Manage their personal profile
- **Restrictions**: Cannot access other users' applications or perform administrative functions

### 2. **Security Analyst** (`role: 'security_analyst'`)
- **Purpose**: Security experts who review applications
- **Capabilities**:
  - Review assigned applications
  - Perform STRIDE threat analysis
  - Complete security assessments
  - Manage review workload
  - Access analyst-specific dashboard and tools
- **Restrictions**: Cannot create applications or access admin functions

### 3. **Administrator** (`role: 'admin'`)
- **Purpose**: System administrators with full access
- **Capabilities**:
  - All user and analyst capabilities
  - Manage all users and roles
  - Override application statuses
  - Access system-wide statistics and reports
  - Manage system configuration
  - View audit logs

## 📁 **File Structure**

### **Blueprint Organization**
```
app/
├── blueprints/
│   ├── __init__.py
│   ├── auth.py          # Authentication (login, logout, register)
│   ├── user.py          # User functionality
│   ├── analyst.py       # Analyst functionality
│   └── admin.py         # Admin functionality
├── decorators.py        # Role-based access decorators
├── database.py          # Database utilities
└── workflow.py          # Enhanced status logic
```

### **Template Organization**
```
templates/
├── shared/
│   └── base.html        # Common base template with role-aware navigation
├── auth/
│   ├── home.html        # Landing page
│   ├── login.html       # Login form
│   ├── register.html    # Registration form
│   └── onboarding.html  # User onboarding
├── user/
│   ├── dashboard.html   # User dashboard
│   ├── applications.html # User's applications
│   ├── create_application.html
│   ├── security_assessment.html
│   ├── review_results.html
│   ├── profile.html
│   ├── edit_profile.html
│   └── change_password.html
├── analyst/
│   ├── dashboard.html   # Analyst dashboard
│   ├── reviews.html     # Assigned reviews
│   ├── review_detail.html
│   ├── stride_analysis.html
│   ├── workload.html    # Workload management
│   └── profile.html
└── admin/
    ├── dashboard.html   # Admin dashboard
    ├── users.html       # User management
    ├── edit_user.html   # User editing
    ├── applications.html # Application management
    ├── reviews.html     # Review management
    ├── audit_logs.html  # System logs
    ├── reports.html     # System reports
    └── settings.html    # System settings
```

## 🛠 **Core Components**

### **1. Authentication Blueprint** (`auth.py`)
- **Routes**:
  - `/` - Home page with role-based redirects
  - `/login` - User authentication
  - `/logout` - Session termination
  - `/register` - User registration
  - `/onboarding` - First-time user setup

### **2. User Blueprint** (`user.py`)
- **URL Prefix**: `/user`
- **Routes**:
  - `/user/dashboard` - User overview
  - `/user/applications` - Application list
  - `/user/applications/create` - New application
  - `/user/applications/<id>/assessment` - Security assessment
  - `/user/applications/<id>/results` - Review results
  - `/user/profile` - Profile management

### **3. Analyst Blueprint** (`analyst.py`)
- **URL Prefix**: `/analyst`
- **Routes**:
  - `/analyst/dashboard` - Review workload overview
  - `/analyst/reviews` - Assigned reviews
  - `/analyst/reviews/<id>` - Review details
  - `/analyst/reviews/<id>/stride` - STRIDE analysis
  - `/analyst/workload` - Workload management

### **4. Admin Blueprint** (`admin.py`)
- **URL Prefix**: `/admin`
- **Routes**:
  - `/admin/dashboard` - System overview
  - `/admin/users` - User management
  - `/admin/applications` - Application management
  - `/admin/reviews` - Review management
  - `/admin/audit-logs` - System logs
  - `/admin/reports` - System reports

## 🔐 **Access Control**

### **Role-Based Decorators** (`app/decorators.py`)
```python
@login_required          # Requires authentication
@user_required          # Requires 'user' or 'admin' role
@analyst_required       # Requires 'security_analyst' or 'admin' role  
@admin_required         # Requires 'admin' role only
@role_required('user', 'analyst')  # Flexible role checking
```

### **Navigation Security**
- Role-aware navigation menus
- Conditional menu items based on user permissions
- Automatic redirects to appropriate dashboards

## 🚀 **Running the Application**

### **New Restructured Version**
```bash
python app_restructured.py
```

### **Legacy Version** (for compatibility)
```bash
python app_web.py
```

## 📊 **User Experience by Role**

### **Regular Users**
1. **Login** → Redirected to `/user/dashboard`
2. **Navigation**: Dashboard, My Applications, Profile
3. **Workflow**: Create → Assess → Submit → View Results

### **Security Analysts**
1. **Login** → Redirected to `/analyst/dashboard`
2. **Navigation**: Dashboard, My Reviews, Workload, Analyst Tools
3. **Workflow**: Review Assignments → STRIDE Analysis → Complete Reviews

### **Administrators**
1. **Login** → Redirected to `/admin/dashboard`
2. **Navigation**: All role menus + Admin dropdown
3. **Capabilities**: Full system access and management

## 🔄 **Migration & Compatibility**

### **Legacy Route Redirects**
The new structure maintains backward compatibility with legacy routes:
- `/dashboard` → Role-appropriate dashboard
- `/applications` → `/user/applications`
- `/analyst/dashboard` → `/analyst/dashboard`

### **Database Compatibility**
- Uses the same database schema
- All existing data remains accessible
- Demo users work with both versions

## 🛡️ **Security Enhancements**

### **Role Enforcement**
- Blueprint-level role checking
- Decorator-based access control
- Template-level permission filtering

### **Session Management**
- Role-aware session handling
- Automatic role-based redirects
- Secure logout and session cleanup

## 📈 **Benefits of Restructuring**

### **1. Better Organization**
- Clear separation by role
- Logical file grouping
- Easier maintenance

### **2. Enhanced Security**
- Role-based access control
- Blueprint-level isolation
- Cleaner permission checking

### **3. Improved Scalability**
- Modular architecture
- Independent role development
- Easy feature addition

### **4. Better User Experience**
- Role-specific interfaces
- Relevant navigation only
- Streamlined workflows

## 🧪 **Testing the Structure**

### **Demo Accounts**
```
👤 Regular User:     user@demo.com / password123
🔍 Security Analyst: analyst@demo.com / analyst123  
🛡️ Administrator:    superadmin@demo.com / admin123
```

### **Test Scenarios**
1. **User Login** → Should see user dashboard and application management
2. **Analyst Login** → Should see analyst dashboard and review management
3. **Admin Login** → Should see admin dashboard with full system access
4. **Role Switching** → Test access restrictions between roles

## 🔧 **Next Steps**

1. **Template Completion**: Create remaining role-specific templates
2. **Static Assets**: Organize CSS/JS by role if needed
3. **API Integration**: Update API endpoints for role-based access
4. **Testing**: Comprehensive role-based testing
5. **Documentation**: User guides for each role

This restructured approach provides a solid foundation for role-based security while maintaining the existing functionality and improving the overall architecture. 