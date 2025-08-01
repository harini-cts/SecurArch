#!/bin/bash

# SecureArch Portal - Git Repository Setup Script
# Run this script after installing Git to initialize the repository

echo ""
echo "========================================"
echo "   SecureArch Portal - Git Setup"
echo "========================================"
echo ""

# Check if Git is installed
if ! command -v git &> /dev/null; then
    echo "❌ ERROR: Git is not installed or not in PATH"
    echo "Please install Git:"
    echo "  - macOS: brew install git"
    echo "  - Ubuntu/Debian: sudo apt-get install git"
    echo "  - CentOS/RHEL: sudo yum install git"
    echo "Then run this script again."
    exit 1
fi

echo "✅ Git is installed and available"
echo ""

# Initialize repository if not already initialized
if [ ! -d ".git" ]; then
    echo "🔄 Initializing Git repository..."
    git init
    echo "✅ Repository initialized"
else
    echo "✅ Repository already initialized"
fi
echo ""

# Configure Git user (optional - user can modify)
echo "🔧 Setting up Git configuration..."
git config user.name "SecureArch Developer"
git config user.email "developer@securearch.com"
echo "✅ Git user configured (you can change this with 'git config --global user.name \"Your Name\"')"
echo ""

# Add all documentation files to staging
echo "📋 Adding documentation files to staging..."
git add README.md
git add PROJECT_PLAN.md
git add SYSTEM_ARCHITECTURE.md
git add OWASP_INTEGRATION.md
git add DATABASE_DESIGN.md
git add API_SPECIFICATION.md
git add USER_STORIES.md
git add .gitignore
git add COMMIT_MESSAGE.txt
git add setup-git-repo.bat
git add setup-git-repo.sh
echo "✅ All files staged"
echo ""

# Show status
echo "📊 Current repository status:"
git status --short
echo ""

# Create initial commit using the commit message file
echo "📝 Creating initial commit..."
git commit -F COMMIT_MESSAGE.txt

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ SUCCESS: Initial commit created!"
    echo ""
    echo "📈 Repository statistics:"
    git log --oneline
    echo ""
    echo "📋 Files in repository:"
    git ls-files
    echo ""
    echo "🎉 Git repository setup complete!"
    echo ""
    echo "🚀 Next steps:"
    echo "   1. Connect to remote repository: git remote add origin [URL]"
    echo "   2. Push to remote: git push -u origin main"
    echo "   3. Ready for development phase!"
else
    echo "❌ ERROR: Failed to create initial commit"
    echo "Please check the error messages above"
    exit 1
fi

echo ""
echo "========================================"
echo "   Setup Complete"
echo "========================================" 