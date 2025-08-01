@echo off
REM SecureArch Portal - Git Repository Setup Script
REM Run this script after installing Git to initialize the repository

echo.
echo ========================================
echo   SecureArch Portal - Git Setup
echo ========================================
echo.

REM Check if Git is installed
git --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Git is not installed or not in PATH
    echo Please install Git from: https://git-scm.com/download/windows
    echo Then run this script again.
    pause
    exit /b 1
)

echo ✅ Git is installed and available
echo.

REM Initialize repository if not already initialized
if not exist .git (
    echo 🔄 Initializing Git repository...
    git init
    echo ✅ Repository initialized
) else (
    echo ✅ Repository already initialized
)
echo.

REM Configure Git user (optional - user can modify)
echo 🔧 Setting up Git configuration...
git config user.name "SecureArch Developer"
git config user.email "developer@securearch.com"
echo ✅ Git user configured (you can change this with 'git config --global user.name "Your Name"')
echo.

REM Add all documentation files to staging
echo 📋 Adding documentation files to staging...
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
echo ✅ All files staged
echo.

REM Show status
echo 📊 Current repository status:
git status --short
echo.

REM Create initial commit using the commit message file
echo 📝 Creating initial commit...
git commit -F COMMIT_MESSAGE.txt
echo.

if %errorlevel% equ 0 (
    echo ✅ SUCCESS: Initial commit created!
    echo.
    echo 📈 Repository statistics:
    git log --oneline
    echo.
    echo 📋 Files in repository:
    git ls-files
    echo.
    echo 🎉 Git repository setup complete!
    echo.
    echo 🚀 Next steps:
    echo    1. Connect to remote repository: git remote add origin [URL]
    echo    2. Push to remote: git push -u origin main
    echo    3. Ready for development phase!
) else (
    echo ❌ ERROR: Failed to create initial commit
    echo Please check the error messages above
)

echo.
echo ========================================
echo   Setup Complete
echo ========================================
pause 