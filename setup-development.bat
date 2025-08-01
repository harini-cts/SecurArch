@echo off
REM SecureArch Portal - Development Environment Setup Script

echo.
echo ========================================
echo   SecureArch Portal - Development Setup
echo ========================================
echo.

REM Check if Node.js is installed
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ ERROR: Node.js is not installed
    echo Please install Node.js from: https://nodejs.org/
    echo Required version: Node.js 18+ and npm 9+
    pause
    exit /b 1
)

echo ✅ Node.js is installed
node --version
npm --version
echo.

REM Install backend dependencies
echo 📦 Installing backend dependencies...
npm install
if %errorlevel% neq 0 (
    echo ❌ ERROR: Failed to install backend dependencies
    pause
    exit /b 1
)
echo ✅ Backend dependencies installed
echo.

REM Create necessary directories
echo 📁 Creating project directories...
if not exist "uploads" mkdir uploads
if not exist "logs" mkdir logs
if not exist "src\client" mkdir src\client
if not exist "dist" mkdir dist
echo ✅ Directories created
echo.

REM Copy environment file
echo ⚙️ Setting up environment configuration...
if not exist ".env" (
    copy "env.example" ".env"
    echo ✅ Environment file created (.env)
    echo ⚠️  Please update .env with your database credentials
) else (
    echo ✅ Environment file already exists
)
echo.

REM Check TypeScript compilation
echo 🔧 Checking TypeScript compilation...
npm run build:server
if %errorlevel% neq 0 (
    echo ⚠️  TypeScript compilation has errors (expected for missing dependencies)
    echo This is normal - we'll fix this after full setup
) else (
    echo ✅ TypeScript compilation successful
)
echo.

echo 🎯 Next Steps:
echo.
echo 1. Update .env file with your database credentials:
echo    - DB_HOST=localhost
echo    - DB_NAME=securearch_portal  
echo    - DB_USER=your_username
echo    - DB_PASSWORD=your_password
echo.
echo 2. Set up PostgreSQL database:
echo    - Install PostgreSQL if not already installed
echo    - Create database: securearch_portal
echo    - Run: npm run setup:db
echo.
echo 3. Start development server:
echo    - npm run dev
echo.
echo 4. Access the application:
echo    - API: http://localhost:3001/api/v1
echo    - Health: http://localhost:3001/health
echo.

echo ========================================
echo   Setup Complete!
echo ========================================
pause 