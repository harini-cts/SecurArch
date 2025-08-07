#!/bin/bash

# SecureArch Portal - Secure Deployment Script
# This script helps deploy the secure version of the application

set -e  # Exit on any error

echo "🚀 SecureArch Portal - Secure Deployment Setup"
echo "================================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   print_error "This script should not be run as root for security reasons"
   exit 1
fi

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check prerequisites
echo
print_info "Checking prerequisites..."

# Check Python
if ! command_exists python3; then
    print_error "Python 3 is required but not installed"
    exit 1
fi
print_status "Python 3 found"

# Check pip
if ! command_exists pip3; then
    print_error "pip3 is required but not installed"
    exit 1
fi
print_status "pip3 found"

# Check if virtual environment exists
if [ ! -d ".venv" ]; then
    print_info "Creating Python virtual environment..."
    python3 -m venv .venv
    print_status "Virtual environment created"
fi

# Activate virtual environment
print_info "Activating virtual environment..."
source .venv/bin/activate
print_status "Virtual environment activated"

# Install/upgrade dependencies
print_info "Installing/upgrading dependencies..."
pip install --upgrade pip
pip install -r requirements.txt
print_status "Dependencies installed"

# Setup environment file
if [ ! -f ".env" ]; then
    print_info "Setting up environment configuration..."
    cp env.example .env
    
    # Generate secure keys
    SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    
    # Update .env file with generated keys
    sed -i "s/your-super-secret-flask-key-change-this-in-production/$SECRET_KEY/" .env
    sed -i "s/your-jwt-secret-key-change-this-in-production/$JWT_SECRET/" .env
    
    print_status "Environment file created with secure keys"
    print_warning "Please review and update .env file with your specific configuration"
else
    print_status "Environment file already exists"
fi

# Check for Redis (optional but recommended)
echo
print_info "Checking Redis availability..."
if command_exists redis-cli; then
    if redis-cli ping > /dev/null 2>&1; then
        print_status "Redis is running and accessible"
    else
        print_warning "Redis is installed but not running"
        print_info "To start Redis: sudo systemctl start redis-server"
    fi
else
    print_warning "Redis not found - sessions will use filesystem storage"
    print_info "To install Redis: sudo apt install redis-server (Ubuntu/Debian)"
fi

# Check for PostgreSQL (optional but recommended for production)
echo
print_info "Checking PostgreSQL availability..."
if command_exists psql; then
    print_status "PostgreSQL client found"
    print_info "To migrate to PostgreSQL, set DB_* variables in .env and run:"
    print_info "python migrate_to_postgresql.py"
else
    print_warning "PostgreSQL not found - will use SQLite for development"
    print_info "To install PostgreSQL: sudo apt install postgresql postgresql-contrib"
fi

# Create necessary directories
print_info "Creating necessary directories..."
mkdir -p uploads/architecture
mkdir -p uploads/documents
mkdir -p logs
print_status "Directories created"

# Set proper permissions
print_info "Setting secure file permissions..."
chmod 755 app_secure.py
chmod 755 migrate_to_postgresql.py
chmod 600 .env  # Secure environment file
chmod 755 uploads
print_status "File permissions set"

# Development setup
echo
print_info "Setting up development environment..."

# Check if we should run the secure app
read -p "Do you want to start the secure application now? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    print_info "Starting SecureArch Portal with security features..."
    print_info "The application will be available at http://localhost:5000"
    print_info "Demo credentials:"
    print_info "  User: admin@demo.com / password123"
    print_info "  Analyst: analyst@demo.com / analyst123"
    echo
    print_warning "Press Ctrl+C to stop the application"
    echo
    
    # Start the secure application
    python app_secure.py
else
    echo
    print_status "Setup completed successfully!"
    echo
    print_info "To start the secure application manually:"
    print_info "  source .venv/bin/activate"
    print_info "  python app_secure.py"
    echo
    print_info "To start with production server:"
    print_info "  gunicorn --bind 0.0.0.0:5000 --workers 4 app_secure:app"
    echo
fi

# Production deployment notes
echo
print_info "📋 Production Deployment Checklist:"
echo "   - Set FLASK_ENV=production in .env"
echo "   - Configure PostgreSQL database"
echo "   - Set up Redis for sessions and caching"
echo "   - Configure HTTPS with SSL certificates"
echo "   - Set up reverse proxy (nginx/Apache)"
echo "   - Configure monitoring and logging"
echo "   - Set up automated backups"
echo "   - Review SECURITY_DEPLOYMENT_GUIDE.md for details"
echo

print_status "🎉 SecureArch Portal secure deployment setup completed!"

# Security reminder
echo
print_warning "🛡️  SECURITY REMINDERS:"
echo "   - Never commit .env file to version control"
echo "   - Regularly update dependencies"
echo "   - Monitor audit logs for suspicious activity"
echo "   - Use HTTPS in production"
echo "   - Keep backup of your data" 