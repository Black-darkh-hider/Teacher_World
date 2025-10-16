#!/bin/bash

# Auto Update Script for Teacher World
# This script helps manage automated updates

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if we're in the right directory
check_directory() {
    if [ ! -f "backend/package.json" ]; then
        print_error "Please run this script from the project root directory"
        exit 1
    fi
}

# Function to update dependencies
update_dependencies() {
    print_status "Updating dependencies..."
    cd backend
    
    # Check for outdated packages
    print_status "Checking for outdated packages..."
    npm outdated || true
    
    # Update packages
    print_status "Updating packages..."
    npm update
    
    # Run security audit
    print_status "Running security audit..."
    npm audit || true
    
    # Try to fix security issues
    print_status "Attempting to fix security issues..."
    npm audit fix || true
    
    cd ..
    print_success "Dependencies updated successfully!"
}

# Function to run tests
run_tests() {
    print_status "Running tests..."
    cd backend
    npm test || print_warning "No tests configured or tests failed"
    cd ..
}

# Function to run security scan
run_security_scan() {
    print_status "Running security scan..."
    cd backend
    npm audit --audit-level moderate || true
    cd ..
}

# Function to check for updates
check_updates() {
    print_status "Checking for available updates..."
    cd backend
    npm outdated
    cd ..
}

# Function to create update summary
create_summary() {
    print_status "Creating update summary..."
    
    # Get current date
    DATE=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Create summary file
    cat > update-summary.md << EOF
# Update Summary - $DATE

## Dependencies Updated
\`\`\`
$(cd backend && npm list --depth=0 2>/dev/null || echo "No dependencies found")
\`\`\`

## Security Audit Results
\`\`\`
$(cd backend && npm audit --json 2>/dev/null || echo "No audit results")
\`\`\`

## Outdated Packages
\`\`\`
$(cd backend && npm outdated 2>/dev/null || echo "All packages up to date")
\`\`\`

---
*This summary was generated automatically by the update script.*
EOF
    
    print_success "Update summary created: update-summary.md"
}

# Function to show help
show_help() {
    echo "Teacher World Auto Update Script"
    echo ""
    echo "Usage: $0 [OPTION]"
    echo ""
    echo "Options:"
    echo "  update      Update all dependencies"
    echo "  check       Check for available updates"
    echo "  test        Run tests"
    echo "  security    Run security scan"
    echo "  summary     Create update summary"
    echo "  all         Run all update tasks"
    echo "  help        Show this help message"
    echo ""
}

# Main script logic
main() {
    check_directory
    
    case "${1:-help}" in
        "update")
            update_dependencies
            ;;
        "check")
            check_updates
            ;;
        "test")
            run_tests
            ;;
        "security")
            run_security_scan
            ;;
        "summary")
            create_summary
            ;;
        "all")
            print_status "Running all update tasks..."
            check_updates
            update_dependencies
            run_tests
            run_security_scan
            create_summary
            print_success "All update tasks completed!"
            ;;
        "help"|*)
            show_help
            ;;
    esac
}

# Run main function with all arguments
main "$@"