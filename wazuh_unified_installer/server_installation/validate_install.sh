#!/bin/bash
# Wazuh Server Installation Validation Script
# Author: Rodrigo Marins Piaba (Fanaticos4tech)
# E-Mail: rodrigomarinsp@gmail.com / fanaticos4tech@gmail.com
# GitHub: rodrigomarinsp
# Instagram: @fanaticos4tech
# License: GPL-3.0

set -euo pipefail

# =============================================================================
# GLOBAL VARIABLES
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="/var/log/wazuh-validation.log"
REPORT_FILE="/var/log/wazuh-validation-report.txt"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Validation flags
FIX_SERVICES=false
FIX_CONNECTIVITY=false
COMPREHENSIVE=false
PERFORMANCE=false
SECURITY_CHECK=false
DEBUG_MODE=false

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
    
    case "$level" in
        "ERROR")
            echo -e "${RED}❌ ERROR: $message${NC}" >&2
            ;;
        "WARN")
            echo -e "${YELLOW}⚠️  WARNING: $message${NC}"
            ;;
        "INFO")
            echo -e "${BLUE}ℹ️  INFO: $message${NC}"
            ;;
        "SUCCESS")
            echo -e "${GREEN}✅ SUCCESS: $message${NC}"
            ;;
        "CHECK")
            echo -e "${CYAN}🔍 CHECK: $message${NC}"
            ;;
        "FIX")
            echo -e "${PURPLE}🔧 FIX: $message${NC}"
            ;;
    esac
}

error_exit() {
    log "ERROR" "$1"
    exit 1
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error_exit "This script must be run as root. Use: sudo $0"
    fi
}

# =============================================================================
# SERVICE VALIDATION FUNCTIONS
# =============================================================================

check_service_status() {
    local service="$1"
    local required="$2"
    
    log "CHECK" "Checking $service service status..."
    
    if systemctl is-active --quiet "$service"; then
        log "SUCCESS" "$service is running"
        return 0
    else
        if [ "$required" = "true" ]; then
            log "ERROR" "$service is not running"
            if [ "$FIX_SERVICES" = true ]; then
                fix_service "$service"
            fi
            return 1
        else
            log "WARN" "$service is not running (optional)"
            return 0
        fi
    fi
}

fix_service() {
    local service="$1"
    
    log "FIX" "Attempting to fix $service service..."
    
    # Check if service is enabled
    if ! systemctl is-enabled --quiet "$service"; then
        log "FIX" "Enabling $service service..."
        systemctl enable "$service"
    fi
    
    # Try to start the service
    log "FIX" "Starting $service service..."
    if systemctl start "$service"; then
        log "SUCCESS" "$service service fixed and started"
        
        # Wait for service to be fully ready
        sleep 5
        
        if systemctl is-active --quiet "$service"; then
            log "SUCCESS" "$service is now running properly"
        else
            log "ERROR" "$service failed to start properly"
            # Show service logs for debugging
            log "INFO" "Last 10 lines of $service logs:"
            journalctl -u "$service" --no-pager -n 10 | tee -a "$LOG_FILE"
        fi
    else
        log "ERROR" "Failed to start $service service"
        # Show service logs for debugging
        log "INFO" "Last 20 lines of $service logs:"
        journalctl -u "$service" --no-pager -n 20 | tee -a "$LOG_FILE"
    fi
}

validate_wazuh_services() {
    log "CHECK" "Validating Wazuh services..."
    
    local services=(
        "wazuh-indexer:true"
        "wazuh-manager:true"
        "wazuh-dashboard:true"
    )
    
    local failed_services=0
    
    for service_info in "${services[@]}"; do
        IFS=':' read -r service required <<< "$service_info"
        if ! check_service_status "$service" "$required"; then
            ((failed_services++))
        fi
    done
    
    if [ $failed_services -eq 0 ]; then
        log "SUCCESS" "All Wazuh services are running properly"
        return 0
    else
        log "ERROR" "$failed_services Wazuh service(s) have issues"
        return 1
    fi
}

# =============================================================================
# CONNECTIVITY VALIDATION FUNCTIONS
# =============================================================================

check_port_connectivity() {
    local service="$1"
    local port="$2"
    local protocol="$3"
    
    log "CHECK" "Checking $service connectivity on port $port ($protocol)..."
    
    case "$protocol" in
        "http")
            if curl -s -f "http://localhost:$port" >/dev/null 2>&1; then
                log "SUCCESS" "$service HTTP port $port is accessible"
                return 0
            fi
            ;;
        "https")
            if curl -s -f -k "https://localhost:$port" >/dev/null 2>&1; then
                log "SUCCESS" "$service HTTPS port $port is accessible"
                return 0
            fi
            ;;
        "tcp")
            if timeout 5 bash -c "</dev/tcp/localhost/$port" >/dev/null 2>&1; then
                log "SUCCESS" "$service TCP port $port is accessible"
                return 0
            fi
            ;;
    esac
    
    log "ERROR" "$service port $port is not accessible"
    
    if [ "$FIX_CONNECTIVITY" = true ]; then
        fix_connectivity "$service" "$port"
    fi
    
    return 1
}

fix_connectivity() {
    local service="$1"
    local port="$2"
    
    log "FIX" "Attempting to fix connectivity for $service on port $port..."
    
    # Check if service is listening on the port
    if ! ss -tulpn | grep -q ":$port "; then
        log "WARN" "Service is not listening on port $port"
        
        # Try to restart the service
        log "FIX" "Restarting $service service..."
        systemctl restart "wazuh-${service,,}" || log "ERROR" "Failed to restart service"
        
        # Wait for service to be ready
        sleep 10
    fi
    
    # Check firewall rules
    if command -v ufw >/dev/null 2>&1; then
        log "FIX" "Adding UFW firewall rule for port $port..."
        ufw allow "$port"/tcp || log "WARN" "Failed to add UFW rule"
    elif command -v firewall-cmd >/dev/null 2>&1; then
        log "FIX" "Adding firewalld rule for port $port..."
        firewall-cmd --permanent --add-port="$port"/tcp || log "WARN" "Failed to add firewalld rule"
        firewall-cmd --reload || log "WARN" "Failed to reload firewalld"
    fi
}

validate_connectivity() {
    log "CHECK" "Validating service connectivity..."
    
    local connectivity_tests=(
        "dashboard:443:https"
        "indexer:9200:https"
        "manager:55000:tcp"
        "manager:1514:tcp"
        "manager:1515:tcp"
    )
    
    local failed_tests=0
    
    for test_info in "${connectivity_tests[@]}"; do
        IFS=':' read -r service port protocol <<< "$test_info"
        if ! check_port_connectivity "$service" "$port" "$protocol"; then
            ((failed_tests++))
        fi
    done
    
    if [ $failed_tests -eq 0 ]; then
        log "SUCCESS" "All connectivity tests passed"
        return 0
    else
        log "ERROR" "$failed_tests connectivity test(s) failed"
        return 1
    fi
}

# =============================================================================
# CONFIGURATION VALIDATION FUNCTIONS
# =============================================================================

validate_configuration_files() {
    log "CHECK" "Validating configuration files..."
    
    local config_files=(
        "/var/ossec/etc/ossec.conf:Wazuh Manager"
        "/etc/wazuh-indexer/opensearch.yml:Wazuh Indexer"
        "/etc/wazuh-dashboard/opensearch_dashboards.yml:Wazuh Dashboard"
    )
    
    local failed_configs=0
    
    for config_info in "${config_files[@]}"; do
        IFS=':' read -r config_file service_name <<< "$config_info"
        
        if [ -f "$config_file" ]; then
            log "SUCCESS" "$service_name configuration file exists: $config_file"
            
            # Check if file is readable
            if [ -r "$config_file" ]; then
                log "SUCCESS" "$service_name configuration file is readable"
            else
                log "WARN" "$service_name configuration file is not readable"
                ((failed_configs++))
            fi
        else
            log "ERROR" "$service_name configuration file missing: $config_file"
            ((failed_configs++))
        fi
    done
    
    if [ $failed_configs -eq 0 ]; then
        log "SUCCESS" "All configuration files are valid"
        return 0
    else
        log "ERROR" "$failed_configs configuration file(s) have issues"
        return 1
    fi
}

# =============================================================================
# CERTIFICATE VALIDATION FUNCTIONS
# =============================================================================

validate_certificates() {
    log "CHECK" "Validating SSL/TLS certificates..."
    
    local cert_dirs=(
        "/etc/wazuh-indexer/certs"
        "/etc/wazuh-dashboard/certs"
    )
    
    local failed_certs=0
    
    for cert_dir in "${cert_dirs[@]}"; do
        if [ -d "$cert_dir" ]; then
            log "SUCCESS" "Certificate directory exists: $cert_dir"
            
            # Check for common certificate files
            local cert_files=("node.pem" "node-key.pem" "root-ca.pem")
            for cert_file in "${cert_files[@]}"; do
                if [ -f "$cert_dir/$cert_file" ]; then
                    log "SUCCESS" "Certificate file found: $cert_dir/$cert_file"
                    
                    # Validate certificate if it's a .pem file
                    if [[ "$cert_file" == *.pem ]] && [[ "$cert_file" != *-key.pem ]]; then
                        if openssl x509 -in "$cert_dir/$cert_file" -noout -text >/dev/null 2>&1; then
                            log "SUCCESS" "Certificate is valid: $cert_file"
                        else
                            log "WARN" "Certificate validation failed: $cert_file"
                            ((failed_certs++))
                        fi
                    fi
                else
                    log "WARN" "Certificate file not found: $cert_dir/$cert_file"
                fi
            done
        else
            log "WARN" "Certificate directory not found: $cert_dir"
            ((failed_certs++))
        fi
    done
    
    if [ $failed_certs -eq 0 ]; then
        log "SUCCESS" "Certificate validation completed successfully"
        return 0
    else
        log "WARN" "$failed_certs certificate issue(s) found"
        return 1
    fi
}

# =============================================================================
# PERFORMANCE VALIDATION FUNCTIONS
# =============================================================================

validate_performance() {
    log "CHECK" "Running performance validation..."
    
    # Check system resources
    log "INFO" "Current system resource usage:"
    
    # Memory usage
    local mem_info=$(free -h | grep "Mem:")
    log "INFO" "Memory: $mem_info"
    
    # CPU usage
    local cpu_usage=$(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1}')
    log "INFO" "CPU usage: ${cpu_usage}%"
    
    # Disk usage
    local disk_usage=$(df -h / | awk 'NR==2 {print $5}')
    log "INFO" "Disk usage: $disk_usage"
    
    # Check Java heap size for Wazuh Indexer
    if systemctl is-active --quiet wazuh-indexer; then
        local heap_size=$(ps aux | grep wazuh-indexer | grep -o '\-Xmx[0-9]*[mg]' | head -1)
        if [ -n "$heap_size" ]; then
            log "INFO" "Wazuh Indexer heap size: $heap_size"
        fi
    fi
    
    # Check log file sizes
    log "INFO" "Log file sizes:"
    if [ -d "/var/ossec/logs" ]; then
        du -sh /var/ossec/logs/* 2>/dev/null | head -5 | while read -r line; do
            log "INFO" "  $line"
        done
    fi
    
    log "SUCCESS" "Performance validation completed"
}

# =============================================================================
# SECURITY VALIDATION FUNCTIONS
# =============================================================================

validate_security() {
    log "CHECK" "Running security validation..."
    
    # Check file permissions
    local security_files=(
        "/var/ossec/etc/ossec.conf:640"
        "/etc/wazuh-indexer/opensearch.yml:640"
        "/etc/wazuh-dashboard/opensearch_dashboards.yml:640"
    )
    
    for file_info in "${security_files[@]}"; do
        IFS=':' read -r file_path expected_perm <<< "$file_info"
        
        if [ -f "$file_path" ]; then
            local actual_perm=$(stat -c "%a" "$file_path")
            if [ "$actual_perm" -le "$expected_perm" ]; then
                log "SUCCESS" "File permissions OK: $file_path ($actual_perm)"
            else
                log "WARN" "File permissions too open: $file_path ($actual_perm, expected <= $expected_perm)"
            fi
        fi
    done
    
    # Check for default passwords
    if [ -f "/var/log/wazuh-passwords.txt" ]; then
        log "SUCCESS" "Custom passwords file found"
    else
        log "WARN" "Default passwords may be in use"
    fi
    
    # Check firewall status
    if command -v ufw >/dev/null 2>&1; then
        if ufw status | grep -q "Status: active"; then
            log "SUCCESS" "UFW firewall is active"
        else
            log "WARN" "UFW firewall is not active"
        fi
    elif command -v firewall-cmd >/dev/null 2>&1; then
        if firewall-cmd --state 2>/dev/null | grep -q "running"; then
            log "SUCCESS" "Firewalld is running"
        else
            log "WARN" "Firewalld is not running"
        fi
    else
        log "WARN" "No supported firewall detected"
    fi
    
    log "SUCCESS" "Security validation completed"
}

# =============================================================================
# COMPREHENSIVE VALIDATION FUNCTION
# =============================================================================

run_comprehensive_validation() {
    log "CHECK" "Running comprehensive validation..."
    
    local total_tests=0
    local passed_tests=0
    
    # Service validation
    ((total_tests++))
    if validate_wazuh_services; then
        ((passed_tests++))
    fi
    
    # Connectivity validation
    ((total_tests++))
    if validate_connectivity; then
        ((passed_tests++))
    fi
    
    # Configuration validation
    ((total_tests++))
    if validate_configuration_files; then
        ((passed_tests++))
    fi
    
    # Certificate validation
    ((total_tests++))
    if validate_certificates; then
        ((passed_tests++))
    fi
    
    # Performance validation (if requested)
    if [ "$PERFORMANCE" = true ]; then
        ((total_tests++))
        if validate_performance; then
            ((passed_tests++))
        fi
    fi
    
    # Security validation (if requested)
    if [ "$SECURITY_CHECK" = true ]; then
        ((total_tests++))
        if validate_security; then
            ((passed_tests++))
        fi
    fi
    
    # Generate report
    generate_validation_report "$total_tests" "$passed_tests"
    
    log "INFO" "Comprehensive validation completed: $passed_tests/$total_tests tests passed"
    
    if [ $passed_tests -eq $total_tests ]; then
        return 0
    else
        return 1
    fi
}

# =============================================================================
# REPORT GENERATION
# =============================================================================

generate_validation_report() {
    local total_tests="$1"
    local passed_tests="$2"
    
    cat > "$REPORT_FILE" << EOF
# Wazuh Server Validation Report
# Author: Rodrigo Marins Piaba (Fanaticos4tech)
# Generated: $(date)

## Summary
- Total tests: $total_tests
- Passed tests: $passed_tests
- Failed tests: $((total_tests - passed_tests))
- Success rate: $(( (passed_tests * 100) / total_tests ))%

## Service Status
$(systemctl status wazuh-indexer wazuh-manager wazuh-dashboard --no-pager -l 2>/dev/null || echo "Error getting service status")

## System Information
- OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)
- Kernel: $(uname -r)
- Uptime: $(uptime)

## Network Information
- Hostname: $(hostname)
- IP Address: $(hostname -I | awk '{print $1}')

## Log File Location
- Validation log: $LOG_FILE
- Installation log: /var/log/wazuh-server-install.log (if exists)

## Recommendations
$(if [ $passed_tests -lt $total_tests ]; then
    echo "- Review failed tests in the validation log"
    echo "- Check service logs for error details"
    echo "- Ensure firewall rules are properly configured"
    echo "- Verify system resources meet requirements"
else
    echo "- All tests passed successfully"
    echo "- Consider running security hardening"
    echo "- Set up regular monitoring and maintenance"
fi)

EOF
    
    log "INFO" "Validation report generated: $REPORT_FILE"
}

# =============================================================================
# COMMAND LINE ARGUMENT PARSING
# =============================================================================

show_help() {
    cat << EOF
Wazuh Server Installation Validation Script
Author: Rodrigo Marins Piaba (Fanaticos4tech)

Usage: $0 [OPTIONS]

OPTIONS:
    --fix-services         Attempt to fix service issues automatically
    --fix-connectivity     Attempt to fix connectivity issues automatically
    --comprehensive        Run comprehensive validation (all tests)
    --performance         Include performance validation
    --security-check      Include security validation
    --debug               Enable debug mode with verbose output
    --help                Show this help message

EXAMPLES:
    $0                                    # Basic validation
    $0 --comprehensive                    # All validation tests
    $0 --fix-services --fix-connectivity  # Auto-fix issues
    $0 --performance --security-check     # Extended validation

For more information, see: $SCRIPT_DIR/README.md
EOF
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --fix-services)
                FIX_SERVICES=true
                shift
                ;;
            --fix-connectivity)
                FIX_CONNECTIVITY=true
                shift
                ;;
            --comprehensive)
                COMPREHENSIVE=true
                PERFORMANCE=true
                SECURITY_CHECK=true
                shift
                ;;
            --performance)
                PERFORMANCE=true
                shift
                ;;
            --security-check)
                SECURITY_CHECK=true
                shift
                ;;
            --debug)
                DEBUG_MODE=true
                set -x
                shift
                ;;
            --help)
                show_help
                exit 0
                ;;
            *)
                error_exit "Unknown option: $1. Use --help for usage information."
                ;;
        esac
    done
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

main() {
    # Parse command line arguments
    parse_arguments "$@"
    
    # Initialize logging
    mkdir -p "$(dirname "$LOG_FILE")"
    touch "$LOG_FILE"
    
    log "INFO" "Starting Wazuh Server validation..."
    log "INFO" "Script: $0"
    log "INFO" "Arguments: $*"
    log "INFO" "Author: Rodrigo Marins Piaba (Fanaticos4tech)"
    
    # Check if running as root
    check_root
    
    # Run validation based on options
    if [ "$COMPREHENSIVE" = true ]; then
        run_comprehensive_validation
    else
        # Run individual validations
        local failed_validations=0
        
        # Always run basic validations
        validate_wazuh_services || ((failed_validations++))
        validate_connectivity || ((failed_validations++))
        validate_configuration_files || ((failed_validations++))
        
        # Optional validations
        if [ "$PERFORMANCE" = true ]; then
            validate_performance || ((failed_validations++))
        fi
        
        if [ "$SECURITY_CHECK" = true ]; then
            validate_security || ((failed_validations++))
        fi
        
        # Generate simple report
        if [ $failed_validations -eq 0 ]; then
            log "SUCCESS" "All validations passed successfully!"
        else
            log "WARN" "$failed_validations validation(s) failed"
        fi
    fi
    
    log "INFO" "Validation completed. Check $LOG_FILE for detailed results."
}

# =============================================================================
# SCRIPT ENTRY POINT
# =============================================================================

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
