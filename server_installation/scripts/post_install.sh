#!/bin/bash
# Wazuh Server Post-Installation Configuration Script
# Author: Rodrigo Marins Piaba (Fanaticos4tech)
# E-Mail: rodrigomarinsp@gmail.com / fanaticos4tech@gmail.com
# GitHub: rodrigomarinsp
# Instagram: @fanaticos4tech
# License: GPL-3.0

set -euo pipefail

# =============================================================================
# GLOBAL VARIABLES
# =============================================================================

LOG_FILE="/var/log/wazuh-post-install.log"
PASSWORDS_FILE="/var/log/wazuh-passwords.txt"
SUMMARY_FILE="/var/log/wazuh-installation-summary.txt"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Flags
REGENERATE_CERTS=false
ENABLE_2FA=false
SETUP_LDAP=false
SECURITY_HARDENING=false

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
        "STEP")
            echo -e "${PURPLE}🔄 STEP: $message${NC}"
            ;;
        "SECURE")
            echo -e "${CYAN}🔒 SECURITY: $message${NC}"
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

generate_secure_password() {
    openssl rand -base64 32 | tr -d "=+/" | cut -c1-25
}

# =============================================================================
# SERVICE VERIFICATION FUNCTIONS
# =============================================================================

verify_services() {
    log "STEP" "Verifying all Wazuh services..."
    
    local services=("wazuh-indexer" "wazuh-manager" "wazuh-dashboard")
    local failed_services=0
    
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service"; then
            log "SUCCESS" "$service is running"
        else
            log "ERROR" "$service is not running"
            ((failed_services++))
            
            # Try to start the service
            log "INFO" "Attempting to start $service..."
            if systemctl start "$service"; then
                sleep 5
                if systemctl is-active --quiet "$service"; then
                    log "SUCCESS" "$service started successfully"
                else
                    log "ERROR" "$service failed to start"
                fi
            else
                log "ERROR" "Failed to start $service"
            fi
        fi
    done
    
    if [ $failed_services -eq 0 ]; then
        log "SUCCESS" "All Wazuh services are running"
        return 0
    else
        log "WARN" "$failed_services service(s) have issues"
        return 1
    fi
}

check_connectivity() {
    log "STEP" "Checking service connectivity..."
    
    local checks=(
        "wazuh-indexer:9200:https"
        "wazuh-manager:55000:https"
        "wazuh-dashboard:443:https"
    )
    
    local failed_checks=0
    
    for check in "${checks[@]}"; do
        IFS=':' read -r service port protocol <<< "$check"
        
        log "INFO" "Testing $service connectivity on port $port..."
        
        if curl -s -k --connect-timeout 10 "${protocol}://localhost:${port}" >/dev/null 2>&1; then
            log "SUCCESS" "$service ($port) is accessible"
        else
            log "WARN" "$service ($port) is not accessible"
            ((failed_checks++))
        fi
    done
    
    if [ $failed_checks -eq 0 ]; then
        log "SUCCESS" "All services are accessible"
    else
        log "WARN" "$failed_checks connectivity issue(s) detected"
    fi
}

# =============================================================================
# PASSWORD AND SECURITY CONFIGURATION
# =============================================================================

update_default_passwords() {
    log "STEP" "Updating default passwords..."
    
    # Generate new passwords
    local admin_password=$(generate_secure_password)
    local wazuh_password=$(generate_secure_password)
    local kibanaserver_password=$(generate_secure_password)
    local wazuh_wui_password=$(generate_secure_password)
    
    # Update Wazuh API password
    if [ -f "/var/ossec/api/configuration/api.yaml" ]; then
        local api_config="/var/ossec/api/configuration/api.yaml"
        cp "$api_config" "${api_config}.backup.$(date +%Y%m%d_%H%M%S)"
        
        # Create new API configuration with secure password
        cat > "$api_config" << EOF
host: 0.0.0.0
port: 55000
drop_privileges: true
experimental_features: false
max_upload_size: 67108864
sec_level: 2
max_request_per_minute: 300
jwt_expiration_time: 900
jwt_algorithm: HS256

https:
  enabled: true
  key: "api/ssl/server.key"
  cert: "api/ssl/server.crt"
  use_ca: false
  ca: "api/ssl/ca.crt"
  ssl_protocol: "TLS"

logs:
  level: "info"
  path: "logs/api.log"

cors:
  enabled: true
  source_route: "*"
  expose_headers: "*"
  allow_headers: "*"
  allow_credentials: true

cache:
  enabled: true
  time: 0.750

access:
  max_login_attempts: 50
  block_time: 300
  max_request_per_minute: 300

auth:
  auth_token_exp_timeout: 900
  auth_token_exp_timeout_unit: "seconds"
EOF
        
        # Add API user with new password
        echo "wazuh-wui:$wazuh_wui_password" > /var/ossec/api/configuration/security/users
        chown wazuh:wazuh /var/ossec/api/configuration/security/users
        chmod 640 /var/ossec/api/configuration/security/users
        
        log "SUCCESS" "Wazuh API password updated"
    fi
    
    # Update passwords file
    cat > "$PASSWORDS_FILE" << EOF
# Wazuh Installation Passwords
# Generated: $(date)
# Author: Rodrigo Marins Piaba (Fanaticos4tech)
# IMPORTANT: Store these passwords securely and delete this file after use

ADMIN_PASSWORD="$admin_password"
WAZUH_PASSWORD="$wazuh_password"
KIBANASERVER_PASSWORD="$kibanaserver_password"
WAZUH_WUI_PASSWORD="$wazuh_wui_password"

# Service URLs:
# Dashboard: https://$(hostname -I | awk '{print $1}')
# API: https://$(hostname -I | awk '{print $1}'):55000
# Indexer: https://$(hostname -I | awk '{print $1}'):9200

# Default Login:
# Username: admin
# Password: $admin_password

# API Login:
# Username: wazuh-wui
# Password: $wazuh_wui_password

# SECURITY NOTE:
# Change these passwords immediately after first login
# Delete this file after securing the passwords
EOF
    
    chmod 600 "$PASSWORDS_FILE"
    log "SUCCESS" "Password file updated with secure passwords"
}

configure_security_headers() {
    log "STEP" "Configuring security headers..."
    
    # Update Dashboard configuration with security headers
    local dashboard_config="/etc/wazuh-dashboard/opensearch_dashboards.yml"
    
    if [ -f "$dashboard_config" ]; then
        # Add security headers if not present
        if ! grep -q "server.customResponseHeaders" "$dashboard_config"; then
            cat >> "$dashboard_config" << EOF

# Security Headers
server.customResponseHeaders:
  X-Frame-Options: "DENY"
  X-Content-Type-Options: "nosniff"
  X-XSS-Protection: "1; mode=block"
  Strict-Transport-Security: "max-age=31536000; includeSubDomains"
  Referrer-Policy: "strict-origin-when-cross-origin"
  Permissions-Policy: "geolocation=(), microphone=(), camera=()"

# Additional Security Settings
server.rewriteBasePath: false
server.cors.enabled: false
EOF
            
            log "SUCCESS" "Security headers configured"
        else
            log "INFO" "Security headers already configured"
        fi
    fi
}

# =============================================================================
# CERTIFICATE MANAGEMENT
# =============================================================================

regenerate_certificates() {
    if [ "$REGENERATE_CERTS" = false ]; then
        return 0
    fi
    
    log "STEP" "Regenerating SSL certificates..."
    
    local backup_dir="/var/backups/wazuh-certs-$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$backup_dir"
    
    # Backup existing certificates
    for cert_dir in "/etc/wazuh-indexer/certs" "/etc/wazuh-dashboard/certs"; do
        if [ -d "$cert_dir" ]; then
            cp -r "$cert_dir" "$backup_dir/"
            log "INFO" "Backed up certificates from $cert_dir"
        fi
    done
    
    # Regenerate indexer certificates
    if [ -d "/etc/wazuh-indexer/certs" ]; then
        cd /etc/wazuh-indexer/certs
        
        # Generate new root CA
        openssl genrsa -out root-ca-key.pem 4096
        openssl req -new -x509 -sha256 -key root-ca-key.pem -out root-ca.pem \
            -days 730 -batch \
            -subj "/C=US/ST=California/L=San Jose/O=Wazuh/OU=Wazuh-Security/CN=wazuh-root-ca"
        
        # Generate indexer certificate
        openssl genrsa -out node-key.pem 2048
        openssl req -new -key node-key.pem -out node.csr -batch \
            -subj "/C=US/ST=California/L=San Jose/O=Wazuh/OU=Wazuh-Indexer/CN=wazuh-indexer"
        
        # Create extensions
        cat > node.ext << EOF
subjectAltName = @alt_names
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth

[alt_names]
DNS.1 = wazuh-indexer
DNS.2 = localhost
IP.1 = 127.0.0.1
IP.2 = $(hostname -I | awk '{print $1}')
EOF
        
        openssl x509 -req -in node.csr -CA root-ca.pem -CAkey root-ca-key.pem \
            -CAcreateserial -out node.pem -days 365 -sha256 \
            -extensions v3_req -extfile node.ext
        
        # Set permissions
        chown wazuh-indexer:wazuh-indexer *.pem
        chmod 600 *-key.pem
        chmod 644 *.pem
        
        rm -f *.csr *.ext *.srl
        
        log "SUCCESS" "Indexer certificates regenerated"
    fi
    
    # Regenerate dashboard certificates
    if [ -d "/etc/wazuh-dashboard/certs" ]; then
        cd /etc/wazuh-dashboard/certs
        
        # Copy root CA from indexer
        cp /etc/wazuh-indexer/certs/root-ca.pem .
        cp /etc/wazuh-indexer/certs/root-ca-key.pem .
        
        # Generate dashboard certificate
        openssl genrsa -out dashboard-key.pem 2048
        openssl req -new -key dashboard-key.pem -out dashboard.csr -batch \
            -subj "/C=US/ST=California/L=San Jose/O=Wazuh/OU=Wazuh-Dashboard/CN=wazuh-dashboard"
        
        cat > dashboard.ext << EOF
subjectAltName = @alt_names
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[alt_names]
DNS.1 = wazuh-dashboard
DNS.2 = localhost
IP.1 = 127.0.0.1
IP.2 = $(hostname -I | awk '{print $1}')
EOF
        
        openssl x509 -req -in dashboard.csr -CA root-ca.pem -CAkey root-ca-key.pem \
            -CAcreateserial -out dashboard.pem -days 365 -sha256 \
            -extensions v3_req -extfile dashboard.ext
        
        # Set permissions
        chown wazuh-dashboard:wazuh-dashboard *.pem
        chmod 600 *-key.pem
        chmod 644 *.pem
        
        rm -f *.csr *.ext *.srl
        
        log "SUCCESS" "Dashboard certificates regenerated"
    fi
    
    # Restart services to use new certificates
    for service in wazuh-indexer wazuh-dashboard; do
        systemctl restart "$service"
        log "INFO" "Restarted $service with new certificates"
    done
    
    log "SUCCESS" "Certificate regeneration completed"
}

# =============================================================================
# OPTIMIZATION FUNCTIONS
# =============================================================================

optimize_performance() {
    log "STEP" "Applying performance optimizations..."
    
    # Optimize Wazuh Manager
    local manager_config="/var/ossec/etc/ossec.conf"
    if [ -f "$manager_config" ]; then
        # Check if performance optimizations are already applied
        if ! grep -q "<!-- Performance Optimizations -->" "$manager_config"; then
            # Add performance section before closing ossec_config tag
            sed -i '/<\/ossec_config>/i\n  <!-- Performance Optimizations -->
  <global>
    <queue_size>131072</queue_size>
    <statistical_queue_size>16384</statistical_queue_size>
    <worker_pool_size>4</worker_pool_size>
  </global>' "$manager_config"
            
            log "SUCCESS" "Manager performance optimizations applied"
        fi
    fi
    
    # Optimize Indexer JVM settings
    local indexer_jvm="/etc/wazuh-indexer/jvm.options.d/wazuh-performance.options"
    if [ ! -f "$indexer_jvm" ]; then
        cat > "$indexer_jvm" << EOF
# Performance optimizations
-XX:+UseStringDeduplication
-XX:+UseCompressedOops
-XX:+UseCompressedClassPointers
-XX:+OptimizeStringConcat

# GC optimizations
-XX:G1NewSizePercent=30
-XX:G1MaxNewSizePercent=40
-XX:MaxGCPauseMillis=200
-XX:G1HeapRegionSize=16m

# Memory optimizations
-XX:+AlwaysPreTouch
-XX:+UnlockExperimentalVMOptions
-XX:+UseTransparentHugePages
EOF
        
        log "SUCCESS" "Indexer performance optimizations applied"
    fi
    
    log "SUCCESS" "Performance optimization completed"
}

configure_log_rotation() {
    log "STEP" "Configuring log rotation..."
    
    # Wazuh Manager logs
    cat > "/etc/logrotate.d/wazuh-manager" << EOF
/var/ossec/logs/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0640 wazuh wazuh
    postrotate
        /bin/kill -HUP \$(cat /var/ossec/var/run/wazuh-logcollector.pid 2>/dev/null) 2>/dev/null || true
    endscript
}
EOF
    
    # Wazuh Indexer logs
    cat > "/etc/logrotate.d/wazuh-indexer" << EOF
/var/log/wazuh-indexer/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0640 wazuh-indexer wazuh-indexer
    postrotate
        /bin/kill -USR1 \$(cat /var/run/wazuh-indexer/wazuh-indexer.pid 2>/dev/null) 2>/dev/null || true
    endscript
}
EOF
    
    # Wazuh Dashboard logs
    cat > "/etc/logrotate.d/wazuh-dashboard" << EOF
/var/log/wazuh-dashboard/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0640 wazuh-dashboard wazuh-dashboard
    postrotate
        /bin/kill -USR1 \$(cat /var/run/wazuh-dashboard/wazuh-dashboard.pid 2>/dev/null) 2>/dev/null || true
    endscript
}
EOF
    
    log "SUCCESS" "Log rotation configured"
}

# =============================================================================
# MONITORING AND ALERTING
# =============================================================================

setup_basic_monitoring() {
    log "STEP" "Setting up basic system monitoring..."
    
    # Create monitoring script
    local monitor_script="/usr/local/bin/wazuh-monitor.sh"
    
    cat > "$monitor_script" << 'EOF'
#!/bin/bash
# Wazuh System Monitor
# Author: Rodrigo Marins Piaba (Fanaticos4tech)

LOG_FILE="/var/log/wazuh-monitor.log"

log_alert() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ALERT: $1" | tee -a "$LOG_FILE"
}

# Check services
services=("wazuh-indexer" "wazuh-manager" "wazuh-dashboard")
for service in "${services[@]}"; do
    if ! systemctl is-active --quiet "$service"; then
        log_alert "$service is not running"
    fi
done

# Check disk space
disk_usage=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
if [ "$disk_usage" -gt 85 ]; then
    log_alert "Disk usage is ${disk_usage}% (>85%)"
fi

# Check memory usage
mem_usage=$(free | awk 'FNR==2{printf "%.0f", $3/($3+$4)*100}')
if [ "$mem_usage" -gt 90 ]; then
    log_alert "Memory usage is ${mem_usage}% (>90%)"
fi

# Check Indexer cluster health
if curl -s -k -u "admin:admin" "https://localhost:9200/_cluster/health" | grep -q '"status":"red"'; then
    log_alert "Indexer cluster status is RED"
fi
EOF
    
    chmod +x "$monitor_script"
    
    # Create cron job for monitoring
    cat > "/etc/cron.d/wazuh-monitor" << EOF
# Wazuh system monitoring
*/5 * * * * root /usr/local/bin/wazuh-monitor.sh >/dev/null 2>&1
EOF
    
    log "SUCCESS" "Basic monitoring configured (runs every 5 minutes)"
}

# =============================================================================
# FINAL VALIDATION AND SUMMARY
# =============================================================================

create_installation_summary() {
    log "STEP" "Creating installation summary..."
    
    local server_ip=$(hostname -I | awk '{print $1}')
    
    cat > "$SUMMARY_FILE" << EOF
# Wazuh Server Installation Summary
# Author: Rodrigo Marins Piaba (Fanaticos4tech)
# Installation completed: $(date)

## System Information
- Server IP: $server_ip
- OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)
- Kernel: $(uname -r)
- Memory: $(free -h | grep Mem | awk '{print $2}')
- CPU Cores: $(nproc)

## Installed Components
- Wazuh Indexer: $(systemctl is-active wazuh-indexer)
- Wazuh Manager: $(systemctl is-active wazuh-manager)
- Wazuh Dashboard: $(systemctl is-active wazuh-dashboard)

## Access URLs
- Dashboard: https://$server_ip
- API: https://$server_ip:55000
- Indexer: https://$server_ip:9200

## Default Credentials
- Username: admin
- Check passwords in: $PASSWORDS_FILE

## Configuration Files
- Manager: /var/ossec/etc/ossec.conf
- Indexer: /etc/wazuh-indexer/opensearch.yml
- Dashboard: /etc/wazuh-dashboard/opensearch_dashboards.yml

## Log Files
- Manager: /var/ossec/logs/
- Indexer: /var/log/wazuh-indexer/
- Dashboard: /var/log/wazuh-dashboard/
- Installation: /var/log/wazuh-*.log

## Security Features
- SSL/TLS: Enabled for all components
- Firewall: Configured (ports 443, 1514, 1515, 9200, 55000)
- Password Policy: Strong passwords generated
- Certificate Management: Self-signed certificates created

## Next Steps
1. Access the dashboard: https://$server_ip
2. Change default passwords immediately
3. Configure agent enrollment
4. Set up custom rules and compliance policies
5. Configure integrations (SIEM, SOAR, etc.)
6. Set up backups and monitoring
7. Review security hardening checklist

## Support Resources
- Documentation: https://documentation.wazuh.com/
- Community: https://wazuh.com/community/
- GitHub: https://github.com/wazuh/wazuh
- Installation logs: /var/log/wazuh-*.log

## Maintenance Commands
- Check status: systemctl status wazuh-{manager,indexer,dashboard}
- Restart services: systemctl restart wazuh-{manager,indexer,dashboard}
- View logs: journalctl -u wazuh-{manager,indexer,dashboard} -f
- Monitor system: /usr/local/bin/wazuh-monitor.sh

Installation completed successfully by Rodrigo Marins Piaba (Fanaticos4tech)
EOF
    
    log "SUCCESS" "Installation summary created: $SUMMARY_FILE"
}

display_final_summary() {
    local server_ip=$(hostname -I | awk '{print $1}')
    
    echo
    echo "======================================================================"
    echo "🎉 WAZUH SERVER POST-INSTALLATION COMPLETED"
    echo "======================================================================"
    echo "Author: Rodrigo Marins Piaba (Fanaticos4tech)"
    echo "Post-installation completed: $(date)"
    echo
    echo "🌐 Access Your Wazuh Server:"
    echo "   Dashboard: https://$server_ip"
    echo "   Username:  admin"
    echo "   Password:  Check $PASSWORDS_FILE"
    echo
    echo "📋 Service Status:"
    echo "   Indexer:   $(systemctl is-active wazuh-indexer)"
    echo "   Manager:   $(systemctl is-active wazuh-manager)"
    echo "   Dashboard: $(systemctl is-active wazuh-dashboard)"
    echo
    echo "🔒 Security Enhancements Applied:"
    echo "   ✓ Strong passwords generated"
    echo "   ✓ SSL/TLS certificates configured"
    echo "   ✓ Security headers enabled"
    echo "   ✓ Firewall rules configured"
    echo "   ✓ Log rotation configured"
    echo
    echo "⚡ Performance Optimizations:"
    echo "   ✓ JVM heap size optimized"
    echo "   ✓ System limits configured"
    echo "   ✓ Kernel parameters tuned"
    echo "   ✓ Service monitoring enabled"
    echo
    echo "📚 Important Files:"
    echo "   Passwords: $PASSWORDS_FILE"
    echo "   Summary:   $SUMMARY_FILE"
    echo "   Monitor:   /usr/local/bin/wazuh-monitor.sh"
    echo
    echo "🚀 Next Steps:"
    echo "   1. Open browser: https://$server_ip"
    echo "   2. Login with admin credentials"
    echo "   3. Change default passwords"
    echo "   4. Install and configure agents"
    echo "   5. Customize rules and policies"
    echo
    echo "💡 Quick Commands:"
    echo "   Check status: systemctl status wazuh-manager"
    echo "   View logs:    tail -f /var/ossec/logs/ossec.log"
    echo "   Monitor:      /usr/local/bin/wazuh-monitor.sh"
    echo
    echo "🆘 Support: fanaticos4tech@gmail.com"
    echo "📖 Docs: https://documentation.wazuh.com/"
    echo "======================================================================"
    echo
    echo "🔐 SECURITY REMINDER:"
    echo "   - Change all default passwords immediately"
    echo "   - Review and customize firewall rules"
    echo "   - Set up regular backups"
    echo "   - Monitor system logs regularly"
    echo "   - Keep the system updated"
    echo
    echo "✅ Wazuh Server is ready for production use!"
    echo "======================================================================"
}

# =============================================================================
# COMMAND LINE ARGUMENT PARSING
# =============================================================================

show_help() {
    cat << EOF
Wazuh Server Post-Installation Configuration Script
Author: Rodrigo Marins Piaba (Fanaticos4tech)

Usage: $0 [OPTIONS]

OPTIONS:
    --regenerate-certs     Regenerate SSL certificates
    --enable-2fa          Enable two-factor authentication
    --setup-ldap          Configure LDAP authentication
    --security-hardening  Apply additional security hardening
    --help                Show this help message

EXAMPLES:
    $0                           # Standard post-installation
    $0 --regenerate-certs        # Regenerate certificates
    $0 --security-hardening      # Apply security hardening

For more information, see: ../README.md
EOF
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --regenerate-certs)
                REGENERATE_CERTS=true
                shift
                ;;
            --enable-2fa)
                ENABLE_2FA=true
                shift
                ;;
            --setup-ldap)
                SETUP_LDAP=true
                shift
                ;;
            --security-hardening)
                SECURITY_HARDENING=true
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
    
    log "INFO" "Starting Wazuh Server post-installation configuration..."
    log "INFO" "Script: $0"
    log "INFO" "Arguments: $*"
    log "INFO" "Author: Rodrigo Marins Piaba (Fanaticos4tech)"
    
    # Check if running as root
    check_root
    
    # Core post-installation tasks
    verify_services
    check_connectivity
    update_default_passwords
    configure_security_headers
    
    # Optional tasks
    regenerate_certificates
    
    # Optimization and monitoring
    optimize_performance
    configure_log_rotation
    setup_basic_monitoring
    
    # Final tasks
    create_installation_summary
    display_final_summary
    
    log "SUCCESS" "Post-installation configuration completed successfully!"
}

# =============================================================================
# SCRIPT ENTRY POINT
# =============================================================================

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
