#!/bin/bash
# Wazuh Dashboard Installation Script
# Author: Rodrigo Marins Piaba (Fanaticos4tech)
# E-Mail: rodrigomarinsp@gmail.com / fanaticos4tech@gmail.com
# GitHub: rodrigomarinsp
# Instagram: @fanaticos4tech
# License: GPL-3.0

set -euo pipefail

# =============================================================================
# GLOBAL VARIABLES
# =============================================================================

LOG_FILE="/var/log/wazuh-dashboard-install.log"
CONFIG_DIR="/etc/wazuh-dashboard"
DATA_DIR="/var/lib/wazuh-dashboard"
LOGS_DIR="/var/log/wazuh-dashboard"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

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

detect_package_manager() {
    if command -v apt >/dev/null 2>&1; then
        export PKG_MANAGER="apt"
        export PKG_INSTALL="apt install -y"
    elif command -v dnf >/dev/null 2>&1; then
        export PKG_MANAGER="dnf"
        export PKG_INSTALL="dnf install -y"
    elif command -v yum >/dev/null 2>&1; then
        export PKG_MANAGER="yum"
        export PKG_INSTALL="yum install -y"
    else
        error_exit "No supported package manager found"
    fi
}

generate_random_password() {
    openssl rand -base64 32 | tr -d "=+/" | cut -c1-25
}

# =============================================================================
# INSTALLATION FUNCTIONS
# =============================================================================

install_wazuh_dashboard() {
    log "STEP" "Installing Wazuh Dashboard package..."
    
    # Install the package
    $PKG_INSTALL wazuh-dashboard || error_exit "Failed to install Wazuh Dashboard"
    
    log "SUCCESS" "Wazuh Dashboard package installed"
}

configure_dashboard() {
    log "STEP" "Configuring Wazuh Dashboard..."
    
    # Backup original configuration
    if [ -f "$CONFIG_DIR/opensearch_dashboards.yml" ]; then
        cp "$CONFIG_DIR/opensearch_dashboards.yml" "$CONFIG_DIR/opensearch_dashboards.yml.backup.$(date +%Y%m%d_%H%M%S)"
        log "INFO" "Original configuration backed up"
    fi
    
    # Get server IP
    local server_ip=$(hostname -I | awk '{print $1}' || echo "127.0.0.1")
    local cookie_password=$(generate_random_password)
    
    # Create enhanced opensearch_dashboards.yml configuration
    cat > "$CONFIG_DIR/opensearch_dashboards.yml" << EOF
# Wazuh Dashboard Configuration
# Author: Rodrigo Marins Piaba (Fanaticos4tech)

# Server Configuration
server.host: 0.0.0.0
server.port: 443
server.name: wazuh-dashboard
server.basePath: ""
server.maxPayloadBytes: 1048576

# SSL Configuration
server.ssl.enabled: true
server.ssl.key: "$CONFIG_DIR/certs/dashboard-key.pem"
server.ssl.certificate: "$CONFIG_DIR/certs/dashboard.pem"
server.ssl.certificateAuthorities: ["$CONFIG_DIR/certs/root-ca.pem"]
server.ssl.supportedProtocols: ["TLSv1.2", "TLSv1.3"]
server.ssl.clientAuthentication: optional
server.ssl.verificationMode: certificate
server.ssl.cipherSuites:
  - ECDHE-RSA-AES256-GCM-SHA384
  - ECDHE-RSA-AES128-GCM-SHA256
  - ECDHE-RSA-AES256-SHA384
  - ECDHE-RSA-AES128-SHA256

# OpenSearch Configuration
opensearch.hosts: ["https://localhost:9200"]
opensearch.ssl.verificationMode: certificate
opensearch.ssl.certificateAuthorities: ["$CONFIG_DIR/certs/root-ca.pem"]
opensearch.ssl.certificate: "$CONFIG_DIR/certs/dashboard.pem"
opensearch.ssl.key: "$CONFIG_DIR/certs/dashboard-key.pem"

opensearch.username: "kibanaserver"
opensearch.password: "kibanaserver"

opensearch.requestHeadersWhitelist: ["securitytenant", "Authorization"]
opensearch.requestTimeout: 120000
opensearch.shardTimeout: 30000
opensearch.pingTimeout: 3000
opensearch.startupTimeout: 5000

# Wazuh API Configuration
wazuh.api.timeout: 20000

# Multiple API connections support
wazuh.hosts:
  - default:
      url: https://localhost
      port: 55000
      username: wazuh-wui
      password: MyS3cr37P455w0rd!
      run_as: false

# Logging Configuration
logging.appenders.default:
  type: file
  fileName: $LOGS_DIR/wazuh-dashboard.log
  layout:
    type: json

logging.appenders.console:
  type: console
  layout:
    type: pattern
    pattern: "[%date] [%level] [%logger] %message"

logging.root:
  appenders: [default, console]
  level: info

logging.loggers:
  - name: http.server.response
    level: debug
    appenders: [default]
    additivity: false
  - name: plugins.wazuh
    level: info
    appenders: [default]
    additivity: false

# Security Configuration
opensearch_security.multitenancy.enabled: true
opensearch_security.multitenancy.tenants.preferred: ["Private", "Global"]

opensearch_security.auth.type: basicauth
opensearch_security.auth.anonymous_auth_enabled: false

opensearch_security.cookie.secure: true
opensearch_security.cookie.name: "wazuh-dashboard-auth"
opensearch_security.cookie.password: "$cookie_password"

opensearch_security.session.ttl: 86400000
opensearch_security.session.keepalive: true

# Visualization Configuration
vis.defaultAggregation: terms

map.includeOpenSearchMapsService: false
map.proxyOpenSearchMapsServiceInMaps: false
map.tilemap.url: "https://tiles-{s}.elastic.co/v2/default/{z}/{x}/{y}.png?elastic_tile_service_tos=agree"
map.tilemap.options.minZoom: 0
map.tilemap.options.maxZoom: 12
map.tilemap.options.attribution: "© OpenSearch Contributors | © OpenStreetMap contributors"

# Monitoring Configuration
monitoring.enabled: false
status.allowAnonymous: false

# Console Configuration
console.enabled: true

# Discover Configuration
discover.sampleSize: 500
discover.aggs.terms.size: 20

# Advanced Settings
dateFormat: "MMM D, YYYY @ HH:mm:ss.SSS"
dateFormat:tz: Browser
defaultColumns: ["_source"]
defaultIndex: "wazuh-alerts-*"
doc_table.highlight: true
filterByEnabled: true
histogram.barTarget: 50
histogram.maxBars: 100
metaFields: ["_source", "_id", "_type", "_index", "_score"]
query.allowLeadingWildcards: true
query.queryString.options: {}
search.queryLanguage: kuery
sort.options: ["desc", "asc"]
state.storeInSessionStorage: false
truncate.maxHeight: 500

# Data Configuration
data.autocomplete.valueSuggestions.enabled: true
data.autocomplete.valueSuggestions.method: terms_agg
data.autocomplete.valueSuggestions.size: 10
data.autocomplete.valueSuggestions.timeout: 1000

# Saved Objects Configuration
savedObjects.maxImportPayloadBytes: 26214400
savedObjects.maxImportExportSize: 10000

# Search Configuration
search.timeout: 600000

# Visualization Configuration
visualization.colorMapping: {}
visualization.regionmap.includeOpenSearchMapsService: false
visualization.loadingDelay: 2000

# Telemetry Configuration
telemetry.enabled: false
telemetry.allowChangingOptInStatus: false
telemetry.optIn: false

# Home Configuration
home.disableWelcomeScreen: true

# News Feed Configuration
newsfeed.enabled: false

# Usage Collection Configuration
usage_collection.enabled: false

# Security Headers
csp.rules:
  - "script-src 'self' 'unsafe-eval'"
  - "style-src 'self' 'unsafe-inline'"
  - "connect-src 'self'"

# Performance Configuration
ops.interval: 5000
ops.cGroupOverrides.cpuPath: "/sys/fs/cgroup/cpu"
ops.cGroupOverrides.cpuAcctPath: "/sys/fs/cgroup/cpuacct"

# Migration Configuration
migrations.batchSize: 1000
migrations.scrollDuration: "15m"
migrations.pollInterval: 1500
migrations.skip: false

# Path Configuration
pid.file: "/var/run/wazuh-dashboard/wazuh-dashboard.pid"
pid.exclusive: false
path.data: "$DATA_DIR"

# Wazuh App Configuration
wazuh.pattern: "wazuh-alerts-*"

wazuh.monitoring.enabled: true
wazuh.monitoring.frequency: 900
wazuh.monitoring.shards: 1
wazuh.monitoring.replicas: 0
wazuh.monitoring.creation: "h"
wazuh.monitoring.pattern: "wazuh-monitoring-*"

wazuh.statistics.enabled: true
wazuh.statistics.indices: "statistics"
wazuh.statistics.frequency: 900
wazuh.statistics.shards: 1
wazuh.statistics.replicas: 0
wazuh.statistics.creation: "w"
wazuh.statistics.pattern: "wazuh-statistics-*"

wazuh.vulnerabilities.pattern: "wazuh-alerts-*"

wazuh.sample.prefix: "wazuh-sample"
wazuh.sample.template: "wazuh-sample-template"
wazuh.sample.alerts.sampleSize: 500

wazuh.timeout: 20000
wazuh.checkUpdates: true
wazuh.hideManagerAlerts: false

# Default extensions
wazuh.extensions.pci: true
wazuh.extensions.gdpr: true
wazuh.extensions.hipaa: true
wazuh.extensions.nist: true
wazuh.extensions.tsc: true
wazuh.extensions.audit: true
wazuh.extensions.oscap: false
wazuh.extensions.ciscat: false
wazuh.extensions.aws: false
wazuh.extensions.gcp: false
wazuh.extensions.virustotal: false
wazuh.extensions.osquery: false
wazuh.extensions.docker: false

# Custom branding
wazuh.customization.enabled: false
wazuh.customization.logo.app: ""
wazuh.customization.logo.sidebar: ""
wazuh.customization.logo.login: ""
wazuh.customization.logo.reports: ""

# IP selector
wazuh.ip.selector: true
wazuh.ip.ignore: []

# Logs level
wazuh.logs.level: "info"

# Enrollment DNS
wazuh.enrollment.dns: ""
wazuh.enrollment.password: ""

# Application Configuration
newPlatform.enabled: true

# Plugin Configuration
plugins.scanDirs: []
plugins.initialize: true

security.showInsecureClusterWarning: false

# Disabled features
timelion.enabled: false
vega.enabled: false
cross_cluster_search.enabled: false
watcher.enabled: false

# X-Pack Configuration
xpack.encryptedSavedObjects.encryptionKey: "fhjskloppd678ehkdfdlliverpoolfcr"
xpack.reporting.enabled: false
xpack.security.enabled: false
xpack.ml.enabled: false

# Dashboard-only mode
dashboard_only_mode.enabled: false

EOF

    log "SUCCESS" "Wazuh Dashboard configuration updated"
}

generate_certificates() {
    log "STEP" "Generating SSL certificates for Dashboard..."
    
    local cert_dir="$CONFIG_DIR/certs"
    mkdir -p "$cert_dir"
    
    # Check if root CA exists (from indexer installation)
    if [ ! -f "/etc/wazuh-indexer/certs/root-ca.pem" ]; then
        log "WARN" "Root CA not found, generating new certificates"
        
        # Generate root CA
        openssl genrsa -out "$cert_dir/root-ca-key.pem" 2048
        openssl req -new -x509 -sha256 -key "$cert_dir/root-ca-key.pem" -out "$cert_dir/root-ca.pem" \
            -days 365 -batch \
            -subj "/C=US/ST=California/L=San Jose/O=Wazuh/OU=Wazuh/CN=root-ca"
    else
        # Copy root CA from indexer
        cp "/etc/wazuh-indexer/certs/root-ca.pem" "$cert_dir/"
        cp "/etc/wazuh-indexer/certs/root-ca-key.pem" "$cert_dir/" 2>/dev/null || true
    fi
    
    # Generate dashboard certificate
    openssl genrsa -out "$cert_dir/dashboard-key.pem" 2048
    openssl req -new -key "$cert_dir/dashboard-key.pem" -out "$cert_dir/dashboard.csr" \
        -batch \
        -subj "/C=US/ST=California/L=San Jose/O=Wazuh/OU=Wazuh/CN=wazuh-dashboard"
    
    # Create certificate extensions
    cat > "$cert_dir/dashboard.ext" << EOF
subjectAltName = @alt_names

[alt_names]
DNS.1 = wazuh-dashboard
DNS.2 = localhost
IP.1 = 127.0.0.1
IP.2 = $(hostname -I | awk '{print $1}')
EOF
    
    # Sign dashboard certificate
    if [ -f "$cert_dir/root-ca-key.pem" ]; then
        openssl x509 -req -in "$cert_dir/dashboard.csr" -CA "$cert_dir/root-ca.pem" \
            -CAkey "$cert_dir/root-ca-key.pem" -CAcreateserial \
            -out "$cert_dir/dashboard.pem" -days 365 -sha256 \
            -extensions v3_req -extfile "$cert_dir/dashboard.ext"
    else
        # Fallback: generate self-signed certificate
        openssl x509 -req -in "$cert_dir/dashboard.csr" -signkey "$cert_dir/dashboard-key.pem" \
            -out "$cert_dir/dashboard.pem" -days 365 -sha256 \
            -extensions v3_req -extfile "$cert_dir/dashboard.ext"
    fi
    
    # Set proper permissions
    chown -R wazuh-dashboard:wazuh-dashboard "$cert_dir"
    chmod 600 "$cert_dir"/*.pem
    chmod 644 "$cert_dir/root-ca.pem" "$cert_dir/dashboard.pem"
    
    # Clean up temporary files
    rm -f "$cert_dir"/*.csr "$cert_dir"/*.ext "$cert_dir"/*.srl
    
    log "SUCCESS" "SSL certificates generated for Dashboard"
}

configure_systemd() {
    log "STEP" "Configuring systemd service..."
    
    # Create systemd override directory
    local override_dir="/etc/systemd/system/wazuh-dashboard.service.d"
    mkdir -p "$override_dir"
    
    # Create override configuration
    cat > "$override_dir/override.conf" << EOF
[Unit]
Description=Wazuh Dashboard
Documentation=https://documentation.wazuh.com
Wants=network-online.target
After=network-online.target wazuh-indexer.service

[Service]
Type=simple
User=wazuh-dashboard
Group=wazuh-dashboard
RuntimeDirectory=wazuh-dashboard
RuntimeDirectoryMode=0755
Environment=NODE_ENV=production
Environment=NODE_OPTIONS="--max-old-space-size=4096"
WorkingDirectory=/usr/share/wazuh-dashboard
ExecStart=/usr/share/wazuh-dashboard/bin/opensearch-dashboards --config $CONFIG_DIR/opensearch_dashboards.yml

StandardOutput=journal
StandardError=inherit

Restart=on-failure
RestartSec=5
TimeoutStopSec=0
KillMode=process
KillSignal=SIGTERM

LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd
    systemctl daemon-reload
    
    log "SUCCESS" "Systemd service configured"
}

set_permissions() {
    log "STEP" "Setting proper permissions..."
    
    # Create directories if they don't exist
    mkdir -p "$DATA_DIR" "$LOGS_DIR"
    
    # Set ownership
    chown -R wazuh-dashboard:wazuh-dashboard "$CONFIG_DIR" "$DATA_DIR" "$LOGS_DIR"
    chown -R wazuh-dashboard:wazuh-dashboard "/usr/share/wazuh-dashboard"
    
    # Set permissions
    chmod 750 "$CONFIG_DIR" "$DATA_DIR" "$LOGS_DIR"
    chmod 640 "$CONFIG_DIR/opensearch_dashboards.yml"
    
    # Create PID directory
    mkdir -p "/var/run/wazuh-dashboard"
    chown wazuh-dashboard:wazuh-dashboard "/var/run/wazuh-dashboard"
    chmod 755 "/var/run/wazuh-dashboard"
    
    log "SUCCESS" "Permissions set"
}

configure_wazuh_plugin() {
    log "STEP" "Configuring Wazuh plugin..."
    
    # Plugin configuration is handled through the main config file
    # Create additional plugin configurations if needed
    
    local plugin_config="/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml"
    local plugin_dir=$(dirname "$plugin_config")
    
    mkdir -p "$plugin_dir"
    
    cat > "$plugin_config" << EOF
# Wazuh Plugin Configuration
# Author: Rodrigo Marins Piaba (Fanaticos4tech)

pattern: wazuh-alerts-*
timeout: 20000
ip.selector: true
ip.ignore: []
xpack.rbac.enabled: false
wazuh.monitoring.enabled: true
wazuh.monitoring.frequency: 900
admin: true
hideManagerAlerts: false

# API Hosts
hosts:
  - default:
      url: https://localhost
      port: 55000
      username: wazuh-wui
      password: MyS3cr37P455w0rd!
      run_as: false

# Extensions
extensions.pci: true
extensions.gdpr: true
extensions.hipaa: true
extensions.nist: true
extensions.tsc: true
extensions.audit: true
extensions.oscap: false
extensions.ciscat: false
extensions.aws: false
extensions.gcp: false
extensions.virustotal: false
extensions.osquery: false
extensions.docker: false

# Customization
customization.enabled: false
customization.logo.app: ''
customization.logo.sidebar: ''
customization.logo.login: ''
customization.logo.reports: ''

# Logs
logs.level: info

# Sample data
sample.prefix: wazuh-sample
sample.template: wazuh-sample-template
sample.alerts.sampleSize: 500

EOF

    chown wazuh-dashboard:wazuh-dashboard "$plugin_config"
    chmod 640 "$plugin_config"
    
    log "SUCCESS" "Wazuh plugin configured"
}

start_and_enable_service() {
    log "STEP" "Starting and enabling Wazuh Dashboard service..."
    
    # Enable service
    systemctl enable wazuh-dashboard
    
    # Start service
    systemctl start wazuh-dashboard
    
    # Wait for service to be ready
    local timeout=180
    local count=0
    
    log "INFO" "Waiting for Wazuh Dashboard to be ready..."
    
    while [ $count -lt $timeout ]; do
        if curl -s -k "https://localhost:443" >/dev/null 2>&1; then
            break
        fi
        sleep 2
        ((count+=2))
    done
    
    if [ $count -ge $timeout ]; then
        error_exit "Wazuh Dashboard failed to start within $timeout seconds"
    fi
    
    log "SUCCESS" "Wazuh Dashboard service started and ready"
}

configure_reverse_proxy() {
    log "STEP" "Checking for reverse proxy configuration..."
    
    # Check if nginx or apache is installed
    if command -v nginx >/dev/null 2>&1; then
        log "INFO" "Nginx detected. Consider configuring reverse proxy."
        
        # Create nginx configuration snippet
        cat > "/tmp/wazuh-dashboard-nginx.conf" << EOF
# Nginx configuration for Wazuh Dashboard
# Place this in your nginx sites-available directory

server {
    listen 80;
    server_name wazuh-dashboard.local;
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name wazuh-dashboard.local;

    ssl_certificate /etc/wazuh-dashboard/certs/dashboard.pem;
    ssl_certificate_key /etc/wazuh-dashboard/certs/dashboard-key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256;
    ssl_prefer_server_ciphers on;

    location / {
        proxy_pass https://localhost:443;
        proxy_ssl_verify off;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF
        
        log "INFO" "Nginx configuration template created at /tmp/wazuh-dashboard-nginx.conf"
    fi
    
    log "SUCCESS" "Reverse proxy check completed"
}

display_dashboard_info() {
    log "INFO" "Wazuh Dashboard installation completed!"
    
    local server_ip=$(hostname -I | awk '{print $1}')
    
    echo
    echo "======================================================================"
    echo "🌐 WAZUH DASHBOARD INSTALLATION SUMMARY"
    echo "======================================================================"
    echo "Author: Rodrigo Marins Piaba (Fanaticos4tech)"
    echo "Installation completed: $(date)"
    echo
    echo "📋 Service Information:"
    echo "   Status: $(systemctl is-active wazuh-dashboard)"
    echo "   Config: $CONFIG_DIR/opensearch_dashboards.yml"
    echo "   Data:   $DATA_DIR"
    echo "   Logs:   $LOGS_DIR"
    echo "   URL:    https://$server_ip:443"
    echo
    echo "🔐 Access Information:"
    echo "   Default URL: https://$server_ip"
    echo "   Username: admin"
    echo "   Password: admin (change immediately!)"
    echo
    echo "🔒 Security:"
    echo "   SSL/TLS: Enabled"
    echo "   Certificates: $CONFIG_DIR/certs/"
    echo "   Multi-tenancy: Enabled"
    echo
    echo "⚙️ Configuration:"
    echo "   Wazuh API: https://localhost:55000"
    echo "   OpenSearch: https://localhost:9200"
    echo "   Index Pattern: wazuh-alerts-*"
    echo
    echo "📚 Next Steps:"
    echo "   1. Access the dashboard and change default passwords"
    echo "   2. Configure Wazuh API connections"
    echo "   3. Set up index patterns and visualizations"
    echo "   4. Configure user roles and permissions"
    echo "   5. Customize branding (optional)"
    echo
    echo "🛠️ Useful Commands:"
    echo "   Check status: systemctl status wazuh-dashboard"
    echo "   View logs:    journalctl -u wazuh-dashboard -f"
    echo "   Restart:      systemctl restart wazuh-dashboard"
    echo "   Test access:  curl -k https://localhost:443"
    echo
    echo "🌐 Browser Access:"
    echo "   Open your browser and navigate to: https://$server_ip"
    echo "   Accept the self-signed certificate warning"
    echo "   Login with admin/admin and change the password immediately"
    echo "======================================================================"
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

main() {
    log "INFO" "Starting Wazuh Dashboard installation..."
    log "INFO" "Author: Rodrigo Marins Piaba (Fanaticos4tech)"
    
    # Check prerequisites
    check_root
    detect_package_manager
    
    # Install and configure
    install_wazuh_dashboard
    configure_dashboard
    generate_certificates
    configure_systemd
    set_permissions
    configure_wazuh_plugin
    start_and_enable_service
    configure_reverse_proxy
    
    # Display summary
    display_dashboard_info
    
    log "SUCCESS" "Wazuh Dashboard installation completed successfully!"
}

# =============================================================================
# SCRIPT ENTRY POINT
# =============================================================================

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
