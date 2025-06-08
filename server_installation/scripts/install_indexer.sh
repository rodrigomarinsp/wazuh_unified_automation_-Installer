#!/bin/bash
# Wazuh Indexer Installation Script
# Author: Rodrigo Marins Piaba (Fanaticos4tech)
# E-Mail: rodrigomarinsp@gmail.com / fanaticos4tech@gmail.com
# GitHub: rodrigomarinsp
# Instagram: @fanaticos4tech
# License: GPL-3.0

set -euo pipefail

# =============================================================================
# GLOBAL VARIABLES
# =============================================================================

LOG_FILE="/var/log/wazuh-indexer-install.log"
CONFIG_DIR="/etc/wazuh-indexer"
DATA_DIR="/var/lib/wazuh-indexer"
LOGS_DIR="/var/log/wazuh-indexer"

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

get_system_memory() {
    # Get total memory in GB
    local mem_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    local mem_gb=$((mem_kb / 1024 / 1024))
    echo $mem_gb
}

calculate_heap_size() {
    local total_mem=$(get_system_memory)
    local heap_size
    
    # Set heap size to 50% of available memory, with limits
    if [ $total_mem -le 2 ]; then
        heap_size="1g"
    elif [ $total_mem -le 4 ]; then
        heap_size="2g"
    elif [ $total_mem -le 8 ]; then
        heap_size="4g"
    elif [ $total_mem -le 16 ]; then
        heap_size="8g"
    else
        heap_size="16g"
    fi
    
    echo "$heap_size"
}

# =============================================================================
# INSTALLATION FUNCTIONS
# =============================================================================

install_wazuh_indexer() {
    log "STEP" "Installing Wazuh Indexer package..."
    
    # Install the package
    $PKG_INSTALL wazuh-indexer || error_exit "Failed to install Wazuh Indexer"
    
    log "SUCCESS" "Wazuh Indexer package installed"
}

configure_indexer() {
    log "STEP" "Configuring Wazuh Indexer..."
    
    # Backup original configuration
    if [ -f "$CONFIG_DIR/opensearch.yml" ]; then
        cp "$CONFIG_DIR/opensearch.yml" "$CONFIG_DIR/opensearch.yml.backup.$(date +%Y%m%d_%H%M%S)"
        log "INFO" "Original configuration backed up"
    fi
    
    # Get server IP
    local server_ip=$(hostname -I | awk '{print $1}' || echo "127.0.0.1")
    
    # Create enhanced opensearch.yml configuration
    cat > "$CONFIG_DIR/opensearch.yml" << EOF
# Wazuh Indexer Configuration
# Author: Rodrigo Marins Piaba (Fanaticos4tech)

# ======================== OpenSearch Configuration =========================

# Cluster Configuration
cluster.name: wazuh-cluster
node.name: wazuh-indexer
node.roles: [master, data, ingest]

# Network Configuration
network.host: 0.0.0.0
network.bind_host: 0.0.0.0
network.publish_host: $server_ip
http.port: 9200
transport.port: 9300

# Path Configuration
path.data: $DATA_DIR
path.logs: $LOGS_DIR
path.repo: $DATA_DIR/backup

# Memory Configuration
bootstrap.memory_lock: true

# Discovery Configuration
discovery.type: single-node
discovery.seed_hosts: ["127.0.0.1:9300"]

# Security Configuration
plugins.security.ssl.transport.pemcert_filepath: certs/node.pem
plugins.security.ssl.transport.pemkey_filepath: certs/node-key.pem
plugins.security.ssl.transport.pemtrustedcas_filepath: certs/root-ca.pem
plugins.security.ssl.transport.enforce_hostname_verification: false
plugins.security.ssl.transport.resolve_hostname: false

plugins.security.ssl.http.enabled: true
plugins.security.ssl.http.pemcert_filepath: certs/node.pem
plugins.security.ssl.http.pemkey_filepath: certs/node-key.pem
plugins.security.ssl.http.pemtrustedcas_filepath: certs/root-ca.pem
plugins.security.ssl.http.clientauth_mode: OPTIONAL

plugins.security.authcz.admin_dn:
- CN=admin,OU=Wazuh,O=Wazuh,L=California,C=US

plugins.security.check_snapshot_restore_write_privileges: true
plugins.security.enable_snapshot_restore_privilege: true
plugins.security.system_indices.enabled: true
plugins.security.system_indices.indices:
- ".opendistro-alerting-config"
- ".opendistro-alerting-alert*"
- ".opendistro-anomaly-results*"
- ".opendistro-anomaly-detector*"
- ".opendistro-anomaly-checkpoints"
- ".opendistro-anomaly-detection-state"
- ".opendistro-reports-*"
- ".opendistro-notifications-*"
- ".opendistro-notebooks"
- ".opendistro-asynchronous-search-response*"

plugins.security.restapi.roles_enabled: ["all_access", "security_rest_api_access"]

# Index Management
indices.query.bool.max_clause_count: 10000
indices.fielddata.cache.size: 20%
indices.requests.cache.size: 1%
indices.recovery.max_bytes_per_sec: 40mb

# Thread Pool Configuration
thread_pool:
  search:
    size: 4
    queue_size: 1000
  search_throttled:
    size: 1
    queue_size: 100
  write:
    size: 4
    queue_size: 1000

# Action Configuration
action.destructive_requires_name: true
action.auto_create_index: true

# Cluster Routing
cluster.routing.allocation.enable: all
cluster.routing.allocation.node_concurrent_incoming_recoveries: 2
cluster.routing.allocation.node_concurrent_outgoing_recoveries: 2
cluster.routing.allocation.node_initial_primaries_recoveries: 4
cluster.routing.allocation.same_shard.host: false

cluster.routing.allocation.disk.threshold_enabled: true
cluster.routing.allocation.disk.watermark.low: 85%
cluster.routing.allocation.disk.watermark.high: 90%
cluster.routing.allocation.disk.watermark.flood_stage: 95%

# Monitoring
monitor.jvm.gc.enabled: true
monitor.jvm.gc.overhead.warn: 50
monitor.jvm.gc.overhead.info: 25
monitor.jvm.gc.overhead.debug: 10

# Performance Tuning
index.codec: best_compression
index.mapping.total_fields.limit: 10000
index.max_result_window: 100000
index.max_docvalue_fields_search: 200

# Search Configuration
search.max_buckets: 65536
search.max_open_scroll_context: 500
search.default_search_timeout: 30s

# HTTP Configuration
http.compression: true
http.compression_level: 6
http.cors.enabled: true
http.cors.allow-origin: "*"
http.cors.max-age: 86400
http.cors.allow-methods: OPTIONS,HEAD,GET,POST,PUT,DELETE
http.cors.allow-headers: X-Requested-With,X-Auth-Token,Content-Type,Content-Length,Authorization
http.cors.allow-credentials: true

# Wazuh Template Settings
wazuh.template.pattern: "wazuh-alerts-*"
wazuh.monitoring.enabled: true
wazuh.monitoring.frequency: 900
wazuh.monitoring.shards: 1
wazuh.monitoring.replicas: 0

# Disable X-Pack features
xpack.ml.enabled: false
xpack.monitoring.enabled: false
xpack.security.enabled: false

# Experimental Features
experimental.feature.composite_template.enabled: false

EOF

    log "SUCCESS" "Wazuh Indexer configuration updated"
}

configure_jvm_options() {
    log "STEP" "Configuring JVM options..."
    
    local jvm_options="$CONFIG_DIR/jvm.options.d/wazuh-indexer.options"
    local heap_size=$(calculate_heap_size)
    
    # Create JVM options file
    cat > "$jvm_options" << EOF
# Wazuh Indexer JVM Configuration
# Author: Rodrigo Marins Piaba (Fanaticos4tech)

# Heap size (set to 50% of available memory)
-Xms$heap_size
-Xmx$heap_size

# GC Configuration
-XX:+UseG1GC
-XX:G1HeapRegionSize=32m
-XX:+UseG1GCApplicationConcurrentTime
-XX:MaxGCPauseMillis=200
-XX:+UnlockExperimentalVMOptions
-XX:+UseStringDeduplication

# Memory Configuration
-XX:+AlwaysPreTouch
-Xss1m
-Djava.awt.headless=true

# File Encoding
-Dfile.encoding=UTF-8

# Network Configuration
-Djava.net.preferIPv4Stack=true

# Temporary Directory
-Djava.io.tmpdir=/tmp

# Security Manager
-Djava.security.manager=default
-Djava.security.policy=$CONFIG_DIR/opensearch.policy

# Log4j Configuration
-Dlog4j2.disable.jmx=true
-Dlog4j.shutdownHookEnabled=false
-Dlog4j2.formatMsgNoLookups=true

# Performance Optimizations
-XX:+UseCompressedOops
-XX:+UseCompressedClassPointers
-XX:+OptimizeStringConcat

# Debug Options (commented out for production)
# -XX:+PrintGCDetails
# -XX:+PrintGCTimeStamps
# -XX:+PrintGCApplicationStoppedTime
# -Xloggc:/var/log/wazuh-indexer/gc.log

EOF

    log "SUCCESS" "JVM options configured with heap size: $heap_size"
}

generate_certificates() {
    log "STEP" "Generating SSL certificates..."
    
    local cert_dir="$CONFIG_DIR/certs"
    mkdir -p "$cert_dir"
    
    # Generate root CA
    openssl genrsa -out "$cert_dir/root-ca-key.pem" 2048
    openssl req -new -x509 -sha256 -key "$cert_dir/root-ca-key.pem" -out "$cert_dir/root-ca.pem" \
        -days 365 -batch \
        -subj "/C=US/ST=California/L=San Jose/O=Wazuh/OU=Wazuh/CN=root-ca"
    
    # Generate node certificate
    openssl genrsa -out "$cert_dir/node-key.pem" 2048
    openssl req -new -key "$cert_dir/node-key.pem" -out "$cert_dir/node.csr" \
        -batch \
        -subj "/C=US/ST=California/L=San Jose/O=Wazuh/OU=Wazuh/CN=wazuh-indexer"
    
    # Create certificate extensions
    cat > "$cert_dir/node.ext" << EOF
subjectAltName = @alt_names

[alt_names]
DNS.1 = wazuh-indexer
DNS.2 = localhost
IP.1 = 127.0.0.1
IP.2 = $(hostname -I | awk '{print $1}')
EOF
    
    # Sign node certificate
    openssl x509 -req -in "$cert_dir/node.csr" -CA "$cert_dir/root-ca.pem" \
        -CAkey "$cert_dir/root-ca-key.pem" -CAcreateserial \
        -out "$cert_dir/node.pem" -days 365 -sha256 \
        -extensions v3_req -extfile "$cert_dir/node.ext"
    
    # Generate admin certificate
    openssl genrsa -out "$cert_dir/admin-key.pem" 2048
    openssl req -new -key "$cert_dir/admin-key.pem" -out "$cert_dir/admin.csr" \
        -batch \
        -subj "/C=US/ST=California/L=San Jose/O=Wazuh/OU=Wazuh/CN=admin"
    
    openssl x509 -req -in "$cert_dir/admin.csr" -CA "$cert_dir/root-ca.pem" \
        -CAkey "$cert_dir/root-ca-key.pem" -CAcreateserial \
        -out "$cert_dir/admin.pem" -days 365 -sha256
    
    # Set proper permissions
    chown -R wazuh-indexer:wazuh-indexer "$cert_dir"
    chmod 600 "$cert_dir"/*.pem
    chmod 644 "$cert_dir/root-ca.pem" "$cert_dir/node.pem" "$cert_dir/admin.pem"
    
    # Clean up temporary files
    rm -f "$cert_dir"/*.csr "$cert_dir"/*.ext "$cert_dir"/*.srl
    
    log "SUCCESS" "SSL certificates generated"
}

configure_systemd() {
    log "STEP" "Configuring systemd service..."
    
    # Create systemd override directory
    local override_dir="/etc/systemd/system/wazuh-indexer.service.d"
    mkdir -p "$override_dir"
    
    # Create override configuration
    cat > "$override_dir/override.conf" << EOF
[Unit]
Description=Wazuh Indexer
Documentation=https://documentation.wazuh.com
Wants=network-online.target
After=network-online.target

[Service]
Type=notify
RuntimeDirectory=wazuh-indexer
RuntimeDirectoryMode=0755
Environment=OPENSEARCH_HOME=$CONFIG_DIR
Environment=OPENSEARCH_PATH_CONF=$CONFIG_DIR
WorkingDirectory=$CONFIG_DIR
User=wazuh-indexer
Group=wazuh-indexer
ExecStart=/usr/share/wazuh-indexer/bin/opensearch

StandardOutput=journal
StandardError=inherit

LimitNOFILE=65535
LimitNPROC=4096
LimitAS=infinity
LimitFSIZE=infinity

TimeoutStopSec=0
KillMode=process
KillSignal=SIGTERM
SendSIGKILL=no

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
    chown -R wazuh-indexer:wazuh-indexer "$CONFIG_DIR" "$DATA_DIR" "$LOGS_DIR"
    
    # Set permissions
    chmod 750 "$CONFIG_DIR" "$DATA_DIR" "$LOGS_DIR"
    chmod 640 "$CONFIG_DIR/opensearch.yml"
    
    log "SUCCESS" "Permissions set"
}

configure_wazuh_template() {
    log "STEP" "Installing Wazuh index template..."
    
    # Create temporary template file
    local template_file="/tmp/wazuh-template.json"
    
    cat > "$template_file" << 'EOF'
{
  "index_patterns": ["wazuh-alerts-*"],
  "priority": 1,
  "template": {
    "settings": {
      "index": {
        "number_of_shards": 1,
        "number_of_replicas": 0,
        "refresh_interval": "5s",
        "codec": "best_compression",
        "mapping": {
          "total_fields": {
            "limit": 10000
          }
        },
        "max_result_window": 100000,
        "max_docvalue_fields_search": 200
      }
    },
    "mappings": {
      "properties": {
        "@timestamp": {
          "type": "date"
        },
        "timestamp": {
          "type": "date",
          "format": "yyyy-MM-dd HH:mm:ss||yyyy-MM-dd||epoch_millis"
        },
        "rule": {
          "properties": {
            "level": {
              "type": "long"
            },
            "id": {
              "type": "keyword"
            },
            "description": {
              "type": "text"
            }
          }
        },
        "agent": {
          "properties": {
            "id": {
              "type": "keyword"
            },
            "name": {
              "type": "keyword"
            },
            "ip": {
              "type": "ip"
            }
          }
        },
        "location": {
          "type": "keyword"
        },
        "full_log": {
          "type": "text"
        }
      }
    }
  }
}
EOF

    # Template will be applied after service starts
    log "SUCCESS" "Wazuh template prepared"
}

start_and_enable_service() {
    log "STEP" "Starting and enabling Wazuh Indexer service..."
    
    # Enable service
    systemctl enable wazuh-indexer
    
    # Start service
    systemctl start wazuh-indexer
    
    # Wait for service to be ready
    local timeout=120
    local count=0
    
    log "INFO" "Waiting for Wazuh Indexer to be ready..."
    
    while [ $count -lt $timeout ]; do
        if curl -s -k -u "admin:admin" "https://localhost:9200" >/dev/null 2>&1; then
            break
        fi
        sleep 2
        ((count+=2))
    done
    
    if [ $count -ge $timeout ]; then
        error_exit "Wazuh Indexer failed to start within $timeout seconds"
    fi
    
    log "SUCCESS" "Wazuh Indexer service started and ready"
}

apply_wazuh_template() {
    log "STEP" "Applying Wazuh index template..."
    
    local template_file="/tmp/wazuh-template.json"
    
    if [ -f "$template_file" ]; then
        # Apply the template
        if curl -s -k -u "admin:admin" -X PUT "https://localhost:9200/_index_template/wazuh" \
            -H "Content-Type: application/json" \
            -d @"$template_file" >/dev/null; then
            log "SUCCESS" "Wazuh index template applied"
        else
            log "WARN" "Failed to apply Wazuh index template"
        fi
        
        # Clean up
        rm -f "$template_file"
    fi
}

display_indexer_info() {
    log "INFO" "Wazuh Indexer installation completed!"
    
    echo
    echo "======================================================================"
    echo "🔍 WAZUH INDEXER INSTALLATION SUMMARY"
    echo "======================================================================"
    echo "Author: Rodrigo Marins Piaba (Fanaticos4tech)"
    echo "Installation completed: $(date)"
    echo
    echo "📋 Service Information:"
    echo "   Status: $(systemctl is-active wazuh-indexer)"
    echo "   Config: $CONFIG_DIR/opensearch.yml"
    echo "   Data:   $DATA_DIR"
    echo "   Logs:   $LOGS_DIR"
    echo "   URL:    https://$(hostname -I | awk '{print $1}'):9200"
    echo
    echo "💾 System Configuration:"
    echo "   JVM Heap: $(calculate_heap_size)"
    echo "   Memory:   $(get_system_memory)GB total"
    echo
    echo "🔐 Security:"
    echo "   SSL/TLS: Enabled"
    echo "   Certificates: $CONFIG_DIR/certs/"
    echo "   Default credentials: admin/admin"
    echo
    echo "📚 Next Steps:"
    echo "   1. Change default passwords"
    echo "   2. Configure index lifecycle policies"
    echo "   3. Set up monitoring"
    echo "   4. Configure backups"
    echo
    echo "🛠️ Useful Commands:"
    echo "   Check status: systemctl status wazuh-indexer"
    echo "   View logs:    journalctl -u wazuh-indexer -f"
    echo "   Test API:     curl -k -u admin:admin https://localhost:9200"
    echo "   Restart:      systemctl restart wazuh-indexer"
    echo "======================================================================"
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

main() {
    log "INFO" "Starting Wazuh Indexer installation..."
    log "INFO" "Author: Rodrigo Marins Piaba (Fanaticos4tech)"
    
    # Check prerequisites
    check_root
    detect_package_manager
    
    # Install and configure
    install_wazuh_indexer
    configure_indexer
    configure_jvm_options
    generate_certificates
    configure_systemd
    set_permissions
    configure_wazuh_template
    start_and_enable_service
    apply_wazuh_template
    
    # Display summary
    display_indexer_info
    
    log "SUCCESS" "Wazuh Indexer installation completed successfully!"
}

# =============================================================================
# SCRIPT ENTRY POINT
# =============================================================================

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
