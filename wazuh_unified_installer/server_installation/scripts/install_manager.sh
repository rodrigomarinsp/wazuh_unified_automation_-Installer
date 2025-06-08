#!/bin/bash
# Wazuh Manager Installation Script
# Author: Rodrigo Marins Piaba (Fanaticos4tech)
# E-Mail: rodrigomarinsp@gmail.com / fanaticos4tech@gmail.com
# GitHub: rodrigomarinsp
# Instagram: @fanaticos4tech
# License: GPL-3.0

set -euo pipefail

# =============================================================================
# GLOBAL VARIABLES
# =============================================================================

LOG_FILE="/var/log/wazuh-manager-install.log"
CONFIG_DIR="/var/ossec/etc"
RULES_DIR="/var/ossec/ruleset"
LOGS_DIR="/var/ossec/logs"

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

# =============================================================================
# INSTALLATION FUNCTIONS
# =============================================================================

install_wazuh_manager() {
    log "STEP" "Installing Wazuh Manager package..."
    
    # Install the package
    $PKG_INSTALL wazuh-manager || error_exit "Failed to install Wazuh Manager"
    
    log "SUCCESS" "Wazuh Manager package installed"
}

configure_manager() {
    log "STEP" "Configuring Wazuh Manager..."
    
    # Backup original configuration
    if [ -f "$CONFIG_DIR/ossec.conf" ]; then
        cp "$CONFIG_DIR/ossec.conf" "$CONFIG_DIR/ossec.conf.backup.$(date +%Y%m%d_%H%M%S)"
        log "INFO" "Original configuration backed up"
    fi
    
    # Create enhanced ossec.conf
    cat > "$CONFIG_DIR/ossec.conf" << 'EOF'
<ossec_config>
  <!-- Global Configuration -->
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>no</logall>
    <logall_json>no</logall_json>
    <email_notification>no</email_notification>
    <smtp_server>localhost</smtp_server>
    <email_from>wazuh@localhost</email_from>
    <email_to>admin@localhost</email_to>
    <email_maxperhour>12</email_maxperhour>
    <email_log_source>alerts.log</email_log_source>
    <agents_disconnection_time>10m</agents_disconnection_time>
    <agents_disconnection_alert_time>0</agents_disconnection_alert_time>
  </global>

  <!-- Rules Configuration -->
  <rules>
    <decoder_dir>ruleset/decoders</decoder_dir>
    <rule_dir>ruleset/rules</rule_dir>
    <rule_exclude>0215-policy_rules.xml</rule_exclude>
    <list>etc/lists/audit-keys</list>
    <list>etc/lists/amazon/aws-eventnames</list>
    <list>etc/lists/security-eventchannel</list>
  </rules>

  <!-- Alerts Configuration -->
  <alerts>
    <log_alert_level>3</log_alert_level>
    <email_alert_level>12</email_alert_level>
  </alerts>

  <!-- Remote Configuration -->
  <remote>
    <connection>secure</connection>
    <port>1514</port>
    <protocol>tcp</protocol>
    <queue_size>131072</queue_size>
  </remote>

  <!-- Authentication Configuration -->
  <auth>
    <disabled>no</disabled>
    <port>1515</port>
    <use_source_ip>no</use_source_ip>
    <force_insert>yes</force_insert>
    <force_time>0</force_time>
    <purge>yes</purge>
    <use_password>no</use_password>
    <limit_maxagents>yes</limit_maxagents>
    <ciphers>HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH</ciphers>
    <ssl_verify_host>no</ssl_verify_host>
    <ssl_manager_cert>etc/sslmanager.cert</ssl_manager_cert>
    <ssl_manager_key>etc/sslmanager.key</ssl_manager_key>
    <ssl_auto_negotiate>no</ssl_auto_negotiate>
  </auth>

  <!-- Cluster Configuration -->
  <cluster>
    <name>wazuh</name>
    <node_name>master</node_name>
    <node_type>master</node_type>
    <key></key>
    <port>1516</port>
    <bind_addr>0.0.0.0</bind_addr>
    <nodes>
        <node>NODE_IP</node>
    </nodes>
    <hidden>no</hidden>
    <disabled>yes</disabled>
  </cluster>

  <!-- Vulnerability Detector -->
  <vulnerability-detector>
    <enabled>yes</enabled>
    <interval>5m</interval>
    <min_full_scan_interval>6h</min_full_scan_interval>
    <run_on_start>yes</run_on_start>
    
    <!-- Ubuntu Feed -->
    <provider name="canonical">
      <enabled>yes</enabled>
      <os>trusty</os>
      <os>xenial</os>
      <os>bionic</os>
      <os>focal</os>
      <os>jammy</os>
      <update_interval>1h</update_interval>
    </provider>
    
    <!-- Debian Feed -->
    <provider name="debian">
      <enabled>yes</enabled>
      <os>wheezy</os>
      <os>jessie</os>
      <os>stretch</os>
      <os>buster</os>
      <os>bullseye</os>
      <update_interval>1h</update_interval>
    </provider>
    
    <!-- RedHat Feed -->
    <provider name="redhat">
      <enabled>yes</enabled>
      <os>5</os>
      <os>6</os>
      <os>7</os>
      <os>8</os>
      <os>9</os>
      <update_interval>1h</update_interval>
    </provider>
    
    <!-- NVD Feed -->
    <provider name="nvd">
      <enabled>yes</enabled>
      <update_interval>1h</update_interval>
    </provider>
  </vulnerability-detector>

  <!-- Log Analysis -->
  <localfile>
    <log_format>command</log_format>
    <command>df -P</command>
    <frequency>360</frequency>
  </localfile>

  <localfile>
    <log_format>full_command</log_format>
    <command>netstat -tulpn | sed 's/\([[:alnum:]]\+\)\ \+\([[:digit:]]\+\)\ \+\([[:digit:]]\+\)\ \+\(.*\):\([[:digit:]]\*\)\ \+\(.*\):\([[:digit:]\*]\+\)\ \+\([[:upper:]]\+\)\ \+\([[:digit:]\*]\+\/[[:alnum:]\-]*\)*/\2 \4 \5 \6 \7 \8 \9/' | sort -k 9 -g | sed 's/.*\/\([[:alnum:]\-]*\)/\1/' | sed 1,2d</command>
    <alias>netstat listening ports</alias>
    <frequency>360</frequency>
  </localfile>

  <localfile>
    <log_format>full_command</log_format>
    <command>last -n 20</command>
    <frequency>360</frequency>
  </localfile>

  <!-- Rootcheck -->
  <rootcheck>
    <disabled>no</disabled>
    <check_files>yes</check_files>
    <check_trojans>yes</check_trojans>
    <check_dev>yes</check_dev>
    <check_sys>yes</check_sys>
    <check_pids>yes</check_pids>
    <check_ports>yes</check_ports>
    <check_if>yes</check_if>
    <frequency>43200</frequency>
    <rootkit_files>etc/shared/rootkit_files.txt</rootkit_files>
    <rootkit_trojans>etc/shared/rootkit_trojans.txt</rootkit_trojans>
    <skip_nfs>yes</skip_nfs>
  </rootcheck>

  <!-- File Integrity Monitoring -->
  <syscheck>
    <disabled>no</disabled>
    <frequency>43200</frequency>
    <scan_on_start>yes</scan_on_start>
    <auto_ignore frequency="10" timeframe="3600">no</auto_ignore>
    <alert_new_files>yes</alert_new_files>
    <remove_old_diff>yes</remove_old_diff>
    <restart_audit>yes</restart_audit>

    <!-- Directories to monitor -->
    <directories>/etc,/usr/bin,/usr/sbin</directories>
    <directories>/bin,/sbin,/boot</directories>

    <!-- Files/directories to ignore -->
    <ignore>/etc/mtab</ignore>
    <ignore>/etc/hosts.deny</ignore>
    <ignore>/etc/mail/statistics</ignore>
    <ignore>/etc/random-seed</ignore>
    <ignore>/etc/random.seed</ignore>
    <ignore>/etc/adjtime</ignore>
    <ignore>/etc/httpd/logs</ignore>
    <ignore>/etc/utmpx</ignore>
    <ignore>/etc/wtmpx</ignore>
    <ignore>/etc/cups/certs</ignore>
    <ignore>/etc/dumpdates</ignore>
    <ignore>/etc/svc/volatile</ignore>

    <!-- Check the file, but never compute the diff -->
    <nodiff>/etc/ssl/private.key</nodiff>

    <skip_nfs>yes</skip_nfs>
    <skip_dev>yes</skip_dev>
    <skip_proc>yes</skip_proc>
    <skip_sys>yes</skip_sys>

    <!-- Nice value for Syscheck process -->
    <process_priority>10</process_priority>

    <!-- Maximum output throughput -->
    <max_eps>100</max_eps>

    <!-- Database to save checksum of monitored files -->
    <database>disk</database>

    <!-- Checking sum method -->
    <checksum>sha1+md5+sha256</checksum>
  </syscheck>

  <!-- System Call Monitoring -->
  <wodle name="syscollector">
    <disabled>no</disabled>
    <interval>1h</interval>
    <scan_on_start>yes</scan_on_start>
    <hardware>yes</hardware>
    <os>yes</os>
    <network>yes</network>
    <packages>yes</packages>
    <ports all="no">yes</ports>
    <processes>yes</processes>
  </wodle>

  <!-- Security Configuration Assessment -->
  <wodle name="sca">
    <enabled>yes</enabled>
    <scan_on_start>yes</scan_on_start>
    <interval>12h</interval>
    <skip_nfs>yes</skip_nfs>
  </wodle>

  <!-- Active Response -->
  <command>
    <name>disable-account</name>
    <executable>disable-account</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>restart-ossec</name>
    <executable>restart-ossec</executable>
  </command>

  <command>
    <name>firewall-drop</name>
    <executable>firewall-drop</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>host-deny</name>
    <executable>host-deny</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>route-null</name>
    <executable>route-null</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>win_route-null</name>
    <executable>route-null.exe</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>netsh</name>
    <executable>netsh.exe</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <!-- Log format -->
  <labels>
    <label key="aws.instance-id">yes</label>
    <label key="aws.account-id">yes</label>
    <label key="aws.region">yes</label>
  </labels>

</ossec_config>
EOF

    log "SUCCESS" "Wazuh Manager configuration updated"
}

configure_api() {
    log "STEP" "Configuring Wazuh API..."
    
    # API configuration file
    local api_config="/var/ossec/api/configuration/api.yaml"
    
    if [ -f "$api_config" ]; then
        # Backup original API configuration
        cp "$api_config" "${api_config}.backup.$(date +%Y%m%d_%H%M%S)"
        
        # Update API configuration
        cat > "$api_config" << EOF
# Wazuh API Configuration
# Author: Rodrigo Marins Piaba (Fanaticos4tech)

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
  ssl_ciphers: ""

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

# Authentication methods
auth:
  auth_token_exp_timeout: 900
  auth_token_exp_timeout_unit: "seconds"
EOF
        
        log "SUCCESS" "Wazuh API configuration updated"
    else
        log "WARN" "API configuration file not found"
    fi
}

generate_ssl_certificates() {
    log "STEP" "Generating SSL certificates..."
    
    local ssl_dir="/var/ossec/etc/ssl"
    mkdir -p "$ssl_dir"
    
    # Generate SSL certificates for Manager
    openssl req -x509 -batch -nodes -days 365 -newkey rsa:2048 \
        -keyout "$ssl_dir/sslmanager.key" \
        -out "$ssl_dir/sslmanager.cert" \
        -subj "/C=US/ST=California/L=San Jose/O=Wazuh/OU=Wazuh/CN=wazuh-manager"
    
    # Set proper permissions
    chmod 600 "$ssl_dir/sslmanager.key"
    chmod 644 "$ssl_dir/sslmanager.cert"
    chown root:wazuh "$ssl_dir/sslmanager.key" "$ssl_dir/sslmanager.cert"
    
    # Generate API SSL certificates
    local api_ssl_dir="/var/ossec/api/ssl"
    mkdir -p "$api_ssl_dir"
    
    openssl req -x509 -batch -nodes -days 365 -newkey rsa:2048 \
        -keyout "$api_ssl_dir/server.key" \
        -out "$api_ssl_dir/server.crt" \
        -subj "/C=US/ST=California/L=San Jose/O=Wazuh/OU=Wazuh-API/CN=wazuh-api"
    
    # Set proper permissions for API certificates
    chmod 600 "$api_ssl_dir/server.key"
    chmod 644 "$api_ssl_dir/server.crt"
    chown root:wazuh "$api_ssl_dir/server.key" "$api_ssl_dir/server.crt"
    
    log "SUCCESS" "SSL certificates generated"
}

configure_custom_rules() {
    log "STEP" "Installing custom rules..."
    
    # Create local rules file
    local local_rules="/var/ossec/etc/rules/local_rules.xml"
    
    cat > "$local_rules" << 'EOF'
<!-- Local Rules -->
<!-- Author: Rodrigo Marins Piaba (Fanaticos4tech) -->

<group name="local,syslog,sshd,">

  <!-- SSH Login attempts -->
  <rule id="100001" level="5">
    <if_sid>5700</if_sid>
    <match>Failed password</match>
    <description>SSH login attempt failed.</description>
    <group>authentication_failed,pci_dss_10.2.4,pci_dss_10.2.5,</group>
  </rule>

  <rule id="100002" level="10" frequency="8" timeframe="120">
    <if_matched_sid>100001</if_matched_sid>
    <description>SSH brute force attack (8 failed attempts in 120 seconds).</description>
    <group>authentication_failures,pci_dss_11.4,pci_dss_10.2.4,pci_dss_10.2.5,</group>
  </rule>

  <!-- Web server attacks -->
  <rule id="100003" level="7">
    <if_sid>31100</if_sid>
    <url>admin|wp-admin|administrator|login|phpMyAdmin</url>
    <description>Common web attack pattern detected.</description>
    <group>attack,web,pci_dss_6.5.10,</group>
  </rule>

  <!-- File changes in sensitive directories -->
  <rule id="100004" level="12">
    <if_sid>550</if_sid>
    <field name="file">/etc/passwd|/etc/shadow|/etc/sudoers</field>
    <description>Critical system file modified.</description>
    <group>syscheck,pci_dss_11.5,</group>
  </rule>

  <!-- Multiple authentication failures -->
  <rule id="100005" level="10" frequency="5" timeframe="300">
    <if_matched_group>authentication_failed</if_matched_group>
    <description>Multiple authentication failures from same source.</description>
    <group>authentication_failures,pci_dss_10.2.4,pci_dss_10.2.5,</group>
  </rule>

</group>
EOF

    # Set proper permissions
    chown root:wazuh "$local_rules"
    chmod 640 "$local_rules"
    
    log "SUCCESS" "Custom rules installed"
}

start_and_enable_services() {
    log "STEP" "Starting and enabling Wazuh Manager services..."
    
    # Reload systemd
    systemctl daemon-reload
    
    # Enable and start Wazuh Manager
    systemctl enable wazuh-manager
    systemctl start wazuh-manager
    
    # Wait for service to be ready
    local timeout=60
    local count=0
    while ! systemctl is-active --quiet wazuh-manager; do
        if [ $count -ge $timeout ]; then
            error_exit "Wazuh Manager failed to start within $timeout seconds"
        fi
        sleep 1
        ((count++))
    done
    
    log "SUCCESS" "Wazuh Manager service started"
    
    # Check if API is responding
    local api_timeout=30
    local api_count=0
    while ! curl -s -k https://localhost:55000 >/dev/null 2>&1; do
        if [ $api_count -ge $api_timeout ]; then
            log "WARN" "Wazuh API not responding after $api_timeout seconds"
            break
        fi
        sleep 1
        ((api_count++))
    done
    
    if [ $api_count -lt $api_timeout ]; then
        log "SUCCESS" "Wazuh API is responding"
    fi
}

create_agent_groups() {
    log "STEP" "Creating default agent groups..."
    
    # Create default groups
    local groups=("linux" "windows" "macos" "servers" "workstations")
    
    for group in "${groups[@]}"; do
        if [ ! -d "/var/ossec/etc/shared/$group" ]; then
            mkdir -p "/var/ossec/etc/shared/$group"
            chown wazuh:wazuh "/var/ossec/etc/shared/$group"
            log "INFO" "Created agent group: $group"
        fi
    done
    
    log "SUCCESS" "Default agent groups created"
}

display_manager_info() {
    log "INFO" "Wazuh Manager installation completed!"
    
    echo
    echo "======================================================================"
    echo "🧠 WAZUH MANAGER INSTALLATION SUMMARY"
    echo "======================================================================"
    echo "Author: Rodrigo Marins Piaba (Fanaticos4tech)"
    echo "Installation completed: $(date)"
    echo
    echo "📋 Service Information:"
    echo "   Status: $(systemctl is-active wazuh-manager)"
    echo "   Config: $CONFIG_DIR/ossec.conf"
    echo "   Logs:   $LOGS_DIR/"
    echo "   API:    https://$(hostname -I | awk '{print $1}'):55000"
    echo
    echo "🔐 Authentication:"
    echo "   Agent enrollment port: 1515"
    echo "   Agent communication port: 1514"
    echo "   API port: 55000"
    echo
    echo "📚 Next Steps:"
    echo "   1. Configure API users (if needed)"
    echo "   2. Install and configure agents"
    echo "   3. Customize rules and decoders"
    echo "   4. Set up integrations"
    echo
    echo "🛠️ Useful Commands:"
    echo "   Check status: systemctl status wazuh-manager"
    echo "   View logs:    tail -f $LOGS_DIR/ossec.log"
    echo "   Restart:      systemctl restart wazuh-manager"
    echo "======================================================================"
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

main() {
    log "INFO" "Starting Wazuh Manager installation..."
    log "INFO" "Author: Rodrigo Marins Piaba (Fanaticos4tech)"
    
    # Check prerequisites
    check_root
    detect_package_manager
    
    # Install and configure
    install_wazuh_manager
    configure_manager
    configure_api
    generate_ssl_certificates
    configure_custom_rules
    create_agent_groups
    start_and_enable_services
    
    # Display summary
    display_manager_info
    
    log "SUCCESS" "Wazuh Manager installation completed successfully!"
}

# =============================================================================
# SCRIPT ENTRY POINT
# =============================================================================

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
