#!/bin/bash
# Wazuh Server Pre-Installation Script
# Author: Rodrigo Marins Piaba (Fanaticos4tech)
# E-Mail: rodrigomarinsp@gmail.com / fanaticos4tech@gmail.com
# GitHub: rodrigomarinsp
# Instagram: @fanaticos4tech
# License: GPL-3.0

set -euo pipefail

# =============================================================================
# GLOBAL VARIABLES
# =============================================================================

LOG_FILE="/var/log/wazuh-pre-install.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Flags
CHECK_ONLY=false
SKIP_UPDATES=false
FORCE=false

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

detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        export OS_NAME="$ID"
        export OS_VERSION="$VERSION_ID"
        export OS_CODENAME="${VERSION_CODENAME:-}"
    else
        error_exit "Cannot detect operating system. /etc/os-release not found."
    fi
    
    log "INFO" "Detected OS: $OS_NAME $OS_VERSION"
    
    case "$OS_NAME" in
        ubuntu|debian)
            export PKG_MANAGER="apt"
            export PKG_UPDATE="apt update"
            export PKG_INSTALL="apt install -y"
            export PKG_UPGRADE="apt upgrade -y"
            ;;
        centos|rhel|rocky|almalinux|fedora)
            export PKG_MANAGER="yum"
            export PKG_UPDATE="yum update -y"
            export PKG_INSTALL="yum install -y"
            export PKG_UPGRADE="yum upgrade -y"
            if command -v dnf >/dev/null 2>&1; then
                export PKG_MANAGER="dnf"
                export PKG_UPDATE="dnf update -y"
                export PKG_INSTALL="dnf install -y"
                export PKG_UPGRADE="dnf upgrade -y"
            fi
            ;;
        *)
            error_exit "Unsupported operating system: $OS_NAME"
            ;;
    esac
}

# =============================================================================
# SYSTEM CHECKS
# =============================================================================

check_system_requirements() {
    log "STEP" "Checking system requirements..."
    
    local failed_checks=0
    
    # Check RAM
    local ram_gb=$(free -g | awk '/^Mem:/{print $2}')
    if [ "$ram_gb" -lt 4 ]; then
        log "WARN" "RAM: ${ram_gb}GB detected. Minimum 4GB recommended for production."
        if [ "$FORCE" = false ]; then
            ((failed_checks++))
        fi
    else
        log "SUCCESS" "RAM: ${ram_gb}GB - Adequate"
    fi
    
    # Check CPU cores
    local cpu_cores=$(nproc)
    if [ "$cpu_cores" -lt 2 ]; then
        log "WARN" "CPU cores: $cpu_cores detected. Minimum 2 cores recommended."
        if [ "$FORCE" = false ]; then
            ((failed_checks++))
        fi
    else
        log "SUCCESS" "CPU cores: $cpu_cores - Adequate"
    fi
    
    # Check disk space
    local disk_space_gb=$(df / | awk 'NR==2 {print int($4/1024/1024)}')
    if [ "$disk_space_gb" -lt 50 ]; then
        log "WARN" "Free disk space: ${disk_space_gb}GB. Minimum 50GB recommended."
        if [ "$FORCE" = false ]; then
            ((failed_checks++))
        fi
    else
        log "SUCCESS" "Free disk space: ${disk_space_gb}GB - Adequate"
    fi
    
    # Check architecture
    local arch=$(uname -m)
    if [[ "$arch" != "x86_64" ]]; then
        log "WARN" "Architecture: $arch detected. x86_64 recommended."
    else
        log "SUCCESS" "Architecture: $arch - Supported"
    fi
    
    # Check kernel version
    local kernel_version=$(uname -r)
    log "INFO" "Kernel version: $kernel_version"
    
    if [ $failed_checks -gt 0 ] && [ "$FORCE" = false ]; then
        error_exit "$failed_checks system requirement(s) not met. Use --force to override."
    fi
    
    log "SUCCESS" "System requirements check completed"
}

check_network_connectivity() {
    log "STEP" "Checking network connectivity..."
    
    local urls=(
        "https://packages.wazuh.com"
        "https://github.com"
        "https://api.github.com"
        "8.8.8.8"
    )
    
    local failed_connections=0
    
    for url in "${urls[@]}"; do
        if curl -s --connect-timeout 10 "$url" >/dev/null 2>&1; then
            log "SUCCESS" "Connectivity to $url - OK"
        else
            log "WARN" "Connectivity to $url - Failed"
            ((failed_connections++))
        fi
    done
    
    if [ $failed_connections -gt 0 ]; then
        log "WARN" "$failed_connections connectivity test(s) failed. Check network configuration."
    else
        log "SUCCESS" "Network connectivity check completed"
    fi
}

check_required_ports() {
    log "STEP" "Checking required ports availability..."
    
    local ports=(443 9200 55000 1514 1515)
    local ports_in_use=0
    
    for port in "${ports[@]}"; do
        if ss -tulpn | grep -q ":$port "; then
            local process=$(ss -tulpn | grep ":$port " | awk '{print $7}' | head -1)
            log "WARN" "Port $port is already in use by: $process"
            ((ports_in_use++))
        else
            log "SUCCESS" "Port $port is available"
        fi
    done
    
    if [ $ports_in_use -gt 0 ]; then
        log "WARN" "$ports_in_use required port(s) are in use. This may cause conflicts."
        if [ "$FORCE" = false ]; then
            error_exit "Port conflicts detected. Use --force to override."
        fi
    else
        log "SUCCESS" "All required ports are available"
    fi
}

# =============================================================================
# SYSTEM PREPARATION
# =============================================================================

update_system_packages() {
    if [ "$SKIP_UPDATES" = true ]; then
        log "INFO" "Skipping system updates as requested"
        return 0
    fi
    
    log "STEP" "Updating system packages..."
    
    # Update package repositories
    $PKG_UPDATE || error_exit "Failed to update package repositories"
    
    # Upgrade existing packages
    if [ "$PKG_MANAGER" = "apt" ]; then
        DEBIAN_FRONTEND=noninteractive $PKG_UPGRADE || log "WARN" "Some packages failed to upgrade"
    else
        $PKG_UPGRADE || log "WARN" "Some packages failed to upgrade"
    fi
    
    log "SUCCESS" "System packages updated"
}

install_essential_packages() {
    log "STEP" "Installing essential packages..."
    
    local common_packages="curl wget gnupg ca-certificates"
    
    case "$PKG_MANAGER" in
        apt)
            local packages="$common_packages apt-transport-https software-properties-common lsb-release"
            DEBIAN_FRONTEND=noninteractive $PKG_INSTALL $packages || error_exit "Failed to install essential packages"
            ;;
        yum|dnf)
            local packages="$common_packages gnupg2 redhat-lsb-core"
            $PKG_INSTALL $packages || error_exit "Failed to install essential packages"
            ;;
    esac
    
    log "SUCCESS" "Essential packages installed"
}

configure_java() {
    log "STEP" "Configuring Java environment..."
    
    # Check if Java is already installed
    if command -v java >/dev/null 2>&1; then
        local java_version=$(java -version 2>&1 | head -n1 | cut -d'"' -f2)
        log "INFO" "Java already installed: $java_version"
        
        # Check Java version compatibility
        local major_version=$(echo "$java_version" | cut -d'.' -f1)
        if [ "$major_version" -ge 11 ]; then
            log "SUCCESS" "Java version is compatible"
            return 0
        else
            log "WARN" "Java version $java_version may not be compatible. Java 11+ recommended."
        fi
    fi
    
    # Install OpenJDK
    case "$PKG_MANAGER" in
        apt)
            DEBIAN_FRONTEND=noninteractive $PKG_INSTALL openjdk-11-jdk || error_exit "Failed to install Java"
            ;;
        yum|dnf)
            $PKG_INSTALL java-11-openjdk java-11-openjdk-devel || error_exit "Failed to install Java"
            ;;
    esac
    
    # Set JAVA_HOME
    local java_home=""
    if [ -d "/usr/lib/jvm/java-11-openjdk-amd64" ]; then
        java_home="/usr/lib/jvm/java-11-openjdk-amd64"
    elif [ -d "/usr/lib/jvm/java-11-openjdk" ]; then
        java_home="/usr/lib/jvm/java-11-openjdk"
    elif [ -d "/usr/lib/jvm/jre-11-openjdk" ]; then
        java_home="/usr/lib/jvm/jre-11-openjdk"
    fi
    
    if [ -n "$java_home" ]; then
        echo "export JAVA_HOME=$java_home" >> /etc/environment
        export JAVA_HOME="$java_home"
        log "SUCCESS" "JAVA_HOME set to: $java_home"
    fi
    
    log "SUCCESS" "Java environment configured"
}

configure_system_limits() {
    log "STEP" "Configuring system limits..."
    
    # Create limits configuration for Wazuh
    cat > /etc/security/limits.d/99-wazuh.conf << EOF
# Wazuh system limits configuration
# Author: Rodrigo Marins Piaba (Fanaticos4tech)

# Soft limits
wazuh-indexer soft nofile 65536
wazuh-indexer soft nproc 4096
wazuh-indexer soft memlock unlimited

# Hard limits  
wazuh-indexer hard nofile 65536
wazuh-indexer hard nproc 4096
wazuh-indexer hard memlock unlimited

# Root limits
root soft nofile 65536
root hard nofile 65536
EOF
    
    # Configure PAM limits
    if ! grep -q "session required pam_limits.so" /etc/pam.d/common-session 2>/dev/null; then
        echo "session required pam_limits.so" >> /etc/pam.d/common-session
    fi
    
    # Configure systemd limits
    mkdir -p /etc/systemd/system.conf.d
    cat > /etc/systemd/system.conf.d/wazuh.conf << EOF
[Manager]
DefaultLimitNOFILE=65536
DefaultLimitNPROC=4096
DefaultLimitMEMLOCK=infinity
EOF
    
    log "SUCCESS" "System limits configured"
}

configure_sysctl() {
    log "STEP" "Configuring kernel parameters..."
    
    # Create sysctl configuration for Wazuh
    cat > /etc/sysctl.d/99-wazuh.conf << EOF
# Wazuh kernel parameters configuration
# Author: Rodrigo Marins Piaba (Fanaticos4tech)

# Virtual memory settings
vm.max_map_count = 262144
vm.swappiness = 1

# Network settings
net.core.rmem_default = 262144
net.core.rmem_max = 16777216
net.core.wmem_default = 262144
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216

# File system settings
fs.file-max = 1000000

# Security settings
kernel.pid_max = 4194304
EOF
    
    # Apply sysctl settings
    sysctl -p /etc/sysctl.d/99-wazuh.conf || log "WARN" "Some sysctl settings failed to apply"
    
    log "SUCCESS" "Kernel parameters configured"
}

create_wazuh_user() {
    log "STEP" "Creating Wazuh system users..."
    
    # Create wazuh user if it doesn't exist
    if ! id wazuh >/dev/null 2>&1; then
        useradd -r -M -s /bin/false -d /var/ossec wazuh
        log "SUCCESS" "Created wazuh user"
    else
        log "INFO" "Wazuh user already exists"
    fi
    
    # Create wazuh-indexer user if it doesn't exist
    if ! id wazuh-indexer >/dev/null 2>&1; then
        useradd -r -M -s /bin/false -d /var/lib/wazuh-indexer wazuh-indexer
        log "SUCCESS" "Created wazuh-indexer user"
    else
        log "INFO" "Wazuh-indexer user already exists"
    fi
    
    # Create wazuh-dashboard user if it doesn't exist
    if ! id wazuh-dashboard >/dev/null 2>&1; then
        useradd -r -M -s /bin/false -d /var/lib/wazuh-dashboard wazuh-dashboard
        log "SUCCESS" "Created wazuh-dashboard user"
    else
        log "INFO" "Wazuh-dashboard user already exists"
    fi
}

configure_firewall() {
    log "STEP" "Configuring firewall..."
    
    local ports=(443 9200 55000 1514 1515)
    
    # Try UFW first (Ubuntu/Debian)
    if command -v ufw >/dev/null 2>&1; then
        ufw --force enable
        for port in "${ports[@]}"; do
            ufw allow "$port"/tcp
        done
        log "SUCCESS" "UFW firewall configured"
    
    # Try firewalld (RHEL/CentOS)
    elif command -v firewall-cmd >/dev/null 2>&1; then
        systemctl enable --now firewalld
        for port in "${ports[@]}"; do
            firewall-cmd --permanent --add-port="$port"/tcp
        done
        firewall-cmd --reload
        log "SUCCESS" "Firewalld configured"
    
    # Try iptables as fallback
    elif command -v iptables >/dev/null 2>&1; then
        for port in "${ports[@]}"; do
            iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
        done
        
        # Save iptables rules
        if command -v iptables-save >/dev/null 2>&1; then
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        fi
        
        log "SUCCESS" "Iptables configured"
    
    else
        log "WARN" "No supported firewall found. Please configure manually."
    fi
}

disable_conflicting_services() {
    log "STEP" "Disabling conflicting services..."
    
    local services=(
        "elasticsearch"
        "kibana" 
        "logstash"
        "filebeat"
        "opensearch"
        "opensearch-dashboards"
    )
    
    for service in "${services[@]}"; do
        if systemctl is-enabled "$service" >/dev/null 2>&1; then
            systemctl disable "$service"
            systemctl stop "$service"
            log "INFO" "Disabled conflicting service: $service"
        fi
    done
    
    log "SUCCESS" "Conflicting services check completed"
}

# =============================================================================
# COMMAND LINE ARGUMENT PARSING
# =============================================================================

show_help() {
    cat << EOF
Wazuh Server Pre-Installation Script
Author: Rodrigo Marins Piaba (Fanaticos4tech)

Usage: $0 [OPTIONS]

OPTIONS:
    --check-only           Only perform system checks without modifications
    --skip-updates         Skip system package updates
    --force               Force installation even if checks fail
    --help                Show this help message

EXAMPLES:
    $0                     # Full pre-installation preparation
    $0 --check-only        # Only check system requirements
    $0 --skip-updates      # Skip package updates
    $0 --force             # Override requirement checks

For more information, see: ../README.md
EOF
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --check-only)
                CHECK_ONLY=true
                shift
                ;;
            --skip-updates)
                SKIP_UPDATES=true
                shift
                ;;
            --force)
                FORCE=true
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
    
    log "INFO" "Starting Wazuh Server pre-installation..."
    log "INFO" "Script: $0"
    log "INFO" "Arguments: $*"
    log "INFO" "Author: Rodrigo Marins Piaba (Fanaticos4tech)"
    
    # Check if running as root
    check_root
    
    # Detect operating system
    detect_os
    
    # Perform system checks
    check_system_requirements
    check_network_connectivity
    check_required_ports
    
    # If check-only mode, exit here
    if [ "$CHECK_ONLY" = true ]; then
        log "INFO" "Check-only mode completed"
        exit 0
    fi
    
    # System preparation
    update_system_packages
    install_essential_packages
    configure_java
    configure_system_limits
    configure_sysctl
    create_wazuh_user
    configure_firewall
    disable_conflicting_services
    
    log "SUCCESS" "Pre-installation completed successfully!"
    log "INFO" "System is ready for Wazuh installation"
}

# =============================================================================
# SCRIPT ENTRY POINT
# =============================================================================

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
