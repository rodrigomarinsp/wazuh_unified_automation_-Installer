#!/bin/bash
# Wazuh Server Installation Script - Production Ready
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
LOG_FILE="/var/log/wazuh-server-install.log"
CONFIG_FILE="${SCRIPT_DIR}/../config.yml"
WAZUH_VERSION="4.7.0"
PASSWORDS_FILE="/var/log/wazuh-passwords.txt"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Installation flags
AUTO_MODE=false
SILENT_MODE=false
SKIP_VALIDATION=false
FORCE_INSTALL=false
CUSTOM_CONFIG=""

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

check_and_install_java() {
    log "STEP" "Verificando o Java..."

    if command -v java >/dev/null 2>&1; then
        java_version=$(java -version 2>&1 | awk -F[\"_] '/version/ {print $2}')
        major_version=$(echo "$java_version" | cut -d. -f1)

        if [[ "$major_version" -eq 11 ]]; then
            log "SUCCESS" "Java 11 já está instalado"
            return
        else
            log "WARN" "Java instalado é versão $java_version (esperado: 11)"
        fi
    else
        log "WARN" "Java não está instalado"
    fi

    log "INFO" "Instalando Java 11..."

    case "$PKG_MANAGER" in
        apt)
            $PKG_UPDATE
            $PKG_INSTALL openjdk-11-jdk || error_exit "Falha ao instalar Java 11 (apt)"
            ;;
        yum|dnf)
            $PKG_UPDATE
            $PKG_INSTALL java-11-openjdk-devel || error_exit "Falha ao instalar Java 11 (yum/dnf)"
            ;;
        *)
            error_exit "Gerenciador de pacotes não suportado para instalação do Java"
            ;;
    esac

    log "SUCCESS" "Java 11 instalado com sucesso"
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
            ;;
        centos|rhel|rocky|almalinux)
            export PKG_MANAGER="yum"
            export PKG_UPDATE="yum update -y"
            export PKG_INSTALL="yum install -y"
            if command -v dnf >/dev/null 2>&1; then
                export PKG_MANAGER="dnf"
                export PKG_UPDATE="dnf update -y"
                export PKG_INSTALL="dnf install -y"
            fi
            ;;
        *)
            error_exit "Unsupported operating system: $OS_NAME"
            ;;
    esac
}

check_system_resources() {
    log "STEP" "Checking system resources..."
    
    # Check RAM
    local ram_gb=$(free -g | awk '/^Mem:/{print $2}')
    if [ "$ram_gb" -lt 4 ]; then
        log "WARN" "RAM: ${ram_gb}GB detected. Minimum 4GB recommended."
        if [ "$FORCE_INSTALL" = false ]; then
            read -p "Continue anyway? (y/N): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                error_exit "Installation cancelled by user."
            fi
        fi
    else
        log "SUCCESS" "RAM: ${ram_gb}GB - Adequate"
    fi
    
    # Check CPU cores
    local cpu_cores=$(nproc)
    if [ "$cpu_cores" -lt 2 ]; then
        log "WARN" "CPU cores: $cpu_cores detected. Minimum 2 cores recommended."
    else
        log "SUCCESS" "CPU cores: $cpu_cores - Adequate"
    fi
    
    # Check disk space
    local disk_space_gb=$(df / | awk 'NR==2 {print int($4/1024/1024)}')
    if [ "$disk_space_gb" -lt 50 ]; then
        log "WARN" "Free disk space: ${disk_space_gb}GB. Minimum 50GB recommended."
        if [ "$FORCE_INSTALL" = false ]; then
            read -p "Continue anyway? (y/N): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                error_exit "Installation cancelled by user."
            fi
        fi
    else
        log "SUCCESS" "Free disk space: ${disk_space_gb}GB - Adequate"
    fi
}

install_dependencies() {
    log "STEP" "Installing system dependencies..."
    
    $PKG_UPDATE || error_exit "Failed to update package repositories"
    
    local common_packages="curl wget gnupg lsb-release ca-certificates apt-transport-https software-properties-common"
    
    case "$PKG_MANAGER" in
        apt)
            $PKG_INSTALL $common_packages || error_exit "Failed to install dependencies"
            ;;
        yum|dnf)
            $PKG_INSTALL curl wget gnupg2 redhat-lsb-core ca-certificates || error_exit "Failed to install dependencies"
            ;;
    esac
    
    log "SUCCESS" "Dependencies installed successfully"
}

add_wazuh_repository() {
    log "STEP" "Adding Wazuh repository..."
    
    # Add GPG key
    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor | tee /usr/share/keyrings/wazuh.gpg > /dev/null
    
    case "$PKG_MANAGER" in
        apt)
            echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list
            apt update || error_exit "Failed to update Wazuh repository"
            ;;
        yum|dnf)
            cat > /etc/yum.repos.d/wazuh.repo << EOF
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-\$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
EOF
            ;;
    esac
    
    log "SUCCESS" "Wazuh repository added successfully"
}

configure_firewall() {
    log "STEP" "Configuring firewall..."
    
    local ports=(443 9200 55000 1514 1515)
    
    if command -v ufw >/dev/null 2>&1; then
        ufw --force enable
        for port in "${ports[@]}"; do
            ufw allow "$port"/tcp
        done
        log "SUCCESS" "UFW firewall configured"
    elif command -v firewall-cmd >/dev/null 2>&1; then
        systemctl enable --now firewalld
        for port in "${ports[@]}"; do
            firewall-cmd --permanent --add-port="$port"/tcp
        done
        firewall-cmd --reload
        log "SUCCESS" "FirewallD configured"
    else
        log "WARN" "No supported firewall found. Please configure manually."
    fi
}

generate_passwords() {
    log "STEP" "Generating secure passwords..."
    
    local admin_password=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
    local wazuh_password=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
    local kibanaserver_password=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
    
    cat > "$PASSWORDS_FILE" << EOF
# Wazuh Installation Passwords
# Generated: $(date)
# Author: Rodrigo Marins Piaba (Fanaticos4tech)

ADMIN_PASSWORD="$admin_password"
WAZUH_PASSWORD="$wazuh_password"
KIBANASERVER_PASSWORD="$kibanaserver_password"

# Service URLs:
# Dashboard: https://$(hostname -I | awk '{print $1}')
# API: https://$(hostname -I | awk '{print $1}'):55000
# Indexer: https://$(hostname -I | awk '{print $1}'):9200
EOF
    
    chmod 600 "$PASSWORDS_FILE"
    log "SUCCESS" "Passwords generated and saved to $PASSWORDS_FILE"
}

install_indexer() {
    log "STEP" "Installing Wazuh Indexer..."
    
    # Run dedicated indexer installation script
    if [ -f "${SCRIPT_DIR}/scripts/install_indexer.sh" ]; then
        bash "${SCRIPT_DIR}/scripts/install_indexer.sh" || error_exit "Indexer installation failed"
    else
        # Fallback inline installation
        $PKG_INSTALL wazuh-indexer || error_exit "Failed to install Wazuh Indexer"
        
        systemctl daemon-reload
        systemctl enable wazuh-indexer
        systemctl start wazuh-indexer
        
        # Wait for service to be ready
        local timeout=60
        local count=0
        while ! curl -s -k https://localhost:9200 >/dev/null 2>&1; do
            if [ $count -ge $timeout ]; then
                error_exit "Wazuh Indexer failed to start within $timeout seconds"
            fi
            sleep 1
            ((count++))
        done
    fi
    
    log "SUCCESS" "Wazuh Indexer installed and started"
}

install_manager() {
    log "STEP" "Installing Wazuh Manager..."
    
    # Run dedicated manager installation script
    if [ -f "${SCRIPT_DIR}/scripts/install_manager.sh" ]; then
        bash "${SCRIPT_DIR}/scripts/install_manager.sh" || error_exit "Manager installation failed"
    else
        # Fallback inline installation
        $PKG_INSTALL wazuh-manager || error_exit "Failed to install Wazuh Manager"
        
        systemctl daemon-reload
        systemctl enable wazuh-manager
        systemctl start wazuh-manager
        
        # Configure API
        if [ -f /var/ossec/api/configuration/api.yaml ]; then
            sed -i "s/password: wazuh/password: $(grep WAZUH_PASSWORD $PASSWORDS_FILE | cut -d'=' -f2 | tr -d '"')/" /var/ossec/api/configuration/api.yaml
        fi
    fi
    
    log "SUCCESS" "Wazuh Manager installed and started"
}

install_dashboard() {
    log "STEP" "Installing Wazuh Dashboard..."
    
    # Run dedicated dashboard installation script
    if [ -f "${SCRIPT_DIR}/scripts/install_dashboard.sh" ]; then
        bash "${SCRIPT_DIR}/scripts/install_dashboard.sh" || error_exit "Dashboard installation failed"
    else
        # Fallback inline installation
        $PKG_INSTALL wazuh-dashboard || error_exit "Failed to install Wazuh Dashboard"
        
        systemctl daemon-reload
        systemctl enable wazuh-dashboard
        systemctl start wazuh-dashboard
        
        # Wait for service to be ready
        local timeout=120
        local count=0
        while ! curl -s -k https://localhost:443 >/dev/null 2>&1; do
            if [ $count -ge $timeout ]; then
                error_exit "Wazuh Dashboard failed to start within $timeout seconds"
            fi
            sleep 1
            ((count++))
        done
    fi
    
    log "SUCCESS" "Wazuh Dashboard installed and started"
}

run_post_install() {
    log "STEP" "Running post-installation configuration..."
    
    if [ -f "${SCRIPT_DIR}/scripts/post_install.sh" ]; then
        bash "${SCRIPT_DIR}/scripts/post_install.sh" || error_exit "Post-installation failed"
    else
        log "WARN" "Post-installation script not found. Skipping..."
    fi
    
    log "SUCCESS" "Post-installation completed"
}

validate_installation() {
    if [ "$SKIP_VALIDATION" = true ]; then
        log "INFO" "Skipping validation as requested"
        return 0
    fi
    
    log "STEP" "Validating installation..."
    
    if [ -f "${SCRIPT_DIR}/validate_install.sh" ]; then
        bash "${SCRIPT_DIR}/validate_install.sh" || log "WARN" "Validation completed with warnings"
    else
        # Basic validation
        local services=("wazuh-indexer" "wazuh-manager" "wazuh-dashboard")
        for service in "${services[@]}"; do
            if systemctl is-active --quiet "$service"; then
                log "SUCCESS" "$service is running"
            else
                log "ERROR" "$service is not running"
            fi
        done
    fi
}

show_installation_summary() {
    log "SUCCESS" "Wazuh Server installation completed!"
    
    local server_ip=$(hostname -I | awk '{print $1}')
    
    echo
    echo "======================================================================"
    echo "🛡️  WAZUH SERVER INSTALLATION SUMMARY"
    echo "======================================================================"
    echo "Author: Rodrigo Marins Piaba (Fanaticos4tech)"
    echo "Installation completed: $(date)"
    echo
    echo "🌐 Access Information:"
    echo "   Dashboard:  https://$server_ip"
    echo "   API:        https://$server_ip:55000"
    echo "   Indexer:    https://$server_ip:9200"
    echo
    echo "🔐 Credentials:"
    echo "   Check file: $PASSWORDS_FILE"
    echo "   Dashboard username: admin"
    echo
    echo "📋 Next Steps:"
    echo "   1. Access the dashboard using the URL above"
    echo "   2. Install agents on your endpoints"
    echo "   3. Configure rules and compliance policies"
    echo "   4. Review security hardening guide"
    echo
    echo "📚 Documentation:"
    echo "   Local:  $SCRIPT_DIR/README.md"
    echo "   Online: https://documentation.wazuh.com/"
    echo
    echo "🆘 Support: fanaticos4tech@gmail.com"
    echo "======================================================================"
}

# =============================================================================
# COMMAND LINE ARGUMENT PARSING
# =============================================================================

show_help() {
    cat << EOF
Wazuh Server Installation Script
Author: Rodrigo Marins Piaba (Fanaticos4tech)

Usage: $0 [OPTIONS]

OPTIONS:
    --auto                  Automated installation with defaults
    --silent               Silent mode (no interactive prompts)
    --force                Force installation (skip resource checks)
    --skip-validation      Skip post-installation validation
    --config FILE          Use custom configuration file
    --log-file FILE        Custom log file location
    --help                 Show this help message

EXAMPLES:
    $0 --auto                          # Automated installation
    $0 --config custom.yml             # Custom configuration
    $0 --silent --log-file install.log # Silent with custom log

For more information, see: $SCRIPT_DIR/README.md
EOF
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --auto)
                AUTO_MODE=true
                FORCE_INSTALL=true
                shift
                ;;
            --silent)
                SILENT_MODE=true
                shift
                ;;
            --force)
                FORCE_INSTALL=true
                shift
                ;;
            --skip-validation)
                SKIP_VALIDATION=true
                shift
                ;;
            --config)
                CUSTOM_CONFIG="$2"
                shift 2
                ;;
            --log-file)
                LOG_FILE="$2"
                shift 2
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
    
    log "INFO" "Starting Wazuh Server installation..."
    log "INFO" "Script: $0"
    log "INFO" "Arguments: $*"
    log "INFO" "Author: Rodrigo Marins Piaba (Fanaticos4tech)"
    
    # Pre-installation checks
    check_and_install_java
    check_root
    detect_os
    check_system_resources
    
    # Pre-installation preparation
    bash "${SCRIPT_DIR}/scripts/pre_install.sh" 2>/dev/null || {
        log "WARN" "Pre-installation script not found, running inline preparation"
        install_dependencies
        add_wazuh_repository
        configure_firewall
    }
    
    # Generate passwords
    generate_passwords
    
    # Install components in order
    install_indexer
    install_manager
    install_dashboard
    
    # Post-installation configuration
    run_post_install
    
    # Validation
    validate_installation
    
    # Show summary
    show_installation_summary
    
    log "SUCCESS" "Installation completed successfully!"
}

# =============================================================================
# SCRIPT ENTRY POINT
# =============================================================================

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
