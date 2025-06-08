#!/bin/bash
# Wazuh Unified Installer - Master Installer Script
# Author: Rodrigo Marins Piaba (Fanaticos4tech)
# E-Mail: rodrigomarinsp@gmail.com / fanaticos4tech@gmail.com
# GitHub: rodrigomarinsp
# Instagram: @fanaticos4tech

# ======== Global Variables ========
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/config.yml"
LOG_FILE="${SCRIPT_DIR}/shared/logs/install_$(date +%Y%m%d-%H%M%S).log"
TEMP_DIR="/tmp/wazuh-install"
VERSION="1.0.0"

# Terminal colors
RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
BLUE="\033[0;34m"
MAGENTA="\033[0;35m"
CYAN="\033[0;36m"
NC="\033[0m" # No Color

# ======== Functions ========
show_banner() {
    echo -e "${BLUE}"
    echo "██╗    ██╗ █████╗ ███████╗██╗   ██╗██╗  ██╗"
    echo "██║    ██║██╔══██╗███╔╝   ██║   ██║██║  ██║"
    echo "██║ █╗ ██║███████║███████╗██║   ██║███████║"
    echo "██║███╗██║██╔══██║╚════██║██║   ██║██╔══██║"
    echo "╚███╔███╔╝██║  ██║███████║╚██████╔╝██║  ██║"
    echo " ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝"
    echo -e "${NC}"
    echo -e "${CYAN}Unified Installer v${VERSION}${NC}"
    echo -e "${CYAN}=====================================${NC}"
    echo -e "${CYAN}Enterprise-grade Automated Deployment${NC}"
    echo -e "${CYAN}=====================================${NC}"
    echo ""
}

log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    
    # Create log directory if it doesn't exist
    mkdir -p "$(dirname "$LOG_FILE")"
    
    # Log to file
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
    
    # Log to console with colors
    case "$level" in
        "INFO")
            echo -e "${GREEN}[INFO]${NC} $message"
            ;;
        "WARNING")
            echo -e "${YELLOW}[WARNING]${NC} $message"
            ;;
        "ERROR")
            echo -e "${RED}[ERROR]${NC} $message"
            ;;
        "DEBUG")
            if [[ "$debug_mode" == "true" ]]; then
                echo -e "${MAGENTA}[DEBUG]${NC} $message"
            fi
            ;;
        *)
            echo -e "$message"
            ;;
    esac
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log "ERROR" "This script must be run as root or with sudo privileges."
        exit 1
    fi
}

check_dependencies() {
    log "INFO" "Checking for required dependencies..."
    local deps=("curl" "wget" "python3" "yq" "jq")
    local missing=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing+=("$dep")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        log "WARNING" "Missing dependencies: ${missing[*]}"
        
        if [[ "$auto_install_dependencies" == "true" ]]; then
            log "INFO" "Installing missing dependencies automatically..."
            
            # Detect package manager
            if command -v apt-get &> /dev/null; then
                apt-get update
                apt-get install -y "${missing[@]}"
            elif command -v yum &> /dev/null; then
                yum install -y "${missing[@]}"
            elif command -v dnf &> /dev/null; then
                dnf install -y "${missing[@]}"
            else
                log "ERROR" "Unsupported package manager. Please install dependencies manually: ${missing[*]}"
                exit 1
            fi
        else
            log "ERROR" "Please install the required dependencies: ${missing[*]}"
            exit 1
        fi
    fi
    
    # Check for Python dependencies
    if [[ -f "${SCRIPT_DIR}/requirements.txt" ]]; then
        log "INFO" "Checking Python dependencies..."
        if command -v pip3 &> /dev/null; then
            if [[ "$auto_install_dependencies" == "true" ]]; then
                pip3 install -r "${SCRIPT_DIR}/requirements.txt"
            else
                log "INFO" "To install Python dependencies: pip3 install -r ${SCRIPT_DIR}/requirements.txt"
            fi
        else
            log "WARNING" "pip3 not found. Cannot check Python dependencies."
        fi
    fi
}

parse_yaml() {
    local yaml_file="$1"
    local prefix="$2"
    local s='[[:space:]]*'
    local w='[a-zA-Z0-9_]*'
    local fs
    
    fs="$(echo @|tr @ '\034')"
    
    if command -v yq &> /dev/null; then
        # If yq is available, use it to parse YAML
        yq eval -o json "$yaml_file" > "${TEMP_DIR}/config.json"
        if [[ $? -ne 0 ]]; then
            log "ERROR" "Failed to parse YAML config using yq."
            return 1
        fi
    else
        # Fallback to our simplified YAML parser
        sed -ne '/^#/d;/^[[:space:]]*$/d;/^[[:space:]]*[a-zA-Z0-9_][^:]*:([^"\'''{][^}]*)?[[:space:]]*$/b p;b' "$yaml_file" |
        sed -e "s|^\([[:space:]]*\)\(.*\): \(.*\)$|\1\2=\3|" |
        sed -e 's|[[:space:]]*$||g' > "${TEMP_DIR}/config.env"
        
        if [[ $? -ne 0 ]]; then
            log "ERROR" "Failed to parse YAML config."
            return 1
        fi
        
        source "${TEMP_DIR}/config.env"
    fi
}

load_config() {
    log "INFO" "Loading configuration from: $CONFIG_FILE"
    
    # Create temp directory
    mkdir -p "$TEMP_DIR"
    
    # Check if config file exists
    if [[ ! -f "$CONFIG_FILE" ]]; then
        log "ERROR" "Configuration file not found: $CONFIG_FILE"
        exit 1
    fi
    
    # Parse YAML config
    parse_yaml "$CONFIG_FILE" "config_"
    
    # Set configuration variables
    if command -v jq &> /dev/null && [[ -f "${TEMP_DIR}/config.json" ]]; then
        # Parse with jq if available
        installation_mode=$(jq -r '.installation_mode // {}' "${TEMP_DIR}/config.json")
        server_automated=$(jq -r '.installation_mode.server_automated // false' "${TEMP_DIR}/config.json")
        ansible_deployment=$(jq -r '.installation_mode.ansible_deployment // false' "${TEMP_DIR}/config.json")
        agent_only=$(jq -r '.installation_mode.agent_only // false' "${TEMP_DIR}/config.json")
        manual_guide=$(jq -r '.installation_mode.manual_guide // false' "${TEMP_DIR}/config.json")
        
        # Get automation settings
        auto_install_dependencies=$(jq -r '.automation.auto_install_dependencies // true' "${TEMP_DIR}/config.json")
        auto_correct_errors=$(jq -r '.automation.auto_correct_errors // true' "${TEMP_DIR}/config.json")
        full_unattended=$(jq -r '.automation.full_unattended // false' "${TEMP_DIR}/config.json")
        
        # Get debug mode
        debug_mode=$(jq -r '.advanced.debug_mode // false' "${TEMP_DIR}/config.json")
    else
        # Fallback to env vars from parse_yaml
        server_automated=${config_installation_mode_server_automated:-true}
        ansible_deployment=${config_installation_mode_ansible_deployment:-false}
        agent_only=${config_installation_mode_agent_only:-false}
        manual_guide=${config_installation_mode_manual_guide:-false}
        
        # Get automation settings
        auto_install_dependencies=${config_automation_auto_install_dependencies:-true}
        auto_correct_errors=${config_automation_auto_correct_errors:-true}
        full_unattended=${config_automation_full_unattended:-false}
        
        # Get debug mode
        debug_mode=${config_advanced_debug_mode:-false}
    fi
    
    log "DEBUG" "Configuration loaded successfully."
}

detect_os() {
    log "INFO" "Detecting operating system..."
    
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS_NAME=$ID
        OS_VERSION_ID=$VERSION_ID
        OS_VERSION=$VERSION
    elif command -v lsb_release &> /dev/null; then
        OS_NAME=$(lsb_release -si | tr '[:upper:]' '[:lower:]')
        OS_VERSION_ID=$(lsb_release -sr)
        OS_VERSION=$(lsb_release -sd)
    elif [[ -f /etc/lsb-release ]]; then
        . /etc/lsb-release
        OS_NAME=$DISTRIB_ID
        OS_VERSION_ID=$DISTRIB_RELEASE
        OS_VERSION=$DISTRIB_DESCRIPTION
    elif [[ -f /etc/debian_version ]]; then
        OS_NAME="debian"
        OS_VERSION_ID=$(cat /etc/debian_version)
        OS_VERSION="Debian $OS_VERSION_ID"
    elif [[ -f /etc/redhat-release ]]; then
        OS_NAME=$(cat /etc/redhat-release | cut -d ' ' -f 1 | tr '[:upper:]' '[:lower:]')
        OS_VERSION_ID=$(cat /etc/redhat-release | grep -oP '\d+(\.\d+)+')
        OS_VERSION=$(cat /etc/redhat-release)
    else
        OS_NAME="unknown"
        OS_VERSION_ID="unknown"
        OS_VERSION="Unknown"
    fi
    
    # Detect system architecture
    ARCH=$(uname -m)
    
    log "INFO" "Detected OS: $OS_NAME $OS_VERSION_ID ($ARCH)"
    log "DEBUG" "Full OS version: $OS_VERSION"
    
    # Check for supported OS
    case "$OS_NAME" in
        ubuntu|debian|centos|rhel|fedora|rocky|almalinux|ol|amazon)
            log "INFO" "Operating system supported: $OS_NAME"
            ;;
        *)
            log "WARNING" "Unsupported operating system: $OS_NAME. Installation may not work correctly."
            ;;
    esac
}

check_system_resources() {
    log "INFO" "Checking system resources..."
    
    # Check CPU
    CPU_CORES=$(nproc --all)
    log "INFO" "CPU cores: $CPU_CORES"
    
    if [[ $CPU_CORES -lt 2 ]]; then
        log "WARNING" "Low CPU resources detected (< 2 cores). Performance may be affected."
    fi
    
    # Check RAM
    MEM_TOTAL=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    MEM_TOTAL_GB=$(awk "BEGIN {printf "%.1f", ${MEM_TOTAL}/1024/1024}")
    log "INFO" "Memory: ${MEM_TOTAL_GB}GB"
    
    if (( $(echo "$MEM_TOTAL_GB < 4" | bc -l) )); then
        log "WARNING" "Low memory detected (< 4GB). Performance may be affected."
    fi
    
    # Check disk space
    DISK_FREE=$(df -h / | awk 'NR==2 {print $4}')
    DISK_FREE_NUM=$(df / | awk 'NR==2 {print $4}')
    log "INFO" "Free disk space: $DISK_FREE"
    
    # Convert to KB for comparison
    if [[ $DISK_FREE_NUM -lt 10485760 ]]; then  # 10GB in KB
        log "WARNING" "Low disk space detected (< 10GB). Installation may fail."
    fi
}

select_installation_method() {
    log "INFO" "Selecting installation method..."
    
    # Check if any method is explicitly enabled in config
    if [[ "$server_automated" == "true" ]]; then
        INSTALL_METHOD="server"
        log "INFO" "Selected method: Server Installation"
    elif [[ "$ansible_deployment" == "true" ]]; then
        INSTALL_METHOD="ansible"
        log "INFO" "Selected method: Ansible Deployment"
    elif [[ "$agent_only" == "true" ]]; then
        INSTALL_METHOD="agent"
        log "INFO" "Selected method: Agent Installation"
    elif [[ "$manual_guide" == "true" ]]; then
        INSTALL_METHOD="manual"
        log "INFO" "Selected method: Manual Installation Guide"
    else
        # Interactive selection if not in unattended mode
        if [[ "$full_unattended" != "true" ]]; then
            echo -e "${CYAN}Please select installation method:${NC}"
            echo "1) Server Installation (Single Node)"
            echo "2) Ansible Deployment (Multi-Node)"
            echo "3) Agent Installation"
            echo "4) Manual Installation Guide"
            echo -n "Selection [1-4]: "
            read -r selection
            
            case $selection in
                1) INSTALL_METHOD="server" ;;
                2) INSTALL_METHOD="ansible" ;;
                3) INSTALL_METHOD="agent" ;;
                4) INSTALL_METHOD="manual" ;;
                *) log "ERROR" "Invalid selection. Defaulting to Server Installation."; INSTALL_METHOD="server" ;;
            esac
        else
            # Default to server installation in unattended mode
            INSTALL_METHOD="server"
            log "INFO" "No installation method selected. Defaulting to Server Installation."
        fi
    fi
}

run_server_installation() {
    log "INFO" "Starting server installation process..."
    
    if [[ -f "${SCRIPT_DIR}/server_installation/server_install.sh" ]]; then
        log "INFO" "Executing server installation script..."
        bash "${SCRIPT_DIR}/server_installation/server_install.sh" --config "$CONFIG_FILE"
        
        if [[ $? -ne 0 ]]; then
            log "ERROR" "Server installation failed. Check logs for details."
            return 1
        else
            log "INFO" "Server installation completed successfully."
            return 0
        fi
    else
        log "ERROR" "Server installation script not found: ${SCRIPT_DIR}/server_installation/server_install.sh"
        return 1
    fi
}

run_ansible_deployment() {
    log "INFO" "Starting Ansible deployment process..."
    
    if [[ -f "${SCRIPT_DIR}/ansible_installation/deploy.sh" ]]; then
        log "INFO" "Executing Ansible deployment script..."
        bash "${SCRIPT_DIR}/ansible_installation/deploy.sh" --config "$CONFIG_FILE"
        
        if [[ $? -ne 0 ]]; then
            log "ERROR" "Ansible deployment failed. Check logs for details."
            return 1
        else
            log "INFO" "Ansible deployment completed successfully."
            return 0
        fi
    else
        log "ERROR" "Ansible deployment script not found: ${SCRIPT_DIR}/ansible_installation/deploy.sh"
        return 1
    fi
}

run_agent_installation() {
    log "INFO" "Starting agent installation process..."
    
    if [[ -f "${SCRIPT_DIR}/agent_installation/agent_deploy.sh" ]]; then
        log "INFO" "Executing agent installation script..."
        bash "${SCRIPT_DIR}/agent_installation/agent_deploy.sh" --config "$CONFIG_FILE"
        
        if [[ $? -ne 0 ]]; then
            log "ERROR" "Agent installation failed. Check logs for details."
            return 1
        else
            log "INFO" "Agent installation completed successfully."
            return 0
        fi
    else
        log "ERROR" "Agent installation script not found: ${SCRIPT_DIR}/agent_installation/agent_deploy.sh"
        return 1
    fi
}

show_manual_guide() {
    log "INFO" "Displaying manual installation guide..."
    
    if [[ -f "${SCRIPT_DIR}/manual_installation/README.md" ]]; then
        if command -v less &> /dev/null; then
            less "${SCRIPT_DIR}/manual_installation/README.md"
        else
            cat "${SCRIPT_DIR}/manual_installation/README.md"
        fi
    else
        log "ERROR" "Manual installation guide not found: ${SCRIPT_DIR}/manual_installation/README.md"
        return 1
    fi
}

validate_installation() {
    log "INFO" "Validating installation..."
    
    case $INSTALL_METHOD in
        "server")
            if [[ -f "${SCRIPT_DIR}/server_installation/validate_install.sh" ]]; then
                bash "${SCRIPT_DIR}/server_installation/validate_install.sh"
            else
                log "WARNING" "Validation script not found: ${SCRIPT_DIR}/server_installation/validate_install.sh"
            fi
            ;;
        "ansible")
            if [[ -f "${SCRIPT_DIR}/ansible_installation/playbooks/validate.yml" ]]; then
                log "INFO" "Running Ansible validation playbook..."
                cd "${SCRIPT_DIR}/ansible_installation" && ansible-playbook playbooks/validate.yml
            else
                log "WARNING" "Ansible validation playbook not found."
            fi
            ;;
        "agent")
            if [[ -f "${SCRIPT_DIR}/agent_installation/scripts/verify_agents.sh" ]]; then
                bash "${SCRIPT_DIR}/agent_installation/scripts/verify_agents.sh"
            else
                log "WARNING" "Agent verification script not found: ${SCRIPT_DIR}/agent_installation/scripts/verify_agents.sh"
            fi
            ;;
        *)
            log "INFO" "No validation required for manual guide."
            ;;
    esac
}

cleanup() {
    log "INFO" "Cleaning up temporary files..."
    rm -rf "$TEMP_DIR"
}

show_completion() {
    local success=$1
    
    if [[ $success -eq 0 ]]; then
        echo -e "${GREEN}=======================================${NC}"
        echo -e "${GREEN}✅ Installation completed successfully!${NC}"
        echo -e "${GREEN}=======================================${NC}"
        
        case $INSTALL_METHOD in
            "server")
                echo -e "${CYAN}Access Wazuh dashboard at: https://localhost${NC}"
                echo -e "${CYAN}Default username: wazuh-admin${NC}"
                echo -e "${CYAN}Check logs for generated password${NC}"
                ;;
            "ansible")
                echo -e "${CYAN}Multi-node deployment completed.${NC}"
                echo -e "${CYAN}Please check individual hosts for status.${NC}"
                ;;
            "agent")
                echo -e "${CYAN}Agent installation completed.${NC}"
                echo -e "${CYAN}Verify agent status with: sudo systemctl status wazuh-agent${NC}"
                ;;
        esac
        
        echo -e "${CYAN}Installation logs: ${LOG_FILE}${NC}"
    else
        echo -e "${RED}========================================${NC}"
        echo -e "${RED}❌ Installation completed with errors!${NC}"
        echo -e "${RED}========================================${NC}"
        echo -e "${CYAN}Please check logs for details: ${LOG_FILE}${NC}"
        echo -e "${CYAN}For troubleshooting assistance, see: ${SCRIPT_DIR}/docs/troubleshooting.md${NC}"
    fi
}

print_help() {
    echo "Wazuh Unified Installer v${VERSION}"
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --config <file>       Use specified configuration file"
    echo "  --method <method>     Select installation method: server|ansible|agent|manual"
    echo "  --unattended          Run in unattended mode (no user prompts)"
    echo "  --validate            Run validation without installing"
    echo "  --check-system        Only check system compatibility"
    echo "  --check-firewall      Check firewall configuration"
    echo "  --fix-certificates    Regenerate certificates"
    echo "  --version             Show version information"
    echo "  --help                Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 --config custom_config.yml"
    echo "  $0 --method server --unattended"
    echo "  $0 --validate"
    echo ""
}

# ======== Main Script ========

# Parse command-line arguments
while [[ $# -gt 0 ]]; do
    key="$1"
    
    case $key in
        --config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        --method)
            case "$2" in
                server|ansible|agent|manual)
                    CLI_INSTALL_METHOD="$2"
                    shift 2
                    ;;
                *)
                    log "ERROR" "Invalid installation method: $2"
                    print_help
                    exit 1
                    ;;
            esac
            ;;
        --unattended)
            CLI_UNATTENDED=true
            shift
            ;;
        --validate)
            VALIDATE_ONLY=true
            shift
            ;;
        --check-system)
            CHECK_SYSTEM_ONLY=true
            shift
            ;;
        --check-firewall)
            CHECK_FIREWALL=true
            shift
            ;;
        --fix-certificates)
            FIX_CERTIFICATES=true
            shift
            ;;
        --version)
            echo "Wazuh Unified Installer version ${VERSION}"
            exit 0
            ;;
        --help)
            print_help
            exit 0
            ;;
        *)
            log "ERROR" "Unknown option: $1"
            print_help
            exit 1
            ;;
    esac
done

# Main execution flow
show_banner
check_root
mkdir -p "$(dirname "$LOG_FILE")"
load_config

# Apply CLI overrides
if [[ -n "$CLI_INSTALL_METHOD" ]]; then
    INSTALL_METHOD="$CLI_INSTALL_METHOD"
fi

if [[ "$CLI_UNATTENDED" == "true" ]]; then
    full_unattended=true
fi

check_dependencies
detect_os
check_system_resources

# Handle special execution modes
if [[ "$CHECK_SYSTEM_ONLY" == "true" ]]; then
    log "INFO" "System check completed. Exiting."
    exit 0
fi

if [[ "$CHECK_FIREWALL" == "true" ]]; then
    log "INFO" "Checking firewall configuration..."
    # TODO: Implement firewall check
    exit 0
fi

if [[ "$FIX_CERTIFICATES" == "true" ]]; then
    log "INFO" "Regenerating certificates..."
    # TODO: Implement certificate regeneration
    exit 0
fi

# Main installation flow
if [[ "$VALIDATE_ONLY" != "true" ]]; then
    select_installation_method
    
    # Execute selected installation method
    case $INSTALL_METHOD in
        "server")
            run_server_installation
            installation_result=$?
            ;;
        "ansible")
            run_ansible_deployment
            installation_result=$?
            ;;
        "agent")
            run_agent_installation
            installation_result=$?
            ;;
        "manual")
            show_manual_guide
            installation_result=$?
            ;;
        *)
            log "ERROR" "Invalid installation method: $INSTALL_METHOD"
            exit 1
            ;;
    esac
    
    # Validate installation
    if [[ $installation_result -eq 0 ]]; then
        validate_installation
    fi
else
    log "INFO" "Running validation only..."
    validate_installation
    installation_result=$?
fi

# Cleanup and finish
cleanup
show_completion $installation_result

exit $installation_result
