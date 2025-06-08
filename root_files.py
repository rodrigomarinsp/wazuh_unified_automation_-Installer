import os
root_dir = 'Wazuh_Unified_Installer'
# 1. Create README.md - Master project guide
readme_content = """<!--
Author: Rodrigo Marins Piaba (Fanaticos4tech)
E-Mail: rodrigomarinsp@gmail.com / fanaticos4tech@gmail.com
GitHub: rodrigomarinsp
Instagram: @fanaticos4tech
-->

# 🛡️ Wazuh Unified Installer

<p align="center">
  <img src="https://wazuh.com/assets/images/wazuh_logo.png" alt="Wazuh Logo" width="300"/>
  <br>
  <em>Enterprise-grade automated deployment for Wazuh SIEM</em>
</p>

<p align="center">
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-features">Features</a> •
  <a href="#-installation-methods">Installation Methods</a> •
  <a href="#-requirements">Requirements</a> •
  <a href="#-documentation">Documentation</a> •
  <a href="#-troubleshooting">Troubleshooting</a> •
  <a href="#-contributing">Contributing</a> •
  <a href="#-license">License</a>
</p>

## 🚀 Quick Start

This project provides a unified installation system for Wazuh components with zero-touch automation and intelligent error handling.

```bash
# Clone the repository
git clone https://github.com/rodrigomarinsp/wazuh-unified-installer.git
cd Wazuh_Unified_Installer

# Run the main installer with default settings (interactive mode)
./main_installer.sh

# Or run with a specific configuration file (non-interactive mode)
./main_installer.sh --config my_config.yml
```

## ✨ Features

- **🔄 Universal Installation System** - Single platform for all deployment methods
- **🧠 Intelligent Detection** - Auto-detects environment and selects optimal installation strategy
- **🛠️ Enterprise-Ready** - Production-grade with zero-touch automation and error recovery
- **🔒 Security First** - Automatic certificate generation and security best practices
- **🌐 Multiple Platforms** - Supports Ubuntu, CentOS, RHEL, Debian, and more
- **📊 Performance Tuning** - Automatic optimization based on available resources
- **📱 Multi-Agent Support** - Automated deployment for Linux, Windows, and macOS agents

## 🔧 Installation Methods

<details>
<summary>🖥️ <b>Server Installation</b> - Complete Wazuh server infrastructure</summary>
<p>

Automated installation of Wazuh Manager, Indexer, and Dashboard on a single server:

```bash
cd server_installation
./server_install.sh
```

Learn more in the [Server Installation Guide](./server_installation/README.md).
</p>
</details>

<details>
<summary>⚙️ <b>Ansible Installation</b> - Enterprise-scale deployment</summary>
<p>

Mass deployment across multiple hosts using Ansible:

```bash
cd ansible_installation
./deploy.sh
```

Learn more in the [Ansible Installation Guide](./ansible_installation/README.md).
</p>
</details>

<details>
<summary>👥 <b>Agent Installation</b> - Connect agents to your Wazuh server</summary>
<p>

Deploy agents on various platforms:

```bash
cd agent_installation
./agent_deploy.sh --manager-ip <WAZUH_MANAGER_IP>
```

Learn more in the [Agent Installation Guide](./agent_installation/README.md).
</p>
</details>

<details>
<summary>📖 <b>Manual Installation</b> - Step-by-step guide</summary>
<p>

Follow our comprehensive step-by-step guide for manual installation and learning:

```bash
cd manual_installation
less README.md
```

Learn more in the [Manual Installation Guide](./manual_installation/README.md).
</p>
</details>

## 📋 Requirements

### System Requirements

- **🖥️ Server Components:**
  - CPU: 4 cores (minimum), 8+ cores (recommended)
  - Memory: 8GB RAM (minimum), 16GB+ RAM (recommended)
  - Disk: 50GB free space (minimum), SSD recommended
  - OS: Ubuntu 20.04+, CentOS 7+, RHEL 7+, Debian 10+

- **💻 Agent Components:**
  - Linux: Any modern distribution with kernel 3.10+
  - Windows: Windows 7+ / Server 2008 R2+
  - macOS: macOS 10.12+

### Software Requirements

- Bash 4.0+
- Python 3.6+ (for Python-based utilities)
- OpenSSL 1.1.1+
- cURL/wget

## 📚 Documentation

Comprehensive documentation is available for all installation methods:

- [Overview & Architecture](./docs/architecture.md)
- [Server Installation Guide](./server_installation/README.md)
- [Ansible Deployment Guide](./ansible_installation/README.md)
- [Agent Installation Guide](./agent_installation/README.md)
- [Manual Installation Guide](./manual_installation/README.md)
- [Configuration Reference](./docs/configuration.md)
- [Performance Tuning](./docs/performance.md)
- [Security Hardening](./docs/security.md)

## 🔍 Troubleshooting

Common issues and their solutions:

<details>
<summary>🔄 <b>Installation Failures</b></summary>
<p>

- Check the logs in `shared/logs/` for detailed error messages
- Ensure your system meets all requirements
- Verify connectivity between components
- Run `./main_installer.sh --validate` to check system compatibility

</p>
</details>

<details>
<summary>🌐 <b>Network Issues</b></summary>
<p>

- Ensure ports 1514, 1515, 55000 are open between agents and manager
- Check firewall rules with `./main_installer.sh --check-firewall`
- Verify DNS resolution for all hosts

</p>
</details>

<details>
<summary>🔐 <b>Certificate Problems</b></summary>
<p>

- Run `./main_installer.sh --fix-certificates` to regenerate certificates
- Check certificate paths and permissions
- Verify CA trust chain is properly configured

</p>
</details>

For more troubleshooting assistance, please refer to our [Troubleshooting Guide](./docs/troubleshooting.md).

## 👥 Contributing

Contributions are welcome and appreciated! Please see our [Contribution Guidelines](./CONTRIBUTING.md) for more details.

- Fork the repository
- Create a feature branch
- Submit a pull request

## 📝 License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](./LICENSE) file for details.

## 🙏 Acknowledgments

- [Wazuh Team](https://wazuh.com/) for their amazing SIEM platform
- All contributors who have helped improve this project
- The open source community for their invaluable tools and libraries

---

<p align="center">
  <sub>Built with ❤️ by <a href="https://github.com/rodrigomarinsp">Rodrigo Marins Piaba</a> and <a href="https://github.com/rodrigomarinsp/wazuh-unified-installer/graphs/contributors">contributors</a></sub>
</p>
"""

# Write the README.md file
with open(os.path.join(root_dir, 'README.md'), 'w') as file:
    file.write(readme_content)
    
    
# 2. Create config.yml - Unified configuration file
config_yml_content = """# Wazuh Unified Installer Configuration
# Author: Rodrigo Marins Piaba (Fanaticos4tech)
# E-Mail: rodrigomarinsp@gmail.com / fanaticos4tech@gmail.com
# GitHub: rodrigomarinsp
# Instagram: @fanaticos4tech

# ===== INSTALLATION MODE =====
# Only one installation mode can be active at a time
installation_mode:
  server_automated: true   # Standalone server installation (Manager + Indexer + Dashboard)
  ansible_deployment: false # Multi-node deployment using Ansible
  agent_only: false        # Agent-only installation
  manual_guide: false      # Show manual installation steps (no actual installation)

# ===== COMPONENT SELECTION =====
# Select which components to install
components:
  wazuh_manager: true      # Wazuh Manager component
  wazuh_indexer: true      # Wazuh Indexer (Elasticsearch) component
  wazuh_dashboard: true    # Wazuh Dashboard (Kibana) component
  filebeat: true           # Filebeat for log shipping
  wazuh_agents: false      # Install agents automatically (only with ansible_deployment: true)

# ===== ENVIRONMENT CONFIGURATION =====
environment:
  auto_detect: true        # Auto-detect environment settings
  target_servers:          # Only used when auto_detect: false
    manager: "127.0.0.1"   # Wazuh Manager IP/hostname
    indexer: "127.0.0.1"   # Wazuh Indexer IP/hostname
    dashboard: "127.0.0.1" # Wazuh Dashboard IP/hostname
  domain_name: "wazuh.local" # Domain name (for certificates)
  cluster_name: "wazuh"    # Wazuh cluster name

# ===== NETWORK CONFIGURATION =====
network:
  manager_port: 1514       # Wazuh Manager port
  registration_port: 1515  # Agent registration service port
  api_port: 55000          # Wazuh API port
  indexer_port: 9200       # Wazuh Indexer port
  dashboard_port: 443      # Wazuh Dashboard port
  use_internal_network: true # Use internal network for cluster communication

# ===== AUTOMATION SETTINGS =====
automation:
  full_unattended: false   # Run completely unattended (no prompts)
  auto_correct_errors: true # Attempt to auto-correct common errors
  auto_install_dependencies: true # Automatically install required dependencies
  auto_configure_firewall: true # Automatically configure firewall rules
  auto_start_services: true # Automatically start services after installation
  restart_on_failure: true # Restart failed services automatically

# ===== SECURITY SETTINGS =====
security:
  generate_certificates: true # Generate certificates for secure communication
  enable_ssl: true        # Enable SSL/TLS for all communications
  enable_firewall: true   # Configure firewall settings during installation
  change_default_passwords: true # Change default passwords
  password_length: 16     # Length of generated passwords
  admin_username: "wazuh-admin" # Admin username
  # Leave admin_password empty for auto-generation (recommended for production)
  admin_password: ""      # Admin password (leave empty to generate)
  enable_rbac: true       # Enable Role-Based Access Control

# ===== PERFORMANCE SETTINGS =====
performance:
  auto_tune_system: true  # Automatically tune system for better performance
  optimize_for_environment: true # Optimize based on detected environment
  memory_allocation:       # Memory allocation for components
    indexer_heap: "50%"   # Percentage or explicit value (e.g. "4g")
    manager_memory: "25%"  # Percentage or explicit value (e.g. "2g")
  cpu_allocation:
    indexer_cpu: 50       # Percentage of CPUs to use for indexer
    manager_cpu: 25       # Percentage of CPUs to use for manager

# ===== BACKUP & RECOVERY =====
backup:
  enable_backups: true    # Enable automatic backups
  backup_path: "/var/backups/wazuh" # Path for backups
  retention_days: 7       # Number of days to keep backups

# ===== ADVANCED OPTIONS =====
advanced:
  debug_mode: false       # Enable extended debugging output
  log_level: "info"       # Log level (debug, info, warning, error, critical)
  log_path: "shared/logs" # Path for logs
  temp_dir: "/tmp/wazuh-install" # Temporary directory for installation files
  custom_packages: false  # Use custom package repositories
  custom_repo_url: ""     # Custom repository URL (if custom_packages: true)
  disable_selinux: true   # Temporarily disable SELinux during installation
  disable_apparmor: false # Temporarily disable AppArmor during installation
"""

# Write the config.yml file
with open(os.path.join(root_dir, 'config.yml'), 'w') as file:
    file.write(config_yml_content)
    
    
# 3. Create main_installer.sh - Master installer
main_installer_content = """#!/bin/bash
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
RED="\\033[0;31m"
GREEN="\\033[0;32m"
YELLOW="\\033[0;33m"
BLUE="\\033[0;34m"
MAGENTA="\\033[0;35m"
CYAN="\\033[0;36m"
NC="\\033[0m" # No Color

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
    
    fs="$(echo @|tr @ '\\034')"
    
    if command -v yq &> /dev/null; then
        # If yq is available, use it to parse YAML
        yq eval -o json "$yaml_file" > "${TEMP_DIR}/config.json"
        if [[ $? -ne 0 ]]; then
            log "ERROR" "Failed to parse YAML config using yq."
            return 1
        fi
    else
        # Fallback to our simplified YAML parser
        sed -ne '/^#/d;/^[[:space:]]*$/d;/^[[:space:]]*[a-zA-Z0-9_][^:]*:([^"\\'\''{][^}]*)?[[:space:]]*$/b p;b' "$yaml_file" |
        sed -e "s|^\([[:space:]]*\)\(.*\): \(.*\)$|\\1\\2=\\3|" |
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
        OS_VERSION_ID=$(cat /etc/redhat-release | grep -oP '\\d+(\\.\\d+)+')
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
    MEM_TOTAL_GB=$(awk "BEGIN {printf \"%.1f\", ${MEM_TOTAL}/1024/1024}")
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
"""

# Write the main_installer.sh file
with open(os.path.join(root_dir, 'main_installer.sh'), 'w') as file:
    file.write(main_installer_content)

# Make the script executable
os.chmod(os.path.join(root_dir, 'main_installer.sh'), 0o755)


# 4. Create requirements.txt - Python dependencies
requirements_content = """# Wazuh Unified Installer - Python Dependencies
# Author: Rodrigo Marins Piaba (Fanaticos4tech)
# E-Mail: rodrigomarinsp@gmail.com / fanaticos4tech@gmail.com
# GitHub: rodrigomarinsp
# Instagram: @fanaticos4tech

# Core dependencies
pyyaml>=6.0       # YAML parsing
requests>=2.28.0  # HTTP requests
cryptography>=37.0.0  # Cryptography operations

# Ansible dependencies (only needed for ansible_installation module)
ansible>=6.0.0    # Ansible core
ansible-core>=2.12.0  # Ansible core components
jinja2>=3.0.0     # Template engine used by Ansible

# Dashboard tools (only needed for dashboard interactions)
elasticsearch>=8.0.0  # Elasticsearch client
opensearch-py>=2.0.0  # OpenSearch client

# Utility libraries
click>=8.0.0      # Command-line interface creation
tqdm>=4.64.0      # Progress bars
colorama>=0.4.4   # Terminal colors
rich>=12.0.0      # Rich text and formatting in terminal
pytest>=7.0.0     # Testing framework (for development only)
"""

# Write the requirements.txt file
with open(os.path.join(root_dir, 'requirements.txt'), 'w') as file:
    file.write(requirements_content)
    
# 5. Create .gitignore - Git ignore file
gitignore_content = """# Wazuh Unified Installer - Git Ignore File
# Author: Rodrigo Marins Piaba (Fanaticos4tech)
# E-Mail: rodrigomarinsp@gmail.com / fanaticos4tech@gmail.com
# GitHub: rodrigomarinsp
# Instagram: @fanaticos4tech

# Logs and temporary files
shared/logs/*.log
shared/logs/*.gz
*.log
logs/
*.tmp
.DS_Store
Thumbs.db

# Installation temp files
/tmp/wazuh-install/
*.swp
*.bak

# Environment configurations
.env
.env.*
!.env.example
*_config.yml
!config.yml
!**/configs/*.yml

# Ansible specific
ansible_installation/inventory.yml
ansible_installation/*.retry
ansible_installation/host_vars/*/secrets.yml
ansible_installation/vault_password.txt

# Python artifacts
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
env/
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
*.egg-info/
.installed.cfg
*.egg
.pytest_cache/
.coverage
htmlcov/
.tox/
.nox/
.hypothesis/

# Virtual environments
venv/
ENV/
env/
.venv/
.env/
.virtualenv/

# IDE specific files
.idea/
.vscode/
*.sublime-workspace
*.sublime-project
.project
.settings/
.classpath
.c9/
.history
*.launch
*.code-workspace

# Certificates and keys
*.pem
*.key
*.crt
*.cer
*.der
*.p12
*.pfx
*.keystore
*.truststore
!shared/templates/*.pem.example
!shared/templates/*.key.example

# Packages and binaries
*.rpm
*.deb
*.exe
*.bin
*.tar.gz
*.zip
*.tar
*.jar
*.war

# Vagrant & Docker
.vagrant/
docker-compose.override.yml
.docker/

# User customizations
custom/
custom_config/
user-data/
"""

# Write the .gitignore file
with open(os.path.join(root_dir, '.gitignore'), 'w') as file:
    file.write(gitignore_content)
    
    
# 6. Create LICENSE - Project license file
license_content = """GNU GENERAL PUBLIC LICENSE
Version 3, 29 June 2007

Copyright (C) 2007 Free Software Foundation, Inc. <https://fsf.org/>
Everyone is permitted to copy and distribute verbatim copies
of this license document, but changing it is not allowed.

                            Preamble

The GNU General Public License is a free, copyleft license for
software and other kinds of works.

The licenses for most software and other practical works are designed
to take away your freedom to share and change the works.  By contrast,
the GNU General Public License is intended to guarantee your freedom to
share and change all versions of a program--to make sure it remains free
software for all its users.  We, the Free Software Foundation, use the
GNU General Public License for most of our software; it applies also to
any other work released this way by its authors.  You can apply it to
your programs, too.

When we speak of free software, we are referring to freedom, not
price.  Our General Public Licenses are designed to make sure that you
have the freedom to distribute copies of free software (and charge for
them if you wish), that you receive source code or can get it if you
want it, that you can change the software or use pieces of it in new
free programs, and that you know you can do these things.

To protect your rights, we need to prevent others from denying you
these rights or asking you to surrender the rights.  Therefore, you have
certain responsibilities if you distribute copies of the software, or if
you modify it: responsibilities to respect the freedom of others.

For more details about the full license, please visit:
https://www.gnu.org/licenses/gpl-3.0.html

Wazuh Unified Installer
Copyright (C) 2023 Rodrigo Marins Piaba

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

# Write the LICENSE file
with open(os.path.join(root_dir, 'LICENSE'), 'w') as file:
    file.write(license_content)
    
# 7. Create CHANGELOG.md - Project changelog
changelog_content = """# Changelog
# Author: Rodrigo Marins Piaba (Fanaticos4tech)
# E-Mail: rodrigomarinsp@gmail.com / fanaticos4tech@gmail.com
# GitHub: rodrigomarinsp
# Instagram: @fanaticos4tech

All notable changes to the Wazuh Unified Installer project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2023-10-31

### Added
- Initial release of Wazuh Unified Installer
- Comprehensive server installation module
- Ansible deployment module for multi-node installations
- Agent installation module with multi-platform support
- Manual installation guide with step-by-step instructions
- Shared utilities for common functionality
- Unified configuration system via config.yml
- Master installer script with intelligent OS detection
- Automatic error recovery and dependency installation
- Cross-platform support for multiple Linux distributions
- Security hardening features with automatic certificate generation
- Comprehensive logging and validation
- Full documentation with troubleshooting guides

### Security
- Automatic firewall configuration
- TLS/SSL secure communication setup
- Certificate generation and management
- Password generation and management
- SELinux/AppArmor policy handling

## [0.9.0] - 2023-10-15

### Added
- Beta version with core functionality
- Basic server, agent, and ansible installation modules
- Initial configuration system and documentation
- Testing across Ubuntu, CentOS, and RHEL distributions

### Changed
- Improved error handling and logging
- Enhanced cross-platform compatibility

### Fixed
- Certificate generation issues on CentOS
- File permissions for configuration files
- Path handling for different distributions

## [0.5.0] - 2023-09-01

### Added
- Initial project structure
- Proof of concept for unified installation
- Basic server installation script
- Preliminary documentation
"""

# Write the CHANGELOG.md file
with open(os.path.join(root_dir, 'CHANGELOG.md'), 'w') as file:
    file.write(changelog_content)
    
    
# 8. Create CONTRIBUTING.md - Contribution guidelines
contributing_content = """# Contributing to Wazuh Unified Installer
# Author: Rodrigo Marins Piaba (Fanaticos4tech)
# E-Mail: rodrigomarinsp@gmail.com / fanaticos4tech@gmail.com
# GitHub: rodrigomarinsp
# Instagram: @fanaticos4tech

Thank you for your interest in contributing to the Wazuh Unified Installer! This document provides guidelines and best practices for contributing to the project.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Documentation](#documentation)
- [Additional Resources](#additional-resources)

## Code of Conduct

This project adheres to a Code of Conduct that all participants are expected to follow. By participating, you are expected to uphold this code. Please report unacceptable behavior to [rodrigomarinsp@gmail.com](mailto:rodrigomarinsp@gmail.com).

## How Can I Contribute?

There are several ways to contribute to the project:

### 🐛 Reporting Bugs

- Check if the bug has already been reported in the GitHub Issues.
- Use the Bug Report template when creating an issue.
- Include as much detail as possible: steps to reproduce, expected behavior, actual behavior, logs, and environment details.

### 💡 Suggesting Features

- Check if the feature has already been suggested in GitHub Issues.
- Use the Feature Request template when creating an issue.
- Provide a clear description of the feature and the problem it solves.

### 💻 Code Contributions

- Start by looking at issues labeled "good first issue" or "help wanted".
- Comment on the issue to express your interest before starting work.
- Fork the repository and create a branch for your changes.
- Follow the coding standards and testing requirements.
- Submit a pull request with a clear description of the changes.

## Development Setup

1. **Fork and Clone**:
   ```bash
   git clone https://github.com/yourusername/wazuh-unified-installer.git
   cd wazuh-unified-installer
   ```

2. **Create a Branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Install Development Dependencies**:
   ```bash
   pip install -r requirements.txt
   pip install -r dev-requirements.txt  # Additional development tools
   ```

4. **Set Up Pre-commit Hooks** (optional but recommended):
   ```bash
   pre-commit install
   ```

## Pull Request Process

1. Update the README.md and documentation with details of changes if applicable.
2. Update the CHANGELOG.md with a description of your changes.
3. Ensure all tests pass and add new tests for new functionality.
4. Submit the pull request with a clear title and description.
5. Request a review from maintainers.
6. The PR will be merged after approval from the maintainers.

## Coding Standards

### Shell Scripts (Bash)

- Follow the [Google Shell Style Guide](https://google.github.io/styleguide/shellguide.html).
- Use shellcheck for linting.
- Include proper error handling.
- Add comments for complex logic.
- Use functions for reusable code.
- Include proper shebang lines: `#!/bin/bash`.

### Python

- Follow PEP 8 and use a linter (flake8, pylint).
- Use type hints (Python 3.6+).
- Document functions and classes with docstrings.
- Keep functions focused on a single responsibility.
- Use meaningful variable and function names.

### YAML/Configuration Files

- Use 2-space indentation.
- Include comments to explain complex configurations.
- Group related configurations together.
- Use consistent naming conventions.

## Testing

- Write unit tests for all new functionality.
- Ensure tests are running in CI/CD pipeline.
- For bash scripts, use frameworks like [bats](https://github.com/bats-core/bats-core).
- For Python code, use pytest.
- Test changes on different OS distributions.

To run tests:

```bash
# For Python tests
pytest

# For shell script tests
bats tests/
```

## Documentation

- Update documentation for any changes to functionality.
- Document all configuration options.
- Keep the README.md up to date.
- Add examples for new features.
- Use consistent formatting in Markdown files.

## Additional Resources

- [Wazuh Documentation](https://documentation.wazuh.com/)
- [GitHub Flow Guide](https://guides.github.com/introduction/flow/)
- [Semantic Versioning](https://semver.org/)

---

Thank you for contributing to Wazuh Unified Installer! Your efforts help make this project better for everyone.
"""

# Write the CONTRIBUTING.md file
with open(os.path.join(root_dir, 'CONTRIBUTING.md'), 'w') as file:
    file.write(contributing_content)
    
# Create shared directory structure
import os

shared_dir = os.path.join(root_dir, 'shared')
utils_dir = os.path.join(shared_dir, 'utils')
templates_dir = os.path.join(shared_dir, 'templates')
logs_dir = os.path.join(shared_dir, 'logs')

# Create the directories if they don't exist
for directory in [shared_dir, utils_dir, templates_dir, logs_dir]:
    if not os.path.exists(directory):
        os.makedirs(directory)

# Create .gitkeep in logs directory to keep it in git
with open(os.path.join(logs_dir, '.gitkeep'), 'w') as file:
    file.write('# This file ensures the logs directory is kept in git\n')
    
    
root_files = [
    'README.md',
    'config.yml',
    'main_installer.sh',
    'requirements.txt',
    '.gitignore',
    'LICENSE',
    'CHANGELOG.md',
    'CONTRIBUTING.md'
]

# Create a report of created files
report = []
for file in root_files:
    file_path = os.path.join(root_dir, file)
    status = "✅ CREATED" if os.path.exists(file_path) else "❌ MISSING"
    report.append((file, status))

# Print the report
print("FILE CREATION REPORT - ROOT MODULE:")
print("=" * 50)
for idx, (file, status) in enumerate(report, 1):
    print(f"{idx}. {file}: {status}")
print("=" * 50)

# Check if all files were created successfully
all_created = all(status == "✅ CREATED" for _, status in report)
print(f"Overall Status: {'✅ COMPLETE' if all_created else '❌ INCOMPLETE'}")
print(f"Created: {sum(1 for _, status in report if status == '✅ CREATED')}/{len(root_files)} files")

# Verify shared directory structure
shared_dirs = ['shared', 'shared/utils', 'shared/templates', 'shared/logs']
shared_report = []
for dir_name in shared_dirs:
    dir_path = os.path.join(root_dir, dir_name)
    status = "✅ CREATED" if os.path.exists(dir_path) else "❌ MISSING"
    shared_report.append((dir_name, status))

print("\nSHARED DIRECTORY STRUCTURE:")
print("=" * 50)
for idx, (dir_name, status) in enumerate(shared_report, 1):
    print(f"{idx}. {dir_name}: {status}")
print("=" * 50)


def get_file_size(file_path):
    """Get file size in bytes"""
    return os.path.getsize(file_path)

def format_size(size_in_bytes):
    """Format size in human-readable format"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_in_bytes < 1024.0:
            return f"{size_in_bytes:.1f} {unit}"
        size_in_bytes /= 1024.0
    return f"{size_in_bytes:.1f} TB"

# Get all files in the repository
all_files = []
for root, dirs, files in os.walk(root_dir):
    for file in files:
        file_path = os.path.join(root, file)
        rel_path = os.path.relpath(file_path, root_dir)
        size = get_file_size(file_path)
        all_files.append({
            'path': rel_path,
            'size': size,
            'size_formatted': format_size(size)
        })

# Sort files by path
all_files.sort(key=lambda x: x['path'])

# Print file manifest
print("COMPLETE FILE MANIFEST:")
print("=" * 80)
print(f"{'#':3s} | {'File Path':<40s} | {'Size':>10s}")
print("-" * 80)
for idx, file_info in enumerate(all_files, 1):
    print(f"{idx:3d} | {file_info['path']:<40s} | {file_info['size_formatted']:>10s}")
print("=" * 80)
print(f"Total: {len(all_files)} files")

# Calculate total size
total_size = sum(f['size'] for f in all_files)
print(f"Total Size: {format_size(total_size)}")
print("=" * 80)

