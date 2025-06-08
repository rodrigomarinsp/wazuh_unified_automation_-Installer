#!/bin/bash

# Wazuh Unified Installer - Ansible Deployment Wrapper Script
# Author: Rodrigo Marins Piaba (Fanaticos4tech)
# E-Mail: rodrigomarinsp@gmail.com / fanaticos4tech@gmail.com
# GitHub: rodrigomarinsp
# Instagram: @fanaticos4tech

set -euo pipefail

# 🎨 Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# 📁 Script directory and paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
ANSIBLE_DIR="$SCRIPT_DIR"
LOGS_DIR="$ANSIBLE_DIR/logs"
BACKUP_DIR="$ANSIBLE_DIR/backups"

# 📊 Default configuration
DEFAULT_INVENTORY="inventory.yml"
DEFAULT_PLAYBOOK="ansible_deploy.yml"
DEFAULT_ENVIRONMENT="production"
DEFAULT_LOG_LEVEL="INFO"

# 🔧 Configuration variables
INVENTORY_FILE="$DEFAULT_INVENTORY"
PLAYBOOK_FILE="$DEFAULT_PLAYBOOK"
ENVIRONMENT="$DEFAULT_ENVIRONMENT"
LOG_LEVEL="$DEFAULT_LOG_LEVEL"
ANSIBLE_OPTS=""
TAGS=""
SKIP_TAGS=""
LIMIT=""
CHECK_MODE=false
DIFF_MODE=false
VERBOSE=false
FORCE=false
BACKUP_BEFORE=false
VALIDATE_ONLY=false
INSTALL_REQUIREMENTS=false

# 📝 Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOGS_DIR/deploy.log"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOGS_DIR/deploy.log"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOGS_DIR/deploy.log"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOGS_DIR/deploy.log"
}

log_debug() {
    if [[ "$VERBOSE" == "true" ]]; then
        echo -e "${PURPLE}[DEBUG]${NC} $1" | tee -a "$LOGS_DIR/deploy.log"
    fi
}

# 🆘 Help function
show_help() {
    cat << EOF
${WHITE}🛡️  Wazuh Unified Installer - Ansible Deployment Script${NC}

${CYAN}USAGE:${NC}
    $0 [OPTIONS]

${CYAN}COMMON DEPLOYMENT SCENARIOS:${NC}
    ${GREEN}# Complete fresh installation${NC}
    $0 --environment production --install-all

    ${GREEN}# Update existing installation${NC}
    $0 --environment production --tags update

    ${GREEN}# Deploy only agents${NC}
    $0 --environment production --tags agents

    ${GREEN}# Validate installation${NC}
    $0 --environment production --tags validate

    ${GREEN}# Check mode (dry run)${NC}
    $0 --environment production --check --diff

${CYAN}OPTIONS:${NC}
    ${YELLOW}General Options:${NC}
    -i, --inventory FILE        Ansible inventory file (default: $DEFAULT_INVENTORY)
    -p, --playbook FILE         Ansible playbook file (default: $DEFAULT_PLAYBOOK)
    -e, --environment ENV       Target environment (default: $DEFAULT_ENVIRONMENT)
    -l, --limit PATTERN         Limit execution to hosts matching pattern
    
    ${YELLOW}Execution Options:${NC}
    -t, --tags TAGS             Run only tasks tagged with these values
    -s, --skip-tags TAGS        Skip tasks tagged with these values
    -c, --check                 Run in check mode (dry run)
    -d, --diff                  Show differences when changing files
    -f, --force                 Force execution even with warnings
    
    ${YELLOW}Installation Options:${NC}
    --install-all               Install all components (managers, indexers, dashboard, agents)
    --install-requirements      Install Ansible Galaxy requirements before deployment
    --managers-only             Install only Wazuh managers
    --indexers-only             Install only Wazuh indexers
    --dashboard-only            Install only Wazuh dashboard
    --agents-only               Install only Wazuh agents
    
    ${YELLOW}Maintenance Options:${NC}
    --backup-before             Create backup before deployment
    --validate-only             Only run validation checks
    --update                    Update existing installation
    --restart                   Restart services after deployment
    
    ${YELLOW}Logging Options:${NC}
    -v, --verbose               Enable verbose output
    --log-level LEVEL           Set log level (DEBUG, INFO, WARNING, ERROR)
    
    ${YELLOW}Help:${NC}
    -h, --help                  Show this help message

${CYAN}EXAMPLES:${NC}
    ${GREEN}# Production deployment with all components${NC}
    $0 -e production --install-all --backup-before

    ${GREEN}# Development environment with only managers${NC}
    $0 -e development --managers-only -v

    ${GREEN}# Update agents on specific hosts${NC}
    $0 -e production --agents-only --update -l "web_servers"

    ${GREEN}# Dry run with diff output${NC}
    $0 -e staging --check --diff --install-all

    ${GREEN}# Validate specific components${NC}
    $0 -e production --validate-only -t "managers,indexers"

${CYAN}CONFIGURATION FILES:${NC}
    📄 Inventory: $ANSIBLE_DIR/$DEFAULT_INVENTORY
    📄 Playbook: $ANSIBLE_DIR/$DEFAULT_PLAYBOOK
    📄 Requirements: $ANSIBLE_DIR/requirements.yml
    📁 Logs: $LOGS_DIR/
    📁 Backups: $BACKUP_DIR/

${CYAN}ENVIRONMENT VARIABLES:${NC}
    ANSIBLE_CONFIG          Path to ansible.cfg file
    ANSIBLE_INVENTORY       Default inventory file
    ANSIBLE_VAULT_PASSWORD  Vault password for encrypted variables
    WAZUH_VERSION          Override default Wazuh version

${CYAN}PREREQUISITES:${NC}
    • Ansible 2.12+ installed
    • SSH access to target hosts
    • sudo/root privileges on target hosts
    • Python 3.8+ on control node

EOF
}

# 🔍 Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check if Ansible is installed
    if ! command -v ansible-playbook &> /dev/null; then
        log_error "Ansible is not installed. Please install Ansible first."
        exit 1
    fi
    
    # Check Ansible version
    local ansible_version
    ansible_version=$(ansible --version | head -n1 | cut -d' ' -f3)
    log_info "Ansible version: $ansible_version"
    
    # Check if inventory file exists
    if [[ ! -f "$ANSIBLE_DIR/$INVENTORY_FILE" ]]; then
        log_error "Inventory file not found: $ANSIBLE_DIR/$INVENTORY_FILE"
        log_info "Please copy and configure the inventory template:"
        log_info "cp $ANSIBLE_DIR/inventory_template.yml $ANSIBLE_DIR/$INVENTORY_FILE"
        exit 1
    fi
    
    # Check if playbook file exists
    if [[ ! -f "$ANSIBLE_DIR/$PLAYBOOK_FILE" ]]; then
        log_error "Playbook file not found: $ANSIBLE_DIR/$PLAYBOOK_FILE"
        exit 1
    fi
    
    # Create logs directory
    mkdir -p "$LOGS_DIR"
    
    # Create backup directory if backup is requested
    if [[ "$BACKUP_BEFORE" == "true" ]]; then
        mkdir -p "$BACKUP_DIR"
    fi
    
    log_success "Prerequisites check completed"
}

# 📦 Install Ansible Galaxy requirements
install_requirements() {
    log_info "Installing Ansible Galaxy requirements..."
    
    if [[ -f "$ANSIBLE_DIR/requirements.yml" ]]; then
        ansible-galaxy install -r "$ANSIBLE_DIR/requirements.yml" --force
        ansible-galaxy collection install -r "$ANSIBLE_DIR/requirements.yml" --force
        log_success "Requirements installed successfully"
    else
        log_warning "Requirements file not found: $ANSIBLE_DIR/requirements.yml"
    fi
}

# 🔍 Validate inventory
validate_inventory() {
    log_info "Validating inventory configuration..."
    
    # Test inventory syntax
    if ! ansible-inventory -i "$ANSIBLE_DIR/$INVENTORY_FILE" --list > /dev/null 2>&1; then
        log_error "Inventory file has syntax errors"
        exit 1
    fi
    
    # Test connectivity
    log_info "Testing connectivity to all hosts..."
    if ! ansible all -i "$ANSIBLE_DIR/$INVENTORY_FILE" -m ping --one-line; then
        log_warning "Some hosts are not reachable"
        if [[ "$FORCE" != "true" ]]; then
            log_error "Use --force to continue with unreachable hosts"
            exit 1
        fi
    fi
    
    log_success "Inventory validation completed"
}

# 💾 Create backup
create_backup() {
    if [[ "$BACKUP_BEFORE" != "true" ]]; then
        return 0
    fi
    
    log_info "Creating backup before deployment..."
    
    local backup_timestamp
    backup_timestamp=$(date +"%Y%m%d_%H%M%S")
    local backup_path="$BACKUP_DIR/backup_$backup_timestamp"
    
    mkdir -p "$backup_path"
    
    # Run backup playbook if it exists
    if [[ -f "$ANSIBLE_DIR/playbooks/backup.yml" ]]; then
        ansible-playbook -i "$ANSIBLE_DIR/$INVENTORY_FILE" \
            "$ANSIBLE_DIR/playbooks/backup.yml" \
            -e "backup_destination=$backup_path" \
            --extra-vars "environment=$ENVIRONMENT"
        log_success "Backup created at: $backup_path"
    else
        log_warning "Backup playbook not found, skipping backup"
    fi
}

# 🚀 Run Ansible deployment
run_deployment() {
    log_info "Starting Wazuh deployment..."
    
    # Build Ansible command
    local ansible_cmd="ansible-playbook"
    local ansible_args=()
    
    # Inventory
    ansible_args+=("-i" "$ANSIBLE_DIR/$INVENTORY_FILE")
    
    # Playbook
    ansible_args+=("$ANSIBLE_DIR/$PLAYBOOK_FILE")
    
    # Environment
    ansible_args+=("--extra-vars" "target_environment=$ENVIRONMENT")
    
    # Tags
    if [[ -n "$TAGS" ]]; then
        ansible_args+=("--tags" "$TAGS")
    fi
    
    # Skip tags
    if [[ -n "$SKIP_TAGS" ]]; then
        ansible_args+=("--skip-tags" "$SKIP_TAGS")
    fi
    
    # Limit
    if [[ -n "$LIMIT" ]]; then
        ansible_args+=("--limit" "$LIMIT")
    fi
    
    # Check mode
    if [[ "$CHECK_MODE" == "true" ]]; then
        ansible_args+=("--check")
    fi
    
    # Diff mode
    if [[ "$DIFF_MODE" == "true" ]]; then
        ansible_args+=("--diff")
    fi
    
    # Verbose
    if [[ "$VERBOSE" == "true" ]]; then
        ansible_args+=("-vvv")
    fi
    
    # Additional options
    if [[ -n "$ANSIBLE_OPTS" ]]; then
        ansible_args+=($ANSIBLE_OPTS)
    fi
    
    # Log command
    log_debug "Executing: $ansible_cmd ${ansible_args[*]}"
    
    # Execute deployment
    local start_time
    start_time=$(date +%s)
    
    if "$ansible_cmd" "${ansible_args[@]}" 2>&1 | tee -a "$LOGS_DIR/deploy.log"; then
        local end_time
        end_time=$(date +%s)
        local duration=$((end_time - start_time))
        log_success "Deployment completed successfully in ${duration}s"
        return 0
    else
        local end_time
        end_time=$(date +%s)
        local duration=$((end_time - start_time))
        log_error "Deployment failed after ${duration}s"
        return 1
    fi
}

# 📊 Show deployment summary
show_summary() {
    log_info "Deployment Summary:"
    echo -e "${CYAN}=====================================${NC}"
    echo -e "${WHITE}🛡️  Wazuh Deployment Summary${NC}"
    echo -e "${CYAN}=====================================${NC}"
    echo -e "${YELLOW}Environment:${NC} $ENVIRONMENT"
    echo -e "${YELLOW}Inventory:${NC} $INVENTORY_FILE"
    echo -e "${YELLOW}Playbook:${NC} $PLAYBOOK_FILE"
    echo -e "${YELLOW}Tags:${NC} ${TAGS:-'all'}"
    echo -e "${YELLOW}Timestamp:${NC} $(date)"
    echo -e "${CYAN}=====================================${NC}"
    
    # Show log location
    echo -e "${YELLOW}📋 Logs available at:${NC} $LOGS_DIR/deploy.log"
    
    # Show access information if deployment was successful
    if [[ -f "$ANSIBLE_DIR/wazuh_deployment_$(date +%s).env" ]]; then
        log_info "Access information saved to deployment environment file"
    fi
}

# 🎛️ Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -i|--inventory)
                INVENTORY_FILE="$2"
                shift 2
                ;;
            -p|--playbook)
                PLAYBOOK_FILE="$2"
                shift 2
                ;;
            -e|--environment)
                ENVIRONMENT="$2"
                shift 2
                ;;
            -l|--limit)
                LIMIT="$2"
                shift 2
                ;;
            -t|--tags)
                TAGS="$2"
                shift 2
                ;;
            -s|--skip-tags)
                SKIP_TAGS="$2"
                shift 2
                ;;
            -c|--check)
                CHECK_MODE=true
                shift
                ;;
            -d|--diff)
                DIFF_MODE=true
                shift
                ;;
            -f|--force)
                FORCE=true
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            --log-level)
                LOG_LEVEL="$2"
                shift 2
                ;;
            --install-all)
                TAGS="prerequisites,server,agents"
                shift
                ;;
            --install-requirements)
                INSTALL_REQUIREMENTS=true
                shift
                ;;
            --managers-only)
                TAGS="prerequisites,managers"
                shift
                ;;
            --indexers-only)
                TAGS="prerequisites,indexers"
                shift
                ;;
            --dashboard-only)
                TAGS="prerequisites,dashboard"
                shift
                ;;
            --agents-only)
                TAGS="prerequisites,agents"
                shift
                ;;
            --backup-before)
                BACKUP_BEFORE=true
                shift
                ;;
            --validate-only)
                VALIDATE_ONLY=true
                TAGS="validate"
                shift
                ;;
            --update)
                TAGS="${TAGS:+$TAGS,}update"
                shift
                ;;
            --restart)
                TAGS="${TAGS:+$TAGS,}restart"
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

# 🚀 Main execution function
main() {
    # Print banner
    echo -e "${WHITE}"
    echo "🛡️  =================================="
    echo "🛡️  Wazuh Unified Installer - Ansible"
    echo "🛡️  Author: Rodrigo Marins Piaba"
    echo "🛡️  =================================="
    echo -e "${NC}"
    
    # Parse arguments
    parse_arguments "$@"
    
    # Set up logging based on level
    export ANSIBLE_LOG_PATH="$LOGS_DIR/ansible.log"
    
    # Change to ansible directory
    cd "$ANSIBLE_DIR"
    
    # Check prerequisites
    check_prerequisites
    
    # Install requirements if requested
    if [[ "$INSTALL_REQUIREMENTS" == "true" ]]; then
        install_requirements
    fi
    
    # Validate inventory unless in check mode
    if [[ "$CHECK_MODE" != "true" ]]; then
        validate_inventory
    fi
    
    # Create backup if requested
    create_backup
    
    # Run deployment
    if run_deployment; then
        show_summary
        log_success "🎉 Wazuh deployment completed successfully!"
        exit 0
    else
        show_summary
        log_error "❌ Wazuh deployment failed!"
        exit 1
    fi
}

# 🎯 Script execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
