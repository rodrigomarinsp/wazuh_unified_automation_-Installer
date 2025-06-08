"""
Wazuh Server Installation Script - Python Implementation
Author: Rodrigo Marins Piaba (Fanaticos4tech)
E-Mail: rodrigomarinsp@gmail.com / fanaticos4tech@gmail.com
GitHub: rodrigomarinsp
Instagram: @fanaticos4tech
License: GPL-3.0

Advanced Python installer with enhanced features, logging, and automation capabilities.
FINAL VERSION with binary data handling fix for Ubuntu 24.04
"""

import argparse
import json
import logging
import os
import platform
import re
import shutil
import subprocess
import sys
import time
import urllib.request
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from shutil import which

# =============================================================================
# CONSTANTS AND CONFIGURATION
# =============================================================================

VERSION = "1.0.1"
AUTHOR = "Rodrigo Marins Piaba (Fanaticos4tech)"

# Supported operating systems
SUPPORTED_OS = {
    'ubuntu': ['18.04', '20.04', '22.04', '24.04'],
    'debian': ['10', '11', '12'],
    'centos': ['7', '8'],
    'rhel': ['7', '8', '9'],
    'amazon': ['2', '2023']
}

# Required dependencies
REQUIRED_TOOLS = ['curl', 'wget', 'gpg', 'openssl', 'systemctl']

# Wazuh package versions
WAZUH_VERSION = "4.9.2"
WAZUH_PACKAGES = {
    'indexer': f'wazuh-indexer={WAZUH_VERSION}-1',
    'manager': f'wazuh-manager={WAZUH_VERSION}-1',
    'dashboard': f'wazuh-dashboard={WAZUH_VERSION}-1'
}

# Network settings
DEFAULT_PORTS = {
    'indexer': 9200,
    'manager': 1514,
    'dashboard': 443,
    'api': 55000
}

# Installation steps for progress tracking
INSTALLATION_STEPS = [
    "Validating system",
    "Checking dependencies", 
    "Getting network configuration",
    "Setting up Wazuh repository",
    "Installing Wazuh Indexer",
    "Setting up SSL certificates",
    "Installing Wazuh Manager",
    "Installing Wazuh Dashboard",
    "Starting services",
    "Final validation"
]

# =============================================================================
# LOGGING CONFIGURATION
# =============================================================================

class ColorFormatter(logging.Formatter):
    """Custom formatter with colors for console output"""
    
    COLORS = {
        'DEBUG': '\033[36m',    # Cyan
        'INFO': '\033[32m',     # Green
        'WARNING': '\033[33m',  # Yellow
        'ERROR': '\033[31m',    # Red
        'CRITICAL': '\033[35m', # Magenta
        'RESET': '\033[0m'      # Reset
    }
    
    def format(self, record):
        color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
        reset = self.COLORS['RESET']
        
        # Format timestamp
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Create formatted message
        formatted_msg = f"{color}{timestamp} - {record.levelname} - {record.getMessage()}{reset}"
        return formatted_msg

def setup_logging(verbose: bool = False, log_file: Optional[str] = None) -> logging.Logger:
    """Setup logging configuration"""
    logger = logging.getLogger('wazuh_installer')
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    
    # Remove existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # Console handler with colors
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    console_handler.setFormatter(ColorFormatter())
    logger.addHandler(console_handler)
    
    # File handler if specified
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
    
    return logger

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def run_command(command: List[str], timeout: int = 300, check: bool = True, 
                capture_output: bool = True, text: bool = True) -> subprocess.CompletedProcess:
    """Execute system command with proper error handling"""
    logger = logging.getLogger('wazuh_installer')
    
    try:
        logger.debug(f"Executing command: {' '.join(command)}")
        
        result = subprocess.run(
            command,
            timeout=timeout,
            check=check,
            capture_output=capture_output,
            text=text
        )
        
        if result.returncode != 0 and check:
            logger.error(f"Command failed: {' '.join(command)}")
            logger.error(f"Return code: {result.returncode}")
            if hasattr(result, 'stdout') and result.stdout:
                logger.error(f"Stdout: {result.stdout}")
            if hasattr(result, 'stderr') and result.stderr:
                logger.error(f"Stderr: {result.stderr}")
        
        return result
    
    except subprocess.TimeoutExpired as e:
        error_msg = f"Command timed out after {timeout} seconds: {' '.join(command)}"
        logger.error(error_msg)
        raise Exception(error_msg)
    
    except subprocess.CalledProcessError as e:
        error_msg = f"Command failed with return code {e.returncode}: {' '.join(command)}"
        logger.error(error_msg)
        raise Exception(error_msg)
    
    except Exception as e:
        error_msg = f"Unexpected error executing command: {e}"
        logger.error(error_msg)
        raise Exception(error_msg)

def run_command_with_input(command: List[str], input_data: bytes, timeout: int = 300) -> subprocess.CompletedProcess:
    """Execute command with binary input data (for GPG operations)"""
    logger = logging.getLogger('wazuh_installer')
    
    try:
        logger.debug(f"Executing command with input: {' '.join(command)}")
        
        result = subprocess.run(
            command,
            input=input_data,
            timeout=timeout,
            capture_output=True,
            check=False  # Don't raise on non-zero exit
        )
        
        return result
    
    except Exception as e:
        error_msg = f"Error executing command with input: {e}"
        logger.error(error_msg)
        raise Exception(error_msg)

def show_progress(step: int, total: int, description: str):
    """Display progress bar"""
    logger = logging.getLogger('wazuh_installer')
    
    percentage = (step / total) * 100
    filled = int(percentage / 5)  # 20 characters total
    bar = '█' * filled + '░' * (20 - filled)
    
    logger.info(f"[{step}/{total}] ({percentage:.1f}%) {bar} {description}")

def check_root():
    """Check if running as root"""
    if os.geteuid() != 0:
        raise Exception("This script must be run as root. Use 'sudo python3 server_install.py'")

def get_system_info() -> Dict[str, str]:
    """Get system information"""
    logger = logging.getLogger('wazuh_installer')
    
    logger.info("Gathering system information...")
    
    try:
        # Get OS information
        with open('/etc/os-release', 'r') as f:
            os_release = f.read()
        
        # Parse OS information
        os_info = {}
        for line in os_release.split('\n'):
            if '=' in line:
                key, value = line.split('=', 1)
                os_info[key] = value.strip('"')
        
        # Get system details
        system_info = {
            'os_name': os_info.get('NAME', platform.system()),
            'os_id': os_info.get('ID', '').lower(),
            'os_version': os_info.get('VERSION_ID', ''),
            'architecture': platform.machine(),
            'kernel': platform.release()
        }
        
        logger.info(f"System: {system_info['os_name']}")
        logger.info(f"OS ID: {system_info['os_id']}")
        logger.info(f"OS Version: {system_info['os_version']}")
        logger.info(f"Architecture: {system_info['architecture']}")
        
        return system_info
    
    except Exception as e:
        raise Exception(f"Failed to get system information: {e}")

def check_os_support(os_id: str, os_version: str) -> bool:
    """Check if OS is supported"""
    logger = logging.getLogger('wazuh_installer')
    
    logger.info(f"Checking OS support for {os_id} {os_version}")
    
    if os_id not in SUPPORTED_OS:
        return False
    
    if os_version not in SUPPORTED_OS[os_id]:
        return False
    
    logger.info(f"Supported OS: {os_id} {os_version}")
    return True

def check_dependencies() -> List[str]:
    """Check for required system dependencies"""
    logger = logging.getLogger('wazuh_installer')
    
    logger.info("Checking required dependencies...")
    
    missing_tools = []
    available_tools = []
    
    for tool in REQUIRED_TOOLS:
        if which(tool):
            available_tools.append(tool)
        else:
            missing_tools.append(tool)
    
    logger.info(f"Available tools: {available_tools}")
    
    if missing_tools:
        logger.warning(f"Missing tools: {missing_tools}")
        return missing_tools
    
    logger.info("All required dependencies are available")
    return []

def install_dependencies(missing_tools: List[str], os_id: str):
    """Install missing dependencies"""
    logger = logging.getLogger('wazuh_installer')
    
    if not missing_tools:
        return
    
    logger.info(f"Installing missing tools: {', '.join(missing_tools)}")
    
    if os_id in ['ubuntu', 'debian', 'linux']:
        # Update package cache
        run_command(['apt-get', 'update'])
        
        # Install missing tools
        cmd = ['apt-get', 'install', '-y'] + missing_tools
        run_command(cmd)
    
    elif os_id in ['centos', 'rhel']:
        cmd = ['yum', 'install', '-y'] + missing_tools
        run_command(cmd)
    
    elif os_id == 'amazon':
        cmd = ['yum', 'install', '-y'] + missing_tools
        run_command(cmd)
    
    else:
        raise Exception(f"Unsupported OS for dependency installation: {os_id}")
    
    logger.info("Successfully installed missing tools")

def get_network_info() -> Tuple[str, str]:
    """Get hostname and IP address"""
    logger = logging.getLogger('wazuh_installer')
    
    logger.info("Getting network information...")
    
    try:
        # Get hostname
        hostname_result = run_command(['hostname'], capture_output=True, text=True)
        hostname = hostname_result.stdout.strip()
        
        # Get IP address
        ip_result = run_command(['hostname', '-I'], capture_output=True, text=True)
        ip_address = ip_result.stdout.strip().split()[0]
        
        logger.info(f"Hostname: {hostname}")
        logger.info(f"IP address (hostname -I): {ip_address}")
        
        return hostname, ip_address
    
    except Exception as e:
        logger.warning(f"Failed to get network info automatically: {e}")
        # Fallback values
        return "wazuh-server", "127.0.0.1"

# =============================================================================
# REPOSITORY MANAGEMENT
# =============================================================================

def get_ubuntu_codename_for_wazuh(version: str) -> str:
    """Get Ubuntu codename for Wazuh repository"""
    # Ubuntu 24.04 uses jammy repository as wazuh doesn't have noble packages yet
    if version in ['20.04']:
        return 'focal'
    elif version in ['22.04', '24.04']:  # 24.04 uses 22.04 repo for compatibility
        return 'jammy'
    else:
        return 'jammy'  # Default to jammy for newer versions

def setup_wazuh_repository(os_id: str, os_version: str):
    """Setup Wazuh repository based on OS"""
    logger = logging.getLogger('wazuh_installer')
    
    logger.info("Setting up Wazuh repository...")
    
    if os_id == 'ubuntu':
        setup_ubuntu_repository(os_version)
    elif os_id == 'debian':
        setup_debian_repository(os_version)
    elif os_id in ['centos', 'rhel']:
        setup_rhel_repository(os_id, os_version)
    elif os_id == 'amazon':
        setup_amazon_repository(os_version)
    else:
        raise Exception(f"Unsupported OS for repository setup: {os_id}")

def setup_ubuntu_repository(os_version: str):
    """Setup Wazuh repository for Ubuntu"""
    logger = logging.getLogger('wazuh_installer')
    
    logger.info(f"Setting up Wazuh repository for ubuntu {os_version}")
    
    # Get compatible codename
    codename = get_ubuntu_codename_for_wazuh(os_version)
    logger.info(f"Using repository codename: {codename}")
    
    try:
        # Create keyrings directory
        keyrings_dir = Path("/usr/share/keyrings")
        keyrings_dir.mkdir(exist_ok=True)
        logger.debug(f"Directory created: {keyrings_dir}")
        
        # Download and import GPG key using binary mode
        logger.info("Downloading Wazuh GPG key...")
        
        # Step 1: Download GPG key as binary data
        curl_result = run_command(
            ['curl', '-fsSL', 'https://packages.wazuh.com/key/GPG-KEY-WAZUH'],
            capture_output=True,
            text=False  # Binary mode for GPG key
        )
        
        if curl_result.returncode != 0:
            raise Exception(f"Failed to download GPG key: {curl_result.stderr}")
        
        # Step 2: Convert to binary format using gpg --dearmor
        gpg_result = run_command_with_input(
            ['gpg', '--dearmor'],
            curl_result.stdout  # Binary data
        )
        
        if gpg_result.returncode != 0:
            raise Exception(f"Failed to process GPG key: {gpg_result.stderr}")
        
        # Step 3: Write binary keyring file
        keyring_path = "/usr/share/keyrings/wazuh.gpg"
        with open(keyring_path, 'wb') as f:
            f.write(gpg_result.stdout)
        
        # Set proper permissions
        os.chmod(keyring_path, 0o644)
        
        logger.info("GPG key imported successfully")
        
        # Add repository
        logger.info("Adding Wazuh repository to sources...")
        
        repo_content = f"deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ {codename} main\n"
        
        with open("/etc/apt/sources.list.d/wazuh.list", "w") as f:
            f.write(repo_content)
        
        logger.info(f"Repository added for {codename}")
        
        # Update package cache
        logger.info("Updating package cache...")
        run_command(['apt-get', 'update'])
        
        logger.info("Successfully added Wazuh repository")
    
    except Exception as e:
        raise Exception(f"Failed to setup Ubuntu repository: {e}")

def setup_debian_repository(os_version: str):
    """Setup Wazuh repository for Debian"""
    # Similar to Ubuntu but with debian codenames
    setup_ubuntu_repository("22.04")  # Use jammy as fallback

def setup_rhel_repository(os_id: str, os_version: str):
    """Setup Wazuh repository for RHEL/CentOS"""
    logger = logging.getLogger('wazuh_installer')
    
    logger.info(f"Setting up Wazuh repository for {os_id} {os_version}")
    
    try:
        # Import GPG key
        run_command(['rpm', '--import', 'https://packages.wazuh.com/key/GPG-KEY-WAZUH'])
        
        # Add repository
        repo_content = f"""[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-{os_version} - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
"""
        
        with open("/etc/yum.repos.d/wazuh.repo", "w") as f:
            f.write(repo_content)
        
        logger.info("Successfully added Wazuh repository")
    
    except Exception as e:
        raise Exception(f"Failed to setup RHEL repository: {e}")

def setup_amazon_repository(os_version: str):
    """Setup Wazuh repository for Amazon Linux"""
    setup_rhel_repository("amazon", os_version)

# =============================================================================
# SSL CERTIFICATE MANAGEMENT
# =============================================================================

def setup_ssl_certificates(hostname: str, ip_address: str):
    """Setup SSL certificates for Wazuh components"""
    logger = logging.getLogger('wazuh_installer')
    
    logger.info("Setting up SSL certificates...")
    
    cert_dir = Path("/etc/wazuh-indexer/certs")
    cert_dir.mkdir(parents=True, exist_ok=True)
    
    try:
        # Generate certificates
        generate_root_ca(cert_dir)
        generate_node_certificate(cert_dir, hostname, ip_address)
        generate_admin_certificate(cert_dir)
        
        # Set proper permissions
        set_certificate_permissions(cert_dir)
        
        logger.info("SSL certificates setup completed")
    
    except Exception as e:
        raise Exception(f"Failed to setup SSL certificates: {e}")

def generate_root_ca(cert_dir: Path):
    """Generate root CA certificate"""
    logger = logging.getLogger('wazuh_installer')
    
    logger.info("Generating root CA certificate...")
    
    # Generate private key
    run_command([
        'openssl', 'genrsa', '-out', 
        str(cert_dir / 'root-ca-key.pem'), '2048'
    ])
    
    # Generate root certificate
    run_command([
        'openssl', 'req', '-new', '-x509',
        '-key', str(cert_dir / 'root-ca-key.pem'),
        '-out', str(cert_dir / 'root-ca.pem'),
        '-days', '365',
        '-subj', '/C=US/ST=CA/L=San Francisco/O=Wazuh/OU=IT/CN=root-ca'
    ])
    
    logger.info("Root CA generated successfully")

def generate_node_certificate(cert_dir: Path, hostname: str, ip_address: str):
    """Generate node certificate with proper SAN"""
    logger = logging.getLogger('wazuh_installer')
    
    logger.info("Generating node certificate...")
    
    # Generate private key
    run_command([
        'openssl', 'genrsa', '-out',
        str(cert_dir / 'node-key.pem'), '2048'
    ])
    
    # Generate certificate signing request
    run_command([
        'openssl', 'req', '-new',
        '-key', str(cert_dir / 'node-key.pem'),
        '-out', str(cert_dir / 'node.csr'),
        '-subj', f'/C=US/ST=CA/L=San Francisco/O=Wazuh/OU=IT/CN={hostname}'
    ])
    
    # Generate certificate with SAN (using -addext to avoid extension file issues)
    san_extension = f'subjectAltName=DNS:localhost,DNS:wazuh-indexer,DNS:{hostname},IP:127.0.0.1,IP:{ip_address}'
    
    run_command([
        'openssl', 'x509', '-req',
        '-in', str(cert_dir / 'node.csr'),
        '-CA', str(cert_dir / 'root-ca.pem'),
        '-CAkey', str(cert_dir / 'root-ca-key.pem'),
        '-CAcreateserial',
        '-out', str(cert_dir / 'node.pem'),
        '-days', '365',
        '-addext', san_extension
    ])
    
    # Clean up CSR file
    (cert_dir / 'node.csr').unlink(missing_ok=True)
    
    logger.info("Node certificate generated successfully")

def generate_admin_certificate(cert_dir: Path):
    """Generate admin certificate"""
    logger = logging.getLogger('wazuh_installer')
    
    logger.info("Generating admin certificate...")
    
    # Generate private key
    run_command([
        'openssl', 'genrsa', '-out',
        str(cert_dir / 'admin-key.pem'), '2048'
    ])
    
    # Generate certificate signing request
    run_command([
        'openssl', 'req', '-new',
        '-key', str(cert_dir / 'admin-key.pem'),
        '-out', str(cert_dir / 'admin.csr'),
        '-subj', '/C=US/ST=CA/L=San Francisco/O=Wazuh/OU=IT/CN=admin'
    ])
    
    # Generate certificate
    run_command([
        'openssl', 'x509', '-req',
        '-in', str(cert_dir / 'admin.csr'),
        '-CA', str(cert_dir / 'root-ca.pem'),
        '-CAkey', str(cert_dir / 'root-ca-key.pem'),
        '-CAcreateserial',
        '-out', str(cert_dir / 'admin.pem'),
        '-days', '365'
    ])
    
    # Clean up CSR file
    (cert_dir / 'admin.csr').unlink(missing_ok=True)
    
    logger.info("Admin certificate generated successfully")

def set_certificate_permissions(cert_dir: Path):
    """Set proper permissions for certificates"""
    logger = logging.getLogger('wazuh_installer')
    
    logger.info("Setting certificate permissions...")
    
    # Set directory permissions
    os.chmod(cert_dir, 0o755)
    
    # Set file permissions
    for cert_file in cert_dir.glob('*.pem'):
        if 'key' in cert_file.name:
            os.chmod(cert_file, 0o600)  # Private keys
        else:
            os.chmod(cert_file, 0o644)  # Certificates
    
    # Change ownership to wazuh-indexer if user exists
    try:
        run_command(['chown', '-R', 'wazuh-indexer:wazuh-indexer', str(cert_dir)])
    except:
        pass  # User might not exist yet

# =============================================================================
# WAZUH COMPONENT INSTALLATION
# =============================================================================

def install_wazuh_indexer(os_id: str):
    """Install Wazuh Indexer"""
    logger = logging.getLogger('wazuh_installer')
    
    logger.info("Installing Wazuh Indexer...")
    
    try:
        if os_id in ['ubuntu', 'debian']:
            run_command(['apt-get', 'install', '-y', WAZUH_PACKAGES['indexer']])
        elif os_id in ['centos', 'rhel', 'amazon']:
            run_command(['yum', 'install', '-y', WAZUH_PACKAGES['indexer']])
        
        logger.info("Wazuh Indexer installed successfully")
    
    except Exception as e:
        raise Exception(f"Failed to install Wazuh Indexer: {e}")

def configure_wazuh_indexer(hostname: str, ip_address: str):
    """Configure Wazuh Indexer"""
    logger = logging.getLogger('wazuh_installer')
    
    logger.info("Configuring Wazuh Indexer...")
    
    config_file = "/etc/wazuh-indexer/opensearch.yml"
    
    config_content = f"""# Wazuh Indexer Configuration
cluster.name: wazuh-cluster
node.name: {hostname}
network.host: {ip_address}
http.port: 9200
discovery.type: single-node

# Security settings
plugins.security.ssl.transport.pemcert_filepath: /etc/wazuh-indexer/certs/node.pem
plugins.security.ssl.transport.pemkey_filepath: /etc/wazuh-indexer/certs/node-key.pem
plugins.security.ssl.transport.pemtrustedcas_filepath: /etc/wazuh-indexer/certs/root-ca.pem
plugins.security.ssl.http.enabled: true
plugins.security.ssl.http.pemcert_filepath: /etc/wazuh-indexer/certs/node.pem
plugins.security.ssl.http.pemkey_filepath: /etc/wazuh-indexer/certs/node-key.pem
plugins.security.ssl.http.pemtrustedcas_filepath: /etc/wazuh-indexer/certs/root-ca.pem

# Security plugin settings
plugins.security.allow_default_init_securityindex: true
plugins.security.authcz.admin_dn:
  - "CN=admin,OU=IT,O=Wazuh,L=San Francisco,ST=CA,C=US"

# Performance settings
bootstrap.memory_lock: true
"""
    
    try:
        with open(config_file, 'w') as f:
            f.write(config_content)
        
        logger.info("Wazuh Indexer configuration completed")
    
    except Exception as e:
        raise Exception(f"Failed to configure Wazuh Indexer: {e}")

def install_wazuh_manager(os_id: str):
    """Install Wazuh Manager"""
    logger = logging.getLogger('wazuh_installer')
    
    logger.info("Installing Wazuh Manager...")
    
    try:
        if os_id in ['ubuntu', 'debian']:
            run_command(['apt-get', 'install', '-y', WAZUH_PACKAGES['manager']])
        elif os_id in ['centos', 'rhel', 'amazon']:
            run_command(['yum', 'install', '-y', WAZUH_PACKAGES['manager']])
        
        logger.info("Wazuh Manager installed successfully")
    
    except Exception as e:
        raise Exception(f"Failed to install Wazuh Manager: {e}")

def configure_wazuh_manager(hostname: str, ip_address: str):
    """Configure Wazuh Manager"""
    logger = logging.getLogger('wazuh_installer')
    
    logger.info("Configuring Wazuh Manager...")
    
    # Basic configuration is usually sufficient
    # Advanced configuration can be done post-installation
    
    logger.info("Wazuh Manager configuration completed")

def install_wazuh_dashboard(os_id: str):
    """Install Wazuh Dashboard"""
    logger = logging.getLogger('wazuh_installer')
    
    logger.info("Installing Wazuh Dashboard...")
    
    try:
        if os_id in ['ubuntu', 'debian']:
            run_command(['apt-get', 'install', '-y', WAZUH_PACKAGES['dashboard']])
        elif os_id in ['centos', 'rhel', 'amazon']:
            run_command(['yum', 'install', '-y', WAZUH_PACKAGES['dashboard']])
        
        logger.info("Wazuh Dashboard installed successfully")
    
    except Exception as e:
        raise Exception(f"Failed to install Wazuh Dashboard: {e}")

def configure_wazuh_dashboard(hostname: str, ip_address: str):
    """Configure Wazuh Dashboard"""
    logger = logging.getLogger('wazuh_installer')
    
    logger.info("Configuring Wazuh Dashboard...")
    
    config_file = "/etc/wazuh-dashboard/opensearch_dashboards.yml"
    
    config_content = f"""# Wazuh Dashboard Configuration
server.host: {ip_address}
server.port: 443
opensearch.hosts: ["https://{ip_address}:9200"]

# SSL Configuration
server.ssl.enabled: true
server.ssl.certificate: /etc/wazuh-indexer/certs/node.pem
server.ssl.key: /etc/wazuh-indexer/certs/node-key.pem

opensearch.ssl.certificateAuthorities: ["/etc/wazuh-indexer/certs/root-ca.pem"]
opensearch.ssl.verificationMode: certificate

# Security settings
opensearch.username: admin
opensearch.password: admin
"""
    
    try:
        with open(config_file, 'w') as f:
            f.write(config_content)
        
        logger.info("Wazuh Dashboard configuration completed")
    
    except Exception as e:
        raise Exception(f"Failed to configure Wazuh Dashboard: {e}")

# =============================================================================
# SERVICE MANAGEMENT
# =============================================================================

def start_services():
    """Start and enable Wazuh services"""
    logger = logging.getLogger('wazuh_installer')
    
    logger.info("Starting Wazuh services...")
    
    services = ['wazuh-indexer', 'wazuh-manager', 'wazuh-dashboard']
    
    for service in services:
        try:
            logger.info(f"Starting {service}...")
            run_command(['systemctl', 'enable', service])
            run_command(['systemctl', 'start', service])
            
            # Wait a moment for service to start
            time.sleep(2)
            
            # Check service status
            result = run_command(['systemctl', 'is-active', service], check=False)
            if result.stdout.strip() == 'active':
                logger.info(f"✓ {service} started successfully")
            else:
                logger.warning(f"⚠ {service} may not be running properly")
        
        except Exception as e:
            logger.error(f"Failed to start {service}: {e}")
            raise

def validate_installation():
    """Validate Wazuh installation"""
    logger = logging.getLogger('wazuh_installer')
    
    logger.info("Validating installation...")
    
    # Check services
    services = ['wazuh-indexer', 'wazuh-manager', 'wazuh-dashboard']
    
    for service in services:
        try:
            result = run_command(['systemctl', 'is-active', service], check=False)
            if result.stdout.strip() == 'active':
                logger.info(f"✓ {service} is running")
            else:
                logger.warning(f"⚠ {service} is not running")
        except Exception as e:
            logger.error(f"Failed to check {service}: {e}")
    
    # Check ports
    logger.info("Checking network ports...")
    
    for component, port in DEFAULT_PORTS.items():
        try:
            result = run_command(['netstat', '-tlpn'], check=False)
            if f":{port}" in result.stdout:
                logger.info(f"✓ {component} port {port} is listening")
            else:
                logger.warning(f"⚠ {component} port {port} is not listening")
        except Exception as e:
            logger.debug(f"Could not check port {port}: {e}")
    
    logger.info("Installation validation completed")

# =============================================================================
# CLEANUP FUNCTIONS
# =============================================================================

def cleanup_failed_installation():
    """Clean up after failed installation"""
    logger = logging.getLogger('wazuh_installer')
    
    logger.info("Cleaning up failed installation...")
    
    # Stop services
    services = ['wazuh-dashboard', 'wazuh-manager', 'wazuh-indexer']
    for service in services:
        try:
            run_command(['systemctl', 'stop', service], check=False)
            run_command(['systemctl', 'disable', service], check=False)
        except:
            pass
    
    # Remove packages
    try:
        run_command(['apt-get', 'remove', '-y'] + list(WAZUH_PACKAGES.values()), check=False)
    except:
        pass
    
    # Remove repository files
    repo_files = [
        '/etc/apt/sources.list.d/wazuh.list',
        '/usr/share/keyrings/wazuh.gpg',
        '/etc/yum.repos.d/wazuh.repo'
    ]
    
    for repo_file in repo_files:
        try:
            Path(repo_file).unlink(missing_ok=True)
        except:
            pass
    
    logger.info("Cleanup completed")

# =============================================================================
# MAIN INSTALLATION FUNCTION
# =============================================================================

def install_wazuh_server(install_indexer: bool = True, install_manager: bool = True, 
                        install_dashboard: bool = True, verbose: bool = False):
    """Main installation function"""
    
    # Setup logging
    log_file = f"/tmp/wazuh_install_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    logger = setup_logging(verbose, log_file)
    
    logger.info(f"Detailed logs will be saved to: {log_file}")
    
    start_time = time.time()
    
    try:
        # Initial setup
        logger.info(f"Starting Wazuh Server Installation Script v{VERSION}")
        logger.info(f"Author: {AUTHOR}")
        
        # Step 1: System validation
        show_progress(1, 10, "Validating system")
        check_root()
        system_info = get_system_info()
        
        if not check_os_support(system_info['os_id'], system_info['os_version']):
            raise Exception(f"Unsupported OS: {system_info['os_version']}")
        
        # Step 2: Dependencies
        show_progress(2, 10, "Checking dependencies")
        missing_deps = check_dependencies()
        if missing_deps:
            install_dependencies(missing_deps, system_info['os_id'])
        
        # Recheck dependencies
        missing_deps = check_dependencies()
        if missing_deps:
            raise Exception(f"Failed to install dependencies: {missing_deps}")
        
        # Step 3: Network configuration
        show_progress(3, 10, "Getting network configuration")
        hostname, ip_address = get_network_info()
        logger.info(f"Using hostname: {hostname}")
        logger.info(f"Using IP address: {ip_address}")
        
        # Step 4: Repository setup
        show_progress(4, 10, "Setting up Wazuh repository")
        setup_wazuh_repository(system_info['os_id'], system_info['os_version'])
        
        # Step 5: Install Wazuh Indexer
        if install_indexer:
            show_progress(5, 10, "Installing Wazuh Indexer")
            install_wazuh_indexer(system_info['os_id'])
            configure_wazuh_indexer(hostname, ip_address)
        
        # Step 6: SSL Certificates
        show_progress(6, 10, "Setting up SSL certificates")
        setup_ssl_certificates(hostname, ip_address)
        
        # Step 7: Install Wazuh Manager
        if install_manager:
            show_progress(7, 10, "Installing Wazuh Manager")
            install_wazuh_manager(system_info['os_id'])
            configure_wazuh_manager(hostname, ip_address)
        
        # Step 8: Install Wazuh Dashboard
        if install_dashboard:
            show_progress(8, 10, "Installing Wazuh Dashboard")
            install_wazuh_dashboard(system_info['os_id'])
            configure_wazuh_dashboard(hostname, ip_address)
        
        # Step 9: Start services
        show_progress(9, 10, "Starting services")
        start_services()
        
        # Step 10: Validation
        show_progress(10, 10, "Final validation")
        validate_installation()
        
        # Success
        elapsed_time = time.time() - start_time
        logger.info(f"🎉 Wazuh installation completed successfully in {elapsed_time:.2f} seconds!")
        logger.info(f"📊 Dashboard URL: https://{ip_address}")
        logger.info(f"📝 Default credentials: admin/admin")
        logger.info(f"📁 Log file: {log_file}")
        
        return True
    
    except Exception as e:
        elapsed_time = time.time() - start_time
        logger.error(f"Installation failed after {elapsed_time:.2f} seconds: {e}")
        
        # Cleanup
        logger.info("Performing cleanup...")
        cleanup_failed_installation()
        
        return False

# =============================================================================
# COMMAND LINE INTERFACE
# =============================================================================

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Wazuh Server Installation Script",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  python3 {sys.argv[0]} --install-all
  python3 {sys.argv[0]} --install-manager --install-indexer
  python3 {sys.argv[0]} --install-dashboard --verbose

Author: {AUTHOR}
Version: {VERSION}
        """
    )
    
    # Installation options
    parser.add_argument('--install-all', action='store_true',
                       help='Install all Wazuh components')
    parser.add_argument('--install-indexer', action='store_true',
                       help='Install Wazuh Indexer')
    parser.add_argument('--install-manager', action='store_true',
                       help='Install Wazuh Manager')
    parser.add_argument('--install-dashboard', action='store_true',
                       help='Install Wazuh Dashboard')
    
    # Configuration options
    parser.add_argument('--verbose', action='store_true',
                       help='Enable verbose logging')
    parser.add_argument('--log-file', type=str,
                       help='Custom log file path')
    
    args = parser.parse_args()
    
    # Determine what to install
    if args.install_all:
        install_indexer = install_manager = install_dashboard = True
    else:
        install_indexer = args.install_indexer
        install_manager = args.install_manager
        install_dashboard = args.install_dashboard
    
    # Check if at least one component is selected
    if not (install_indexer or install_manager or install_dashboard):
        print("ERROR: No installation option specified. Use --help for usage information.")
        return 1
    
    # Run installation
    try:
        success = install_wazuh_server(
            install_indexer=install_indexer,
            install_manager=install_manager,
            install_dashboard=install_dashboard,
            verbose=args.verbose
        )
        
        if success:
            print("\n✅ Installation completed successfully!")
            return 0
        else:
            print("\n❌ Installation failed!")
            return 1
    
    except KeyboardInterrupt:
        print("\n\n⚠️  Installation interrupted by user")
        return 1
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        return 1

if __name__ == "__main__":
    exit(main())