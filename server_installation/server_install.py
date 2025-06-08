"""
Wazuh Server Installation Script - Python Implementation
Author: Rodrigo Marins Piaba (Fanaticos4tech)
E-Mail: rodrigomarinsp@gmail.com / fanaticos4tech@gmail.com
GitHub: rodrigomarinsp
Instagram: @fanaticos4tech
License: GPL-3.0

FINAL CORRECTED VERSION - Ubuntu 24.04 Compatible
- Fixed function parameter errors
- Proper subprocess handling
- SSL certificate generation fixed
- Complete installation flow
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
import yaml
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from shutil import which

# =============================================================================
# CONSTANTS AND CONFIGURATION
# =============================================================================

VERSION = "1.0.1"
AUTHOR = "Rodrigo Marins Piaba (Fanaticos4tech)"
EMAIL = "rodrigomarinsp@gmail.com"
GITHUB = "rodrigomarinsp"
LICENSE = "GPL-3.0"

# Supported operating systems
SUPPORTED_OS = {
    'ubuntu': ['18.04', '20.04', '22.04', '24.04'],
    'debian': ['10', '11', '12'],
    'centos': ['7', '8'],
    'rhel': ['7', '8', '9'],
    'amazon': ['2', '2023']
}

# Required dependencies
REQUIRED_DEPENDENCIES = [
    'curl', 'wget', 'gpg', 'openssl', 'systemctl', 'unzip'
]

# Wazuh configuration
WAZUH_VERSIONS = {
    'manager': '4.9.2',
    'indexer': '4.9.2', 
    'dashboard': '4.9.2'
}

WAZUH_PORTS = {
    'manager': [1514, 1515, 55000],
    'indexer': [9200, 9300],
    'dashboard': [443, 5601]
}

# Installation paths
WAZUH_PATHS = {
    'base': '/var/ossec',
    'indexer': '/etc/wazuh-indexer',
    'dashboard': '/etc/wazuh-dashboard',
    'certs': '/etc/wazuh-indexer/certs',
    'logs': '/var/log/wazuh',
    'tmp': '/tmp/wazuh-install'
}

# =============================================================================
# LOGGING CONFIGURATION
# =============================================================================

def setup_logging(verbose: bool = False, log_file: Optional[str] = None) -> logging.Logger:
    """Setup comprehensive logging configuration"""
    
    # Create log directory if needed
    if log_file:
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
    
    # Configure logging format
    log_format = '%(asctime)s - %(levelname)s - %(message)s'
    date_format = '%Y-%m-%d %H:%M:%S'
    
    # Set logging level
    level = logging.DEBUG if verbose else logging.INFO
    
    # Configure root logger
    logging.basicConfig(
        level=level,
        format=log_format,
        datefmt=date_format,
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(log_file) if log_file else logging.NullHandler()
        ]
    )
    
    return logging.getLogger(__name__)

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def run_command(command: List[str], check: bool = True, capture_output: bool = True, 
                timeout: int = 300, shell: bool = False, input_data: Optional[str] = None) -> subprocess.CompletedProcess:
    """Execute shell command with proper error handling"""
    
    logger = logging.getLogger(__name__)
    
    try:
        # Log command execution
        cmd_str = ' '.join(command) if isinstance(command, list) else str(command)
        logger.debug(f"Executing command: {cmd_str}")
        
        # Prepare subprocess arguments
        kwargs = {
            'capture_output': capture_output,
            'text': True,
            'timeout': timeout,
            'shell': shell,
            'check': False  # We'll handle check manually for better error messages
        }
        
        # Add input if provided
        if input_data:
            kwargs['input'] = input_data
        
        # Execute command
        result = subprocess.run(command, **kwargs)
        
        # Check result if required
        if check and result.returncode != 0:
            logger.error(f"Command failed: {cmd_str}")
            logger.error(f"Return code: {result.returncode}")
            if result.stdout:
                logger.error(f"Stdout: {result.stdout}")
            if result.stderr:
                logger.error(f"Stderr: {result.stderr}")
            raise subprocess.CalledProcessError(result.returncode, command, result.stdout, result.stderr)
        
        return result
        
    except subprocess.TimeoutExpired as e:
        logger.error(f"Command timed out after {timeout} seconds: {cmd_str}")
        raise
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed: {cmd_str}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error executing command: {e}")
        raise

def show_progress(step: int, total: int, description: str) -> None:
    """Display progress bar with step information"""
    logger = logging.getLogger(__name__)
    
    percentage = (step / total) * 100
    filled = int(percentage / 5)  # 20 blocks total
    bar = '█' * filled + '░' * (20 - filled)
    
    logger.info(f"[{step}/{total}] ({percentage:.1f}%) {bar} {description}")

def validate_file_exists(file_path: str, description: str = "File") -> bool:
    """Validate that a file exists"""
    logger = logging.getLogger(__name__)
    
    if os.path.exists(file_path):
        logger.debug(f"{description} exists: {file_path}")
        return True
    else:
        logger.error(f"{description} not found: {file_path}")
        return False

def create_directory(directory: str, mode: int = 0o755) -> bool:
    """Create directory with proper permissions"""
    logger = logging.getLogger(__name__)
    
    try:
        os.makedirs(directory, mode=mode, exist_ok=True)
        logger.debug(f"Directory created: {directory}")
        return True
    except Exception as e:
        logger.error(f"Failed to create directory {directory}: {e}")
        return False

def backup_file(file_path: str) -> Optional[str]:
    """Create backup of existing file"""
    logger = logging.getLogger(__name__)
    
    if not os.path.exists(file_path):
        return None
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = f"{file_path}.backup_{timestamp}"
    
    try:
        shutil.copy2(file_path, backup_path)
        logger.info(f"Created backup: {backup_path}")
        return backup_path
    except Exception as e:
        logger.error(f"Failed to create backup of {file_path}: {e}")
        return None

# =============================================================================
# SYSTEM DETECTION AND VALIDATION
# =============================================================================

class SystemInfo:
    """System information and validation"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.gather_system_info()
    
    def gather_system_info(self) -> None:
        """Gather comprehensive system information"""
        self.logger.info("Gathering system information...")
        
        # Basic system info
        self.platform = platform.system().lower()
        self.architecture = platform.machine()
        self.python_version = platform.python_version()
        
        # OS-specific information
        try:
            # Try to get OS release information
            with open('/etc/os-release', 'r') as f:
                os_release = {}
                for line in f:
                    if '=' in line:
                        key, value = line.strip().split('=', 1)
                        os_release[key] = value.strip('"')
                
                self.os_id = os_release.get('ID', '').lower()
                self.os_version = os_release.get('VERSION_ID', '')
                self.os_name = os_release.get('PRETTY_NAME', '')
                self.os_codename = os_release.get('VERSION_CODENAME', '')
                
        except FileNotFoundError:
            self.logger.warning("Could not read /etc/os-release")
            self.os_id = ''
            self.os_version = ''
            self.os_name = ''
            self.os_codename = ''
        
        # Network information
        self.hostname = self.get_hostname()
        self.ip_address = self.get_ip_address()
        
        # Log system information
        self.logger.info(f"System: {self.os_name}")
        self.logger.info(f"OS ID: {self.os_id}")
        self.logger.info(f"OS Version: {self.os_version}")
        self.logger.info(f"Architecture: {self.architecture}")
    
    def get_hostname(self) -> str:
        """Get system hostname"""
        try:
            result = run_command(['hostname'], capture_output=True)
            return result.stdout.strip()
        except Exception:
            return 'localhost'
    
    def get_ip_address(self) -> str:
        """Get primary IP address"""
        try:
            # Try hostname -I first
            result = run_command(['hostname', '-I'], capture_output=True)
            ip = result.stdout.strip().split()[0]
            self.logger.info(f"IP address (hostname -I): {ip}")
            return ip
        except Exception:
            try:
                # Fallback to ip route
                result = run_command(['ip', 'route', 'get', '1'], capture_output=True)
                for line in result.stdout.split('\n'):
                    if 'src' in line:
                        return line.split('src')[1].strip().split()[0]
            except Exception:
                pass
        
        return '127.0.0.1'
    
    def is_supported_os(self) -> bool:
        """Check if current OS is supported"""
        self.logger.info(f"Checking OS support for {self.os_id} {self.os_version}")
        
        if self.os_id in SUPPORTED_OS:
            if self.os_version in SUPPORTED_OS[self.os_id]:
                self.logger.info(f"Supported OS: {self.os_id} {self.os_version}")
                return True
        
        self.logger.error(f"Unsupported OS: {self.os_version}")
        return False
    
    def check_dependencies(self) -> bool:
        """Check for required dependencies"""
        show_progress(2, 10, "Checking dependencies")
        self.logger.info("Checking required dependencies...")
        
        missing_deps = []
        available_tools = []
        
        for dep in REQUIRED_DEPENDENCIES:
            if which(dep):
                available_tools.append(dep)
            else:
                missing_deps.append(dep)
        
        self.logger.info(f"Available tools: {available_tools}")
        
        if missing_deps:
            self.logger.warning(f"Missing dependencies: {missing_deps}")
            return False
        
        self.logger.info("All required dependencies are available")
        return True

# =============================================================================
# REPOSITORY MANAGEMENT
# =============================================================================

class RepositoryManager:
    """Manage Wazuh repository setup"""
    
    def __init__(self, system_info: SystemInfo):
        self.logger = logging.getLogger(__name__)
        self.system_info = system_info
    
    def get_ubuntu_codename_for_wazuh(self, version: str) -> str:
        """Get compatible Ubuntu codename for Wazuh repository"""
        # Map Ubuntu versions to repository codenames
        version_map = {
            '18.04': 'bionic',
            '20.04': 'focal', 
            '22.04': 'jammy',
            '24.04': 'jammy'  # Use jammy for 24.04 compatibility
        }
        
        codename = version_map.get(version, 'jammy')
        self.logger.info(f"Using repository codename: {codename}")
        return codename
    
    def setup_wazuh_repository(self) -> bool:
        """Setup Wazuh repository for the current OS"""
        show_progress(4, 10, "Setting up Wazuh repository")
        self.logger.info("Setting up Wazuh repository...")
        
        try:
            if self.system_info.os_id == 'ubuntu':
                return self.setup_ubuntu_repository()
            elif self.system_info.os_id == 'debian':
                return self.setup_debian_repository()
            elif self.system_info.os_id in ['centos', 'rhel']:
                return self.setup_rhel_repository()
            else:
                self.logger.error(f"Unsupported OS for repository setup: {self.system_info.os_id}")
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to setup Wazuh repository: {e}")
            return False
    
    def setup_ubuntu_repository(self) -> bool:
        """Setup Wazuh repository for Ubuntu"""
        self.logger.info(f"Setting up Wazuh repository for ubuntu {self.system_info.os_version}")
        
        try:
            # Get the appropriate codename
            codename = self.get_ubuntu_codename_for_wazuh(self.system_info.os_version)
            
            # Download and import GPG key
            self.logger.info("Downloading Wazuh GPG key...")
            
            # Create keyring directory
            keyring_dir = "/usr/share/keyrings"
            create_directory(keyring_dir)
            
            # Download GPG key
            gpg_key_url = "https://packages.wazuh.com/key/GPG-KEY-WAZUH"
            gpg_key_path = "/usr/share/keyrings/wazuh.gpg"
            
            # Use curl to download and gpg to import
            curl_result = run_command(['curl', '-fsSL', gpg_key_url], capture_output=True)
            
            # Import the key using gpg --dearmor
            gpg_result = run_command(['gpg', '--dearmor'], input_data=curl_result.stdout, capture_output=True)
            
            # Write the key to the keyring file
            with open(gpg_key_path, 'wb') as f:
                f.write(gpg_result.stdout.encode('latin1'))
            
            self.logger.info("GPG key imported successfully")
            
            # Add repository
            self.logger.info("Adding Wazuh repository to sources...")
            repo_line = f"deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ {codename} main"
            
            sources_file = "/etc/apt/sources.list.d/wazuh.list"
            with open(sources_file, 'w') as f:
                f.write(repo_line + '\n')
            
            self.logger.info(f"Repository added for {codename}")
            
            # Update package cache
            self.logger.info("Updating package cache...")
            run_command(['apt-get', 'update'], timeout=120)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to setup Ubuntu repository: {e}")
            return False
    
    def setup_debian_repository(self) -> bool:
        """Setup Wazuh repository for Debian"""
        # Similar to Ubuntu setup
        return self.setup_ubuntu_repository()
    
    def setup_rhel_repository(self) -> bool:
        """Setup Wazuh repository for RHEL/CentOS"""
        self.logger.info("Setting up Wazuh repository for RHEL/CentOS")
        
        try:
            # Import GPG key
            run_command(['rpm', '--import', 'https://packages.wazuh.com/key/GPG-KEY-WAZUH'])
            
            # Create repository file
            repo_content = """[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
"""
            
            with open('/etc/yum.repos.d/wazuh.repo', 'w') as f:
                f.write(repo_content)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to setup RHEL repository: {e}")
            return False

# =============================================================================
# SSL CERTIFICATE MANAGEMENT
# =============================================================================

class CertificateManager:
    """Manage SSL certificates for Wazuh components"""
    
    def __init__(self, system_info: SystemInfo):
        self.logger = logging.getLogger(__name__)
        self.system_info = system_info
        self.certs_dir = WAZUH_PATHS['certs']
    
    def setup_certificates(self) -> bool:
        """Setup SSL certificates for Wazuh components"""
        self.logger.info("Setting up SSL certificates...")
        
        try:
            # Create certificates directory
            if not create_directory(self.certs_dir, 0o755):
                return False
            
            # Generate root CA
            if not self.generate_root_ca():
                return False
            
            # Generate node certificates
            if not self.generate_node_certificates():
                return False
            
            # Generate admin certificates
            if not self.generate_admin_certificates():
                return False
            
            # Set proper permissions
            self.set_certificate_permissions()
            
            self.logger.info("SSL certificates setup completed successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to setup certificates: {e}")
            return False
    
    def generate_root_ca(self) -> bool:
        """Generate root CA certificate"""
        self.logger.info("Generating root CA certificate...")
        
        try:
            ca_key_path = os.path.join(self.certs_dir, "root-ca-key.pem")
            ca_cert_path = os.path.join(self.certs_dir, "root-ca.pem")
            
            # Generate CA private key
            run_command([
                'openssl', 'genrsa', '-out', ca_key_path, '2048'
            ])
            
            # Generate CA certificate
            run_command([
                'openssl', 'req', '-new', '-x509',
                '-key', ca_key_path,
                '-out', ca_cert_path,
                '-days', '3650',
                '-subj', '/C=US/ST=CA/L=San Francisco/O=Wazuh/OU=IT/CN=Wazuh Root CA'
            ])
            
            self.logger.info("Root CA certificate generated successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to generate root CA: {e}")
            return False
    
    def generate_node_certificates(self) -> bool:
        """Generate node certificates for Wazuh indexer"""
        self.logger.info("Generating node certificates...")
        
        try:
            node_key_path = os.path.join(self.certs_dir, "node-key.pem")
            node_csr_path = os.path.join(self.certs_dir, "node.csr")
            node_cert_path = os.path.join(self.certs_dir, "node.pem")
            ca_cert_path = os.path.join(self.certs_dir, "root-ca.pem")
            ca_key_path = os.path.join(self.certs_dir, "root-ca-key.pem")
            
            # Generate node private key
            run_command([
                'openssl', 'genrsa', '-out', node_key_path, '2048'
            ])
            
            # Generate certificate signing request
            run_command([
                'openssl', 'req', '-new',
                '-key', node_key_path,
                '-out', node_csr_path,
                '-subj', f'/C=US/ST=CA/L=San Francisco/O=Wazuh/OU=IT/CN={self.system_info.hostname}'
            ])
            
            # Generate node certificate with SAN
            san_extension = f'subjectAltName=DNS:localhost,DNS:{self.system_info.hostname},DNS:wazuh-indexer,IP:127.0.0.1,IP:{self.system_info.ip_address}'
            
            run_command([
                'openssl', 'x509', '-req',
                '-in', node_csr_path,
                '-CA', ca_cert_path,
                '-CAkey', ca_key_path,
                '-CAcreateserial',
                '-out', node_cert_path,
                '-days', '365',
                '-addext', san_extension
            ])
            
            # Clean up CSR file
            os.remove(node_csr_path)
            
            self.logger.info("Node certificates generated successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to generate node certificates: {e}")
            return False
    
    def generate_admin_certificates(self) -> bool:
        """Generate admin certificates"""
        self.logger.info("Generating admin certificates...")
        
        try:
            admin_key_path = os.path.join(self.certs_dir, "admin-key.pem")
            admin_csr_path = os.path.join(self.certs_dir, "admin.csr")
            admin_cert_path = os.path.join(self.certs_dir, "admin.pem")
            ca_cert_path = os.path.join(self.certs_dir, "root-ca.pem")
            ca_key_path = os.path.join(self.certs_dir, "root-ca-key.pem")
            
            # Generate admin private key
            run_command([
                'openssl', 'genrsa', '-out', admin_key_path, '2048'
            ])
            
            # Generate certificate signing request
            run_command([
                'openssl', 'req', '-new',
                '-key', admin_key_path,
                '-out', admin_csr_path,
                '-subj', '/C=US/ST=CA/L=San Francisco/O=Wazuh/OU=IT/CN=admin'
            ])
            
            # Generate admin certificate
            run_command([
                'openssl', 'x509', '-req',
                '-in', admin_csr_path,
                '-CA', ca_cert_path,
                '-CAkey', ca_key_path,
                '-CAcreateserial',
                '-out', admin_cert_path,
                '-days', '365'
            ])
            
            # Clean up CSR file
            os.remove(admin_csr_path)
            
            self.logger.info("Admin certificates generated successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to generate admin certificates: {e}")
            return False
    
    def set_certificate_permissions(self) -> None:
        """Set proper permissions for certificates"""
        self.logger.info("Setting certificate permissions...")
        
        try:
            # Set directory permissions
            os.chmod(self.certs_dir, 0o755)
            
            # Set file permissions
            for cert_file in os.listdir(self.certs_dir):
                cert_path = os.path.join(self.certs_dir, cert_file)
                if cert_file.endswith('-key.pem'):
                    # Private keys should be more restrictive
                    os.chmod(cert_path, 0o600)
                else:
                    # Public certificates
                    os.chmod(cert_path, 0o644)
            
            # Set ownership to wazuh-indexer user if exists
            try:
                run_command(['chown', '-R', 'wazuh-indexer:wazuh-indexer', self.certs_dir], check=False)
            except:
                pass  # User might not exist yet
                
        except Exception as e:
            self.logger.warning(f"Could not set all certificate permissions: {e}")

# =============================================================================
# WAZUH COMPONENT INSTALLERS
# =============================================================================

class WazuhIndexerInstaller:
    """Install and configure Wazuh Indexer"""
    
    def __init__(self, system_info: SystemInfo, cert_manager: CertificateManager):
        self.logger = logging.getLogger(__name__)
        self.system_info = system_info
        self.cert_manager = cert_manager
    
    def install(self) -> bool:
        """Install Wazuh Indexer"""
        show_progress(5, 10, "Installing Wazuh Indexer")
        self.logger.info("Installing Wazuh Indexer...")
        
        try:
            # Install package
            if not self.install_package():
                return False
            
            # Setup SSL certificates
            show_progress(6, 10, "Setting up SSL certificates")
            if not self.cert_manager.setup_certificates():
                return False
            
            # Configure indexer
            if not self.configure_indexer():
                return False
            
            # Start and enable service
            if not self.start_service():
                return False
            
            self.logger.info("Wazuh Indexer installation completed successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to install Wazuh Indexer: {e}")
            return False
    
    def install_package(self) -> bool:
        """Install Wazuh Indexer package"""
        self.logger.info("Installing Wazuh Indexer package...")
        
        try:
            if self.system_info.os_id in ['ubuntu', 'debian']:
                run_command(['apt-get', 'install', '-y', 'wazuh-indexer'], timeout=600)
            elif self.system_info.os_id in ['centos', 'rhel']:
                run_command(['yum', 'install', '-y', 'wazuh-indexer'], timeout=600)
            
            self.logger.info("Wazuh Indexer package installed successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to install Wazuh Indexer package: {e}")
            return False
    
    def configure_indexer(self) -> bool:
        """Configure Wazuh Indexer"""
        self.logger.info("Configuring Wazuh Indexer...")
        
        try:
            config_file = "/etc/wazuh-indexer/opensearch.yml"
            
            # Backup original config
            backup_file(config_file)
            
            # Create new configuration
            config_content = f"""network.host: 0.0.0.0
node.name: node-1
cluster.initial_master_nodes:
- node-1
cluster.name: wazuh-cluster
discovery.seed_hosts: []
node.max_local_storage_nodes: 3
path.data: /var/lib/wazuh-indexer
path.logs: /var/log/wazuh-indexer

plugins.security.ssl.transport.pemcert_filepath: {self.cert_manager.certs_dir}/node.pem
plugins.security.ssl.transport.pemkey_filepath: {self.cert_manager.certs_dir}/node-key.pem
plugins.security.ssl.transport.pemtrustedcas_filepath: {self.cert_manager.certs_dir}/root-ca.pem
plugins.security.ssl.transport.enforce_hostname_verification: false
plugins.security.ssl.http.enabled: true
plugins.security.ssl.http.pemcert_filepath: {self.cert_manager.certs_dir}/node.pem
plugins.security.ssl.http.pemkey_filepath: {self.cert_manager.certs_dir}/node-key.pem
plugins.security.ssl.http.pemtrustedcas_filepath: {self.cert_manager.certs_dir}/root-ca.pem
plugins.security.allow_unsafe_democertificates: true
plugins.security.allow_default_init_securityindex: true
plugins.security.authcz.admin_dn:
- CN=admin,OU=IT,O=Wazuh,L=San Francisco,ST=CA,C=US
plugins.security.audit.type: internal_opensearch
plugins.security.enable_snapshot_restore_privilege: true
plugins.security.check_snapshot_restore_write_privileges: true
plugins.security.restapi.roles_enabled: ["all_access", "security_rest_api_access"]
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
- ".opensearch-observability"
- ".opendistro-asynchronous-search-response*"
- ".replication-metadata-store"
compatibility.override_main_response_version: true
"""
            
            with open(config_file, 'w') as f:
                f.write(config_content)
            
            self.logger.info("Wazuh Indexer configuration updated")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to configure Wazuh Indexer: {e}")
            return False
    
    def start_service(self) -> bool:
        """Start Wazuh Indexer service"""
        self.logger.info("Starting Wazuh Indexer service...")
        
        try:
            # Enable and start service
            run_command(['systemctl', 'daemon-reload'])
            run_command(['systemctl', 'enable', 'wazuh-indexer'])
            run_command(['systemctl', 'start', 'wazuh-indexer'])
            
            # Wait for service to start
            time.sleep(10)
            
            # Check service status
            result = run_command(['systemctl', 'is-active', 'wazuh-indexer'], check=False)
            if 'active' in result.stdout:
                self.logger.info("Wazuh Indexer service started successfully")
                return True
            else:
                self.logger.error("Wazuh Indexer service failed to start")
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to start Wazuh Indexer service: {e}")
            return False

class WazuhManagerInstaller:
    """Install and configure Wazuh Manager"""
    
    def __init__(self, system_info: SystemInfo):
        self.logger = logging.getLogger(__name__)
        self.system_info = system_info
    
    def install(self) -> bool:
        """Install Wazuh Manager"""
        show_progress(7, 10, "Installing Wazuh Manager")
        self.logger.info("Installing Wazuh Manager...")
        
        try:
            # Install package
            if not self.install_package():
                return False
            
            # Configure manager
            if not self.configure_manager():
                return False
            
            # Start and enable service
            if not self.start_service():
                return False
            
            self.logger.info("Wazuh Manager installation completed successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to install Wazuh Manager: {e}")
            return False
    
    def install_package(self) -> bool:
        """Install Wazuh Manager package"""
        self.logger.info("Installing Wazuh Manager package...")
        
        try:
            if self.system_info.os_id in ['ubuntu', 'debian']:
                run_command(['apt-get', 'install', '-y', 'wazuh-manager'], timeout=600)
            elif self.system_info.os_id in ['centos', 'rhel']:
                run_command(['yum', 'install', '-y', 'wazuh-manager'], timeout=600)
            
            self.logger.info("Wazuh Manager package installed successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to install Wazuh Manager package: {e}")
            return False
    
    def configure_manager(self) -> bool:
        """Configure Wazuh Manager"""
        self.logger.info("Configuring Wazuh Manager...")
        
        try:
            config_file = "/var/ossec/etc/ossec.conf"
            
            # Backup original config
            backup_file(config_file)
            
            # The default configuration is usually sufficient for initial setup
            # Additional configuration can be added here as needed
            
            self.logger.info("Wazuh Manager configuration updated")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to configure Wazuh Manager: {e}")
            return False
    
    def start_service(self) -> bool:
        """Start Wazuh Manager service"""
        self.logger.info("Starting Wazuh Manager service...")
        
        try:
            # Enable and start service
            run_command(['systemctl', 'daemon-reload'])
            run_command(['systemctl', 'enable', 'wazuh-manager'])
            run_command(['systemctl', 'start', 'wazuh-manager'])
            
            # Wait for service to start
            time.sleep(5)
            
            # Check service status
            result = run_command(['systemctl', 'is-active', 'wazuh-manager'], check=False)
            if 'active' in result.stdout:
                self.logger.info("Wazuh Manager service started successfully")
                return True
            else:
                self.logger.error("Wazuh Manager service failed to start")
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to start Wazuh Manager service: {e}")
            return False

class WazuhDashboardInstaller:
    """Install and configure Wazuh Dashboard"""
    
    def __init__(self, system_info: SystemInfo, cert_manager: CertificateManager):
        self.logger = logging.getLogger(__name__)
        self.system_info = system_info
        self.cert_manager = cert_manager
    
    def install(self) -> bool:
        """Install Wazuh Dashboard"""
        show_progress(8, 10, "Installing Wazuh Dashboard")
        self.logger.info("Installing Wazuh Dashboard...")
        
        try:
            # Install package
            if not self.install_package():
                return False
            
            # Configure dashboard
            if not self.configure_dashboard():
                return False
            
            # Start and enable service
            if not self.start_service():
                return False
            
            self.logger.info("Wazuh Dashboard installation completed successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to install Wazuh Dashboard: {e}")
            return False
    
    def install_package(self) -> bool:
        """Install Wazuh Dashboard package"""
        self.logger.info("Installing Wazuh Dashboard package...")
        
        try:
            if self.system_info.os_id in ['ubuntu', 'debian']:
                run_command(['apt-get', 'install', '-y', 'wazuh-dashboard'], timeout=600)
            elif self.system_info.os_id in ['centos', 'rhel']:
                run_command(['yum', 'install', '-y', 'wazuh-dashboard'], timeout=600)
            
            self.logger.info("Wazuh Dashboard package installed successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to install Wazuh Dashboard package: {e}")
            return False
    
    def configure_dashboard(self) -> bool:
        """Configure Wazuh Dashboard"""
        self.logger.info("Configuring Wazuh Dashboard...")
        
        try:
            config_file = "/etc/wazuh-dashboard/opensearch_dashboards.yml"
            
            # Backup original config
            backup_file(config_file)
            
            # Create new configuration
            config_content = f"""server.host: 0.0.0.0
server.port: 5601
opensearch.hosts: https://{self.system_info.ip_address}:9200
server.ssl.enabled: true
server.ssl.certificate: {self.cert_manager.certs_dir}/node.pem
server.ssl.key: {self.cert_manager.certs_dir}/node-key.pem
opensearch.ssl.certificateAuthorities: [{self.cert_manager.certs_dir}/root-ca.pem]
opensearch.ssl.verificationMode: certificate
opensearch.username: admin
opensearch.password: admin
opensearch.requestHeadersWhitelist: ["authorization", "securitytenant"]
opensearch_security.multitenancy.enabled: true
opensearch_security.multitenancy.tenants.preferred: ["Private", "Global"]
opensearch_security.readonly_mode.roles: ["kibana_read_only"]
server.ssl.verificationMode: certificate
opensearch.ssl.verificationMode: certificate
"""
            
            with open(config_file, 'w') as f:
                f.write(config_content)
            
            self.logger.info("Wazuh Dashboard configuration updated")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to configure Wazuh Dashboard: {e}")
            return False
    
    def start_service(self) -> bool:
        """Start Wazuh Dashboard service"""
        self.logger.info("Starting Wazuh Dashboard service...")
        
        try:
            # Enable and start service
            run_command(['systemctl', 'daemon-reload'])
            run_command(['systemctl', 'enable', 'wazuh-dashboard'])
            run_command(['systemctl', 'start', 'wazuh-dashboard'])
            
            # Wait for service to start
            time.sleep(10)
            
            # Check service status
            result = run_command(['systemctl', 'is-active', 'wazuh-dashboard'], check=False)
            if 'active' in result.stdout:
                self.logger.info("Wazuh Dashboard service started successfully")
                return True
            else:
                self.logger.error("Wazuh Dashboard service failed to start")
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to start Wazuh Dashboard service: {e}")
            return False

# =============================================================================
# MAIN INSTALLER CLASS
# =============================================================================

class WazuhServerInstaller:
    """Main Wazuh Server installer"""
    
    def __init__(self, args):
        self.args = args
        self.start_time = time.time()
        
        # Setup logging
        log_file = f"/tmp/wazuh_install_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        self.logger = setup_logging(verbose=args.verbose, log_file=log_file)
        self.logger.info(f"Detailed logs will be saved to: {log_file}")
        
        # Initialize system info
        self.system_info = SystemInfo()
        
        # Initialize managers
        self.repo_manager = RepositoryManager(self.system_info)
        self.cert_manager = CertificateManager(self.system_info)
        
        # Initialize installers
        self.indexer_installer = WazuhIndexerInstaller(self.system_info, self.cert_manager)
        self.manager_installer = WazuhManagerInstaller(self.system_info)
        self.dashboard_installer = WazuhDashboardInstaller(self.system_info, self.cert_manager)
    
    def run(self) -> bool:
        """Run the complete installation process"""
        try:
            self.logger.info(f"Starting Wazuh Server Installation Script v{VERSION}")
            self.logger.info(f"Author: {AUTHOR}")
            
            # Validate system
            show_progress(1, 10, "Validating system")
            if not self.validate_system():
                raise Exception("System validation failed")
            
            # Check dependencies
            if not self.system_info.check_dependencies():
                raise Exception("Dependency check failed")
            
            # Get network configuration
            show_progress(3, 10, "Getting network configuration")
            self.get_network_info()
            
            # Setup repository
            if not self.repo_manager.setup_wazuh_repository():
                raise Exception("Failed to setup Wazuh repository")
            
            # Install components based on arguments
            if self.args.install_all or self.args.install_indexer:
                if not self.indexer_installer.install():
                    raise Exception("Failed to install Wazuh Indexer")
            
            if self.args.install_all or self.args.install_manager:
                if not self.manager_installer.install():
                    raise Exception("Failed to install Wazuh Manager")
            
            if self.args.install_all or self.args.install_dashboard:
                if not self.dashboard_installer.install():
                    raise Exception("Failed to install Wazuh Dashboard")
            
            # Final validation
            show_progress(9, 10, "Performing final validation")
            if not self.final_validation():
                raise Exception("Final validation failed")
            
            # Installation completed
            show_progress(10, 10, "Installation completed")
            self.installation_summary()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Installation failed: {e}")
            self.cleanup()
            return False
    
    def validate_system(self) -> bool:
        """Validate system requirements"""
        self.logger.info("Validating system requirements...")
        
        # Check if running as root
        if os.geteuid() != 0:
            self.logger.error("This script must be run as root")
            return False
        
        # Check OS support
        if not self.system_info.is_supported_os():
            return False
        
        # Check available disk space
        if not self.check_disk_space():
            return False
        
        return True
    
    def check_disk_space(self) -> bool:
        """Check available disk space"""
        try:
            # Check available space in /var (where Wazuh data is stored)
            stat = os.statvfs('/var')
            available_gb = (stat.f_bavail * stat.f_frsize) / (1024 ** 3)
            
            if available_gb < 10:  # Minimum 10GB required
                self.logger.error(f"Insufficient disk space. Available: {available_gb:.1f}GB, Required: 10GB")
                return False
            
            self.logger.info(f"Disk space check passed. Available: {available_gb:.1f}GB")
            return True
            
        except Exception as e:
            self.logger.warning(f"Could not check disk space: {e}")
            return True  # Continue anyway
    
    def get_network_info(self) -> None:
        """Get and display network information"""
        self.logger.info("Getting network information...")
        self.logger.info(f"Hostname: {self.system_info.hostname}")
        self.logger.info(f"Using hostname: {self.system_info.hostname}")
        self.logger.info(f"Using IP address: {self.system_info.ip_address}")
    
    def final_validation(self) -> bool:
        """Perform final validation of the installation"""
        self.logger.info("Performing final installation validation...")
        
        try:
            validation_passed = True
            
            # Check if services are running
            services_to_check = []
            
            if self.args.install_all or self.args.install_indexer:
                services_to_check.append('wazuh-indexer')
            
            if self.args.install_all or self.args.install_manager:
                services_to_check.append('wazuh-manager')
            
            if self.args.install_all or self.args.install_dashboard:
                services_to_check.append('wazuh-dashboard')
            
            for service in services_to_check:
                result = run_command(['systemctl', 'is-active', service], check=False)
                if 'active' not in result.stdout:
                    self.logger.error(f"Service {service} is not running")
                    validation_passed = False
                else:
                    self.logger.info(f"Service {service} is running")
            
            # Check if ports are listening
            if self.args.install_all or self.args.install_indexer:
                if not self.check_port_listening(9200):
                    self.logger.warning("Wazuh Indexer port 9200 is not listening")
            
            if self.args.install_all or self.args.install_dashboard:
                if not self.check_port_listening(5601):
                    self.logger.warning("Wazuh Dashboard port 5601 is not listening")
            
            return validation_passed
            
        except Exception as e:
            self.logger.error(f"Final validation failed: {e}")
            return False
    
    def check_port_listening(self, port: int) -> bool:
        """Check if a port is listening"""
        try:
            result = run_command(['netstat', '-ln'], check=False, capture_output=True)
            return f':{port}' in result.stdout
        except Exception:
            return False
    
    def installation_summary(self) -> None:
        """Display installation summary"""
        elapsed_time = time.time() - self.start_time
        
        self.logger.info("=" * 60)
        self.logger.info("WAZUH INSTALLATION COMPLETED SUCCESSFULLY!")
        self.logger.info("=" * 60)
        self.logger.info(f"Installation time: {elapsed_time:.2f} seconds")
        self.logger.info(f"System: {self.system_info.os_name}")
        self.logger.info(f"Hostname: {self.system_info.hostname}")
        self.logger.info(f"IP Address: {self.system_info.ip_address}")
        
        if self.args.install_all or self.args.install_indexer:
            self.logger.info(f"Wazuh Indexer: https://{self.system_info.ip_address}:9200")
        
        if self.args.install_all or self.args.install_dashboard:
            self.logger.info(f"Wazuh Dashboard: https://{self.system_info.ip_address}:5601")
            self.logger.info("Default credentials: admin / admin")
        
        self.logger.info("\nNext steps:")
        self.logger.info("1. Access the Wazuh Dashboard using the URL above")
        self.logger.info("2. Change the default admin password")
        self.logger.info("3. Configure agents to connect to this manager")
        self.logger.info("=" * 60)
    
    def cleanup(self) -> None:
        """Cleanup failed installation"""
        self.logger.info("Performing cleanup...")
        
        try:
            self.logger.info("Cleaning up failed installation...")
            
            # Stop services that might be running
            services = ['wazuh-dashboard', 'wazuh-manager', 'wazuh-indexer']
            for service in services:
                try:
                    run_command(['systemctl', 'stop', service], check=False)
                    run_command(['systemctl', 'disable', service], check=False)
                except:
                    pass
            
            # Remove packages if they were installed
            if self.system_info.os_id in ['ubuntu', 'debian']:
                try:
                    run_command(['apt-get', 'remove', '-y', 'wazuh-dashboard', 'wazuh-manager', 'wazuh-indexer'], check=False)
                except:
                    pass
            
            self.logger.info("Cleanup completed")
            
        except Exception as e:
            self.logger.error(f"Cleanup failed: {e}")

# =============================================================================
# MAIN FUNCTION AND CLI
# =============================================================================

def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description=f"Wazuh Server Installation Script v{VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  {sys.argv[0]} --install-all                    # Install all components
  {sys.argv[0]} --install-manager                # Install only Wazuh Manager
  {sys.argv[0]} --install-indexer                # Install only Wazuh Indexer
  {sys.argv[0]} --install-dashboard              # Install only Wazuh Dashboard
  {sys.argv[0]} --install-all --verbose          # Install with verbose logging

Author: {AUTHOR}
License: {LICENSE}
        """
    )
    
    # Installation options
    parser.add_argument('--install-all', action='store_true',
                       help='Install all Wazuh components (Manager, Indexer, Dashboard)')
    parser.add_argument('--install-manager', action='store_true',
                       help='Install Wazuh Manager')
    parser.add_argument('--install-indexer', action='store_true',
                       help='Install Wazuh Indexer')
    parser.add_argument('--install-dashboard', action='store_true',
                       help='Install Wazuh Dashboard')
    
    # Configuration options
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    parser.add_argument('--config-file', type=str,
                       help='Custom configuration file')
    parser.add_argument('--single-node', action='store_true',
                       help='Configure for single node deployment')
    parser.add_argument('--cluster-mode', action='store_true',
                       help='Configure for cluster deployment')
    parser.add_argument('--node-name', type=str, default='node-1',
                       help='Node name for cluster configuration')
    
    # Advanced options
    parser.add_argument('--force', action='store_true',
                       help='Force installation even if components are already installed')
    parser.add_argument('--skip-validation', action='store_true',
                       help='Skip system validation checks')
    
    args = parser.parse_args()
    
    # Validate arguments
    if not any([args.install_all, args.install_manager, args.install_indexer, args.install_dashboard]):
        parser.error("No installation option specified. Use --help for usage information.")
    
    # Create and run installer
    installer = WazuhServerInstaller(args)
    
    try:
        success = installer.run()
        
        if success:
            elapsed_time = time.time() - installer.start_time
            installer.logger.info(f"Installation completed successfully in {elapsed_time:.2f} seconds")
            sys.exit(0)
        else:
            elapsed_time = time.time() - installer.start_time
            installer.logger.error(f"Installation failed after {elapsed_time:.2f} seconds")
            installer.logger.error("Installation failed!")
            sys.exit(1)
            
    except KeyboardInterrupt:
        installer.logger.error("Installation interrupted by user")
        installer.cleanup()
        sys.exit(1)
    except Exception as e:
        installer.logger.error(f"Unexpected error: {e}")
        installer.cleanup()
        sys.exit(1)

if __name__ == "__main__":
    main()