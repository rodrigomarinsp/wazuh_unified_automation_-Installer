"""
Wazuh Server Installation Script - Python Implementation
Author: Rodrigo Marins Piaba (Fanaticos4tech)
E-Mail: rodrigomarinsp@gmail.com / fanaticos4tech@gmail.com
GitHub: rodrigomarinsp
Instagram: @fanaticos4tech
License: GPL-3.0

## Advanced Python installer with enhanced features, logging, and automation capabilities.
## FIXED: SSL Certificate handling for OpenSearch Security Plugin
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
import socket
import secrets
import string
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from shutil import which

# =============================================================================
# CONSTANTS AND CONFIGURATION
# =============================================================================

VERSION = "1.0.1"
AUTHOR = "Rodrigo Marins Piaba (Fixed SSL Certificates)"
EMAIL = "rodrigomarinsp@gmail.com"
GITHUB = "rodrigomarinsp"

# Wazuh configuration
WAZUH_VERSION = "4.7.0"
WAZUH_MAJOR_VERSION = "4.x"
ELASTIC_VERSION = "7.17.13"

# URLs and repositories
WAZUH_REPO_URL = "https://packages.wazuh.com/4.x"
WAZUH_GPG_KEY = "https://packages.wazuh.com/key/GPG-KEY-WAZUH"
ELASTIC_REPO_URL = "https://artifacts.elastic.co/packages/7.x/apt"
ELASTIC_GPG_KEY = "https://artifacts.elastic.co/GPG-KEY-elasticsearch"

# System paths
LOG_DIR = "/var/log/wazuh-installer"
CONFIG_DIR = "/etc/wazuh-installer"
CERT_DIR = "/etc/wazuh-indexer/certs"
BACKUP_DIR = "/opt/wazuh-installer/backups"

# Service names
SERVICES = {
    'indexer': 'wazuh-indexer',
    'manager': 'wazuh-manager',
    'dashboard': 'wazuh-dashboard'
}

# Certificate configuration
CERT_CONFIG = {
    'root_ca': 'root-ca.pem',
    'root_ca_key': 'root-ca-key.pem',
    'admin': 'admin.pem',
    'admin_key': 'admin-key.pem',
    'node': 'node.pem',
    'node_key': 'node-key.pem'
}

# =============================================================================
# LOGGING CONFIGURATION
# =============================================================================

class ColoredFormatter(logging.Formatter):
    """Custom formatter with colors for console output"""
    
    COLORS = {
        'DEBUG': '\033[36m',    # Cyan
        'INFO': '\033[32m',     # Green
        'WARNING': '\033[33m',  # Yellow
        'ERROR': '\033[31m',    # Red
        'CRITICAL': '\033[35m', # Magenta
        'ENDC': '\033[0m'       # End color
    }
    
    def format(self, record):
        log_color = self.COLORS.get(record.levelname, self.COLORS['ENDC'])
        record.levelname = f"{log_color}{record.levelname}{self.COLORS['ENDC']}"
        return super().format(record)

def setup_logging(log_level: str = "INFO", log_file: Optional[str] = None) -> logging.Logger:
    """Setup logging configuration with both file and console handlers"""
    
    # Create log directory if it doesn't exist
    os.makedirs(LOG_DIR, exist_ok=True)
    
    # Default log file
    if not log_file:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = f"{LOG_DIR}/wazuh_install_{timestamp}.log"
    
    # Create logger
    logger = logging.getLogger("WazuhInstaller")
    logger.setLevel(getattr(logging, log_level.upper()))
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # File handler
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(getattr(logging, log_level.upper()))
    console_formatter = ColoredFormatter(
        '%(asctime)s - %(levelname)s - %(message)s'
    )
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    return logger

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def run_command(command: List[str], check: bool = True, capture_output: bool = True, 
                timeout: Optional[int] = None, shell: bool = False) -> subprocess.CompletedProcess:
    """Execute system command with enhanced error handling"""
    
    logger = logging.getLogger("WazuhInstaller")
    cmd_str = ' '.join(command) if isinstance(command, list) else command
    
    logger.debug(f"Executing command: {cmd_str}")
    
    try:
        if shell:
            result = subprocess.run(
                cmd_str,
                shell=True,
                check=check,
                capture_output=capture_output,
                text=True,
                timeout=timeout
            )
        else:
            result = subprocess.run(
                command,
                check=check,
                capture_output=capture_output,
                text=True,
                timeout=timeout
            )
        
        if result.stdout:
            logger.debug(f"Command output: {result.stdout.strip()}")
        if result.stderr:
            logger.debug(f"Command stderr: {result.stderr.strip()}")
            
        return result
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed: {cmd_str}")
        logger.error(f"Return code: {e.returncode}")
        logger.error(f"Stdout: {e.stdout}")
        logger.error(f"Stderr: {e.stderr}")
        raise
    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out: {cmd_str}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error executing command: {e}")
        raise

def check_system_requirements() -> Dict[str, bool]:
    """Check system requirements for Wazuh installation"""
    
    logger = logging.getLogger("WazuhInstaller")
    logger.info("Checking system requirements...")
    
    requirements = {
        'os_supported': False,
        'memory_sufficient': False,
        'disk_space_sufficient': False,
        'root_privileges': False,
        'network_connectivity': False
    }
    
    # Check OS
    system = platform.system().lower()
    if system == 'linux':
        try:
            with open('/etc/os-release', 'r') as f:
                os_info = f.read().lower()
                if any(distro in os_info for distro in ['ubuntu', 'debian', 'centos', 'rhel', 'fedora']):
                    requirements['os_supported'] = True
                    logger.info("✓ Operating system supported")
                else:
                    logger.warning("⚠ Operating system may not be fully supported")
        except Exception:
            logger.warning("⚠ Could not determine OS distribution")
    
    # Check memory (minimum 2GB)
    try:
        with open('/proc/meminfo', 'r') as f:
            meminfo = f.read()
            mem_total = int(re.search(r'MemTotal:\s+(\d+)', meminfo).group(1)) * 1024
            if mem_total >= 2 * 1024 * 1024 * 1024:  # 2GB
                requirements['memory_sufficient'] = True
                logger.info(f"✓ Memory sufficient: {mem_total / (1024**3):.1f}GB")
            else:
                logger.warning(f"⚠ Memory may be insufficient: {mem_total / (1024**3):.1f}GB (recommended: 2GB+)")
    except Exception:
        logger.warning("⚠ Could not check memory requirements")
    
    # Check disk space (minimum 10GB for /)
    try:
        stat = os.statvfs('/')
        free_space = stat.f_bavail * stat.f_frsize
        if free_space >= 10 * 1024 * 1024 * 1024:  # 10GB
            requirements['disk_space_sufficient'] = True
            logger.info(f"✓ Disk space sufficient: {free_space / (1024**3):.1f}GB")
        else:
            logger.warning(f"⚠ Disk space may be insufficient: {free_space / (1024**3):.1f}GB (recommended: 10GB+)")
    except Exception:
        logger.warning("⚠ Could not check disk space")
    
    # Check root privileges
    if os.geteuid() == 0:
        requirements['root_privileges'] = True
        logger.info("✓ Root privileges confirmed")
    else:
        logger.error("✗ Root privileges required")
    
    # Check network connectivity
    try:
        response = urllib.request.urlopen('https://packages.wazuh.com', timeout=10)
        if response.getcode() == 200:
            requirements['network_connectivity'] = True
            logger.info("✓ Network connectivity confirmed")
    except Exception:
        logger.warning("⚠ Network connectivity issues detected")
    
    return requirements

def generate_password(length: int = 16) -> str:
    """Generate a secure random password"""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def backup_file(file_path: str) -> str:
    """Create a backup of a file"""
    logger = logging.getLogger("WazuhInstaller")
    
    if not os.path.exists(file_path):
        return ""
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = f"{BACKUP_DIR}/{os.path.basename(file_path)}.{timestamp}.bak"
    
    os.makedirs(BACKUP_DIR, exist_ok=True)
    shutil.copy2(file_path, backup_path)
    
    logger.info(f"Backup created: {backup_path}")
    return backup_path

# =============================================================================
# SSL CERTIFICATE MANAGEMENT (FIXED)
# =============================================================================

class CertificateManager:
    """Enhanced certificate manager with proper SSL handling"""
    
    def __init__(self, cert_dir: str = CERT_DIR):
        self.cert_dir = cert_dir
        self.logger = logging.getLogger("WazuhInstaller.CertManager")
        self.hostname = socket.gethostname()
        self.ip_address = self._get_local_ip()
    
    def _get_local_ip(self) -> str:
        """Get local IP address"""
        try:
            # Connect to a remote server to determine local IP
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception:
            return "127.0.0.1"
    
    def setup_certificate_directory(self) -> bool:
        """Create and setup certificate directory with proper permissions"""
        try:
            self.logger.info(f"Setting up certificate directory: {self.cert_dir}")
            
            # Create directory if it doesn't exist
            os.makedirs(self.cert_dir, mode=0o755, exist_ok=True)
            
            # Set proper ownership and permissions
            run_command(['chown', 'wazuh-indexer:wazuh-indexer', self.cert_dir], check=False)
            run_command(['chmod', '755', self.cert_dir])
            
            self.logger.info("✓ Certificate directory setup completed")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to setup certificate directory: {e}")
            return False
    
    def generate_root_ca(self) -> bool:
        """Generate root CA certificate and key"""
        try:
            self.logger.info("Generating root CA certificate...")
            
            ca_key_path = os.path.join(self.cert_dir, CERT_CONFIG['root_ca_key'])
            ca_cert_path = os.path.join(self.cert_dir, CERT_CONFIG['root_ca'])
            
            # Generate private key
            run_command([
                'openssl', 'genrsa', '-out', ca_key_path, '2048'
            ])
            
            # Generate root certificate
            run_command([
                'openssl', 'req', '-new', '-x509', '-days', '3650',
                '-key', ca_key_path, '-out', ca_cert_path,
                '-subj', f'/C=US/ST=State/L=City/O=Wazuh/OU=IT/CN=Wazuh-Root-CA'
            ])
            
            # Set proper permissions
            os.chmod(ca_key_path, 0o600)
            os.chmod(ca_cert_path, 0o644)
            run_command(['chown', 'wazuh-indexer:wazuh-indexer', ca_key_path], check=False)
            run_command(['chown', 'wazuh-indexer:wazuh-indexer', ca_cert_path], check=False)
            
            self.logger.info("✓ Root CA certificate generated successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to generate root CA: {e}")
            return False
    
    def generate_node_certificate(self) -> bool:
        """Generate node certificate for indexer"""
        try:
            self.logger.info("Generating node certificate...")
            
            ca_key_path = os.path.join(self.cert_dir, CERT_CONFIG['root_ca_key'])
            ca_cert_path = os.path.join(self.cert_dir, CERT_CONFIG['root_ca'])
            node_key_path = os.path.join(self.cert_dir, CERT_CONFIG['node_key'])
            node_cert_path = os.path.join(self.cert_dir, CERT_CONFIG['node'])
            
            # Generate private key
            run_command([
                'openssl', 'genrsa', '-out', node_key_path, '2048'
            ])
            
            # Create certificate signing request
            csr_path = f"{node_key_path}.csr"
            run_command([
                'openssl', 'req', '-new', '-key', node_key_path, '-out', csr_path,
                '-subj', f'/C=US/ST=State/L=City/O=Wazuh/OU=IT/CN={self.hostname}'
            ])
            
            # Create extensions file for SAN
            ext_file = f"{self.cert_dir}/node.ext"
            with open(ext_file, 'w') as f:
                f.write(f"""authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = {self.hostname}
DNS.2 = localhost
IP.1 = {self.ip_address}
IP.2 = 127.0.0.1
""")
            
            # Generate signed certificate
            run_command([
                'openssl', 'x509', '-req', '-in', csr_path,
                '-CA', ca_cert_path, '-CAkey', ca_key_path,
                '-CAcreateserial', '-out', node_cert_path,
                '-days', '365', '-extensions', 'v3_req',
                '-extfile', ext_file
            ])
            
            # Clean up temporary files
            os.remove(csr_path)
            os.remove(ext_file)
            
            # Set proper permissions
            os.chmod(node_key_path, 0o600)
            os.chmod(node_cert_path, 0o644)
            run_command(['chown', 'wazuh-indexer:wazuh-indexer', node_key_path], check=False)
            run_command(['chown', 'wazuh-indexer:wazuh-indexer', node_cert_path], check=False)
            
            self.logger.info("✓ Node certificate generated successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to generate node certificate: {e}")
            return False
    
    def generate_admin_certificate(self) -> bool:
        """Generate admin certificate"""
        try:
            self.logger.info("Generating admin certificate...")
            
            ca_key_path = os.path.join(self.cert_dir, CERT_CONFIG['root_ca_key'])
            ca_cert_path = os.path.join(self.cert_dir, CERT_CONFIG['root_ca'])
            admin_key_path = os.path.join(self.cert_dir, CERT_CONFIG['admin_key'])
            admin_cert_path = os.path.join(self.cert_dir, CERT_CONFIG['admin'])
            
            # Generate private key
            run_command([
                'openssl', 'genrsa', '-out', admin_key_path, '2048'
            ])
            
            # Generate certificate signing request
            csr_path = f"{admin_key_path}.csr"
            run_command([
                'openssl', 'req', '-new', '-key', admin_key_path, '-out', csr_path,
                '-subj', '/C=US/ST=State/L=City/O=Wazuh/OU=IT/CN=admin'
            ])
            
            # Generate signed certificate
            run_command([
                'openssl', 'x509', '-req', '-in', csr_path,
                '-CA', ca_cert_path, '-CAkey', ca_key_path,
                '-CAcreateserial', '-out', admin_cert_path,
                '-days', '365'
            ])
            
            # Clean up
            os.remove(csr_path)
            
            # Set proper permissions
            os.chmod(admin_key_path, 0o600)
            os.chmod(admin_cert_path, 0o644)
            run_command(['chown', 'wazuh-indexer:wazuh-indexer', admin_key_path], check=False)
            run_command(['chown', 'wazuh-indexer:wazuh-indexer', admin_cert_path], check=False)
            
            self.logger.info("✓ Admin certificate generated successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to generate admin certificate: {e}")
            return False
    
    def validate_certificates(self) -> bool:
        """Validate all required certificates exist and are valid"""
        try:
            self.logger.info("Validating certificates...")
            
            required_files = [
                CERT_CONFIG['root_ca'],
                CERT_CONFIG['root_ca_key'],
                CERT_CONFIG['node'],
                CERT_CONFIG['node_key'],
                CERT_CONFIG['admin'],
                CERT_CONFIG['admin_key']
            ]
            
            for cert_file in required_files:
                cert_path = os.path.join(self.cert_dir, cert_file)
                
                if not os.path.exists(cert_path):
                    self.logger.error(f"Certificate file missing: {cert_path}")
                    return False
                
                # Check if it's a valid certificate or key
                if cert_file.endswith('.pem') and not cert_file.endswith('-key.pem'):
                    try:
                        run_command(['openssl', 'x509', '-in', cert_path, '-noout', '-text'])
                        self.logger.debug(f"✓ Certificate valid: {cert_file}")
                    except subprocess.CalledProcessError:
                        self.logger.error(f"Invalid certificate: {cert_file}")
                        return False
                
                elif cert_file.endswith('-key.pem'):
                    try:
                        run_command(['openssl', 'rsa', '-in', cert_path, '-check', '-noout'])
                        self.logger.debug(f"✓ Private key valid: {cert_file}")
                    except subprocess.CalledProcessError:
                        self.logger.error(f"Invalid private key: {cert_file}")
                        return False
            
            self.logger.info("✓ All certificates validated successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Certificate validation failed: {e}")
            return False
    
    def setup_certificates(self) -> bool:
        """Complete certificate setup process"""
        try:
            self.logger.info("Starting certificate setup process...")
            
            # Setup certificate directory
            if not self.setup_certificate_directory():
                return False
            
            # Check if certificates already exist and are valid
            if self.validate_certificates():
                self.logger.info("Valid certificates already exist, skipping generation")
                return True
            
            # Generate certificates
            if not self.generate_root_ca():
                return False
            
            if not self.generate_node_certificate():
                return False
            
            if not self.generate_admin_certificate():
                return False
            
            # Final validation
            if not self.validate_certificates():
                return False
            
            self.logger.info("✓ Certificate setup completed successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Certificate setup failed: {e}")
            return False

# =============================================================================
# PACKAGE MANAGEMENT
# =============================================================================

class PackageManager:
    """Enhanced package manager with repository handling"""
    
    def __init__(self):
        self.logger = logging.getLogger("WazuhInstaller.PackageManager")
        self.distro = self._detect_distribution()
        self.package_manager = self._get_package_manager()
    
    def _detect_distribution(self) -> str:
        """Detect Linux distribution"""
        try:
            with open('/etc/os-release', 'r') as f:
                content = f.read().lower()
                if 'ubuntu' in content or 'debian' in content:
                    return 'debian'
                elif 'centos' in content or 'rhel' in content or 'fedora' in content:
                    return 'redhat'
                else:
                    return 'unknown'
        except Exception:
            return 'unknown'
    
    def _get_package_manager(self) -> str:
        """Get appropriate package manager"""
        if self.distro == 'debian':
            return 'apt'
        elif self.distro == 'redhat':
            return 'yum'
        else:
            return 'unknown'
    
    def update_package_cache(self) -> bool:
        """Update package cache"""
        try:
            self.logger.info("Updating package cache...")
            
            if self.package_manager == 'apt':
                run_command(['apt', 'update'])
            elif self.package_manager == 'yum':
                run_command(['yum', 'makecache'])
            
            self.logger.info("✓ Package cache updated")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to update package cache: {e}")
            return False
    
    def install_dependencies(self) -> bool:
        """Install required dependencies"""
        try:
            self.logger.info("Installing dependencies...")
            
            # Common dependencies
            dependencies = ['curl', 'wget', 'gnupg2', 'lsb-release']
            
            if self.distro == 'debian':
                dependencies.extend(['apt-transport-https', 'software-properties-common'])
            
            for package in dependencies:
                self.install_package(package)
            
            # Install OpenSSL if not present
            if not which('openssl'):
                self.install_package('openssl')
            
            self.logger.info("✓ Dependencies installed successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to install dependencies: {e}")
            return False
    
    def install_package(self, package: str) -> bool:
        """Install a single package"""
        try:
            self.logger.info(f"Installing package: {package}")
            
            if self.package_manager == 'apt':
                run_command(['apt', 'install', '-y', package])
            elif self.package_manager == 'yum':
                run_command(['yum', 'install', '-y', package])
            
            return True
            
        except Exception as e:
            self.logger.warning(f"Failed to install package {package}: {e}")
            return False
    
    def add_wazuh_repository(self) -> bool:
        """Add Wazuh repository"""
        try:
            self.logger.info("Adding Wazuh repository...")
            
            if self.distro == 'debian':
                # Add GPG key
                run_command(['curl', '-s', WAZUH_GPG_KEY, '|', 'apt-key', 'add', '-'], shell=True)
                
                # Add repository
                repo_line = f"deb {WAZUH_REPO_URL}/apt/ stable main"
                with open('/etc/apt/sources.list.d/wazuh.list', 'w') as f:
                    f.write(f"{repo_line}\n")
                
                self.update_package_cache()
                
            elif self.distro == 'redhat':
                # Create repository file
                repo_content = f"""[wazuh]
gpgcheck=1
gpgkey={WAZUH_GPG_KEY}
enabled=1
name=EL-\$releasever - Wazuh
baseurl={WAZUH_REPO_URL}/yum/
protect=1
"""
                with open('/etc/yum.repos.d/wazuh.repo', 'w') as f:
                    f.write(repo_content)
            
            self.logger.info("✓ Wazuh repository added successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to add Wazuh repository: {e}")
            return False

# =============================================================================
# WAZUH COMPONENT INSTALLERS
# =============================================================================

class WazuhIndexerInstaller:
    """Wazuh Indexer (OpenSearch) installer with SSL certificate handling"""
    
    def __init__(self, cert_manager: CertificateManager):
        self.logger = logging.getLogger("WazuhInstaller.Indexer")
        self.cert_manager = cert_manager
        self.config_path = "/etc/wazuh-indexer/opensearch.yml"
    
    def install(self) -> bool:
        """Install Wazuh Indexer"""
        try:
            self.logger.info("Installing Wazuh Indexer...")
            
            # Install package
            run_command(['apt', 'install', '-y', 'wazuh-indexer'])
            
            # Setup certificates BEFORE configuration
            if not self.cert_manager.setup_certificates():
                self.logger.error("Failed to setup certificates")
                return False
            
            # Configure indexer
            if not self.configure():
                return False
            
            # Enable and start service
            run_command(['systemctl', 'daemon-reload'])
            run_command(['systemctl', 'enable', 'wazuh-indexer'])
            
            self.logger.info("✓ Wazuh Indexer installed successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to install Wazuh Indexer: {e}")
            return False
    
    def configure(self) -> bool:
        """Configure Wazuh Indexer with proper SSL settings"""
        try:
            self.logger.info("Configuring Wazuh Indexer...")
            
            # Backup original config
            backup_file(self.config_path)
            
            # Get hostname and IP
            hostname = socket.gethostname()
            ip_address = self.cert_manager.ip_address
            
            # OpenSearch configuration with SSL
            config = {
                'cluster.name': 'wazuh-cluster',
                'node.name': hostname,
                'node.roles': ['master', 'ingest', 'data'],
                'path.data': '/var/lib/wazuh-indexer',
                'path.logs': '/var/log/wazuh-indexer',
                'network.host': '0.0.0.0',
                'http.port': 9200,
                'transport.port': 9300,
                'discovery.type': 'single-node',
                'bootstrap.memory_lock': True,
                
                # SSL Configuration (FIXED)
                'plugins.security.ssl.transport.pemcert_filepath': f'{CERT_DIR}/{CERT_CONFIG["node"]}',
                'plugins.security.ssl.transport.pemkey_filepath': f'{CERT_DIR}/{CERT_CONFIG["node_key"]}',
                'plugins.security.ssl.transport.pemtrustedcas_filepath': f'{CERT_DIR}/{CERT_CONFIG["root_ca"]}',
                'plugins.security.ssl.transport.enforce_hostname_verification': False,
                'plugins.security.ssl.transport.resolve_hostname': False,
                
                'plugins.security.ssl.http.enabled': True,
                'plugins.security.ssl.http.pemcert_filepath': f'{CERT_DIR}/{CERT_CONFIG["node"]}',
                'plugins.security.ssl.http.pemkey_filepath': f'{CERT_DIR}/{CERT_CONFIG["node_key"]}',
                'plugins.security.ssl.http.pemtrustedcas_filepath': f'{CERT_DIR}/{CERT_CONFIG["root_ca"]}',
                
                'plugins.security.nodes_dn': [f'CN={hostname},OU=IT,O=Wazuh,L=City,ST=State,C=US'],
                'plugins.security.authcz.admin_dn': ['CN=admin,OU=IT,O=Wazuh,L=City,ST=State,C=US'],
                
                'plugins.security.check_snapshot_restore_write_privileges': True,
                'plugins.security.enable_snapshot_restore_privilege': True,
                'plugins.security.system_indices.enabled': True,
                'plugins.security.system_indices.indices': [
                    '.plugins-ml-config', '.plugins-ml-connector', '.plugins-ml-model-group',
                    '.plugins-ml-model', '.plugins-ml-task', '.plugins-ml-conversation-meta',
                    '.plugins-ml-conversation-interactions', '.opendistro-alerting-config',
                    '.opendistro-alerting-alert*', '.opendistro-anomaly-results*',
                    '.opendistro-anomaly-detector*', '.opendistro-anomaly-checkpoints',
                    '.opendistro-anomaly-detection-state', '.opendistro-reports-*',
                    '.opensearch-notifications-*', '.opensearch-notebooks',
                    '.opensearch-observability', '.ql-datasources', '.opendistro-asynchronous-search-response*',
                    '.replication-metadata-store', '.opensearch-knn-models', '.geospatial-ip2geo-data*'
                ]
            }
            
            # Write configuration
            with open(self.config_path, 'w') as f:
                for key, value in config.items():
                    if isinstance(value, list):
                        f.write(f"{key}:\n")
                        for item in value:
                            f.write(f"  - \"{item}\"\n")
                    elif isinstance(value, bool):
                        f.write(f"{key}: {str(value).lower()}\n")
                    else:
                        f.write(f"{key}: {value}\n")
            
            # Set proper permissions
            run_command(['chown', 'wazuh-indexer:wazuh-indexer', self.config_path])
            run_command(['chmod', '640', self.config_path])
            
            self.logger.info("✓ Wazuh Indexer configured successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to configure Wazuh Indexer: {e}")
            return False
    
    def start_service(self) -> bool:
        """Start Wazuh Indexer service with certificate validation"""
        try:
            self.logger.info("Starting Wazuh Indexer service...")
            
            # Validate certificates before starting
            if not self.cert_manager.validate_certificates():
                self.logger.error("Certificate validation failed, cannot start service")
                return False
            
            # Start service
            run_command(['systemctl', 'start', 'wazuh-indexer'])
            
            # Wait for service to be ready
            max_attempts = 30
            for attempt in range(max_attempts):
                try:
                    result = run_command(['curl', '-k', '-s', 'https://localhost:9200'], check=False)
                    if result.returncode == 0:
                        self.logger.info("✓ Wazuh Indexer service started successfully")
                        return True
                except Exception:
                    pass
                
                self.logger.info(f"Waiting for Wazuh Indexer to start... ({attempt + 1}/{max_attempts})")
                time.sleep(10)
            
            self.logger.error("Wazuh Indexer failed to start within timeout period")
            return False
            
        except Exception as e:
            self.logger.error(f"Failed to start Wazuh Indexer service: {e}")
            return False

class WazuhManagerInstaller:
    """Wazuh Manager installer"""
    
    def __init__(self):
        self.logger = logging.getLogger("WazuhInstaller.Manager")
        self.config_path = "/var/ossec/etc/ossec.conf"
    
    def install(self) -> bool:
        """Install Wazuh Manager"""
        try:
            self.logger.info("Installing Wazuh Manager...")
            
            # Install package
            run_command(['apt', 'install', '-y', 'wazuh-manager'])
            
            # Configure manager
            if not self.configure():
                return False
            
            # Enable and start service
            run_command(['systemctl', 'daemon-reload'])
            run_command(['systemctl', 'enable', 'wazuh-manager'])
            run_command(['systemctl', 'start', 'wazuh-manager'])
            
            self.logger.info("✓ Wazuh Manager installed successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to install Wazuh Manager: {e}")
            return False
    
    def configure(self) -> bool:
        """Configure Wazuh Manager"""
        try:
            self.logger.info("Configuring Wazuh Manager...")
            
            # Backup original config
            backup_file(self.config_path)
            
            # Basic configuration - keeping default settings for production
            # Custom configurations can be added here
            
            self.logger.info("✓ Wazuh Manager configured successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to configure Wazuh Manager: {e}")
            return False

class WazuhDashboardInstaller:
    """Wazuh Dashboard installer"""
    
    def __init__(self):
        self.logger = logging.getLogger("WazuhInstaller.Dashboard")
        self.config_path = "/etc/wazuh-dashboard/opensearch_dashboards.yml"
    
    def install(self) -> bool:
        """Install Wazuh Dashboard"""
        try:
            self.logger.info("Installing Wazuh Dashboard...")
            
            # Install package
            run_command(['apt', 'install', '-y', 'wazuh-dashboard'])
            
            # Configure dashboard
            if not self.configure():
                return False
            
            # Enable and start service
            run_command(['systemctl', 'daemon-reload'])
            run_command(['systemctl', 'enable', 'wazuh-dashboard'])
            run_command(['systemctl', 'start', 'wazuh-dashboard'])
            
            self.logger.info("✓ Wazuh Dashboard installed successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to install Wazuh Dashboard: {e}")
            return False
    
    def configure(self) -> bool:
        """Configure Wazuh Dashboard"""
        try:
            self.logger.info("Configuring Wazuh Dashboard...")
            
            # Backup original config
            backup_file(self.config_path)
            
            # Dashboard configuration
            hostname = socket.gethostname()
            config = {
                'server.host': '0.0.0.0',
                'server.port': 443,
                'opensearch.hosts': ['https://localhost:9200'],
                'opensearch.ssl.verificationMode': 'certificate',
                'opensearch.ssl.certificateAuthorities': [f'{CERT_DIR}/{CERT_CONFIG["root_ca"]}'],
                'opensearch.ssl.certificate': f'{CERT_DIR}/{CERT_CONFIG["node"]}',
                'opensearch.ssl.key': f'{CERT_DIR}/{CERT_CONFIG["node_key"]}',
                'opensearch.username': 'kibanaserver',
                'opensearch.password': 'kibanaserver',
                'opensearch.requestHeadersWhitelist': ['authorization', 'securitytenant'],
                'opensearch_security.multitenancy.enabled': True,
                'opensearch_security.multitenancy.tenants.preferred': ['Private', 'Global'],
                'opensearch_security.readonly_mode.roles': ['kibana_read_only'],
                'server.ssl.enabled': True,
                'server.ssl.certificate': f'{CERT_DIR}/{CERT_CONFIG["node"]}',
                'server.ssl.key': f'{CERT_DIR}/{CERT_CONFIG["node_key"]}',
                'uiSettings.overrides.defaultRoute': '/app/wz-home'
            }
            
            # Write configuration
            with open(self.config_path, 'w') as f:
                for key, value in config.items():
                    if isinstance(value, list):
                        f.write(f"{key}:\n")
                        for item in value:
                            f.write(f"  - \"{item}\"\n")
                    elif isinstance(value, bool):
                        f.write(f"{key}: {str(value).lower()}\n")
                    else:
                        f.write(f"{key}: {value}\n")
            
            # Set proper permissions
            run_command(['chown', 'wazuh-dashboard:wazuh-dashboard', self.config_path])
            run_command(['chmod', '640', self.config_path])
            
            self.logger.info("✓ Wazuh Dashboard configured successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to configure Wazuh Dashboard: {e}")
            return False

# =============================================================================
# MAIN INSTALLER CLASS
# =============================================================================

class WazuhInstaller:
    """Main Wazuh installer orchestrator"""
    
    def __init__(self, args):
        self.args = args
        self.logger = setup_logging(args.log_level, args.log_file)
        self.cert_manager = CertificateManager()
        self.package_manager = PackageManager()
        
        # Component installers
        self.indexer_installer = WazuhIndexerInstaller(self.cert_manager)
        self.manager_installer = WazuhManagerInstaller()
        self.dashboard_installer = WazuhDashboardInstaller()
        
        # Installation state
        self.installation_state = {
            'requirements_checked': False,
            'repositories_added': False,
            'certificates_setup': False,
            'indexer_installed': False,
            'manager_installed': False,
            'dashboard_installed': False
        }
    
    def check_requirements(self) -> bool:
        """Check system requirements"""
        self.logger.info("=== CHECKING SYSTEM REQUIREMENTS ===")
        
        requirements = check_system_requirements()
        
        # Critical requirements
        if not requirements['root_privileges']:
            self.logger.error("Root privileges are required")
            return False
        
        if not requirements['os_supported']:
            self.logger.error("Unsupported operating system")
            return False
        
        self.installation_state['requirements_checked'] = True
        return True
    
    def setup_repositories(self) -> bool:
        """Setup package repositories"""
        self.logger.info("=== SETTING UP REPOSITORIES ===")
        
        try:
            # Update package cache
            if not self.package_manager.update_package_cache():
                return False
            
            # Install dependencies
            if not self.package_manager.install_dependencies():
                return False
            
            # Add Wazuh repository
            if not self.package_manager.add_wazuh_repository():
                return False
            
            self.installation_state['repositories_added'] = True
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to setup repositories: {e}")
            return False
    
    def install_components(self) -> bool:
        """Install Wazuh components"""
        self.logger.info("=== INSTALLING WAZUH COMPONENTS ===")
        
        try:
            # Install Wazuh Indexer (with certificate setup)
            if self.args.components in ['all', 'indexer']:
                if not self.indexer_installer.install():
                    return False
                self.installation_state['indexer_installed'] = True
                
                # Start indexer service
                if not self.indexer_installer.start_service():
                    return False
            
            # Install Wazuh Manager
            if self.args.components in ['all', 'manager']:
                if not self.manager_installer.install():
                    return False
                self.installation_state['manager_installed'] = True
            
            # Install Wazuh Dashboard
            if self.args.components in ['all', 'dashboard']:
                if not self.dashboard_installer.install():
                    return False
                self.installation_state['dashboard_installed'] = True
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to install components: {e}")
            return False
    
    def post_installation_tasks(self) -> bool:
        """Perform post-installation tasks"""
        self.logger.info("=== POST-INSTALLATION TASKS ===")
        
        try:
            # Configure firewall if needed
            if self.args.configure_firewall:
                self.configure_firewall()
            
            # Generate summary
            self.generate_installation_summary()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Post-installation tasks failed: {e}")
            return False
    
    def configure_firewall(self) -> bool:
        """Configure firewall rules"""
        try:
            self.logger.info("Configuring firewall...")
            
            # Common ports for Wazuh
            ports = {
                'indexer': ['9200/tcp', '9300/tcp'],
                'manager': ['1514/tcp', '1514/udp', '1515/tcp', '55000/tcp'],
                'dashboard': ['443/tcp', '5601/tcp']
            }
            
            # Configure UFW if available
            if which('ufw'):
                for component, component_ports in ports.items():
                    if self.installation_state.get(f'{component}_installed', False):
                        for port in component_ports:
                            run_command(['ufw', 'allow', port], check=False)
                
                self.logger.info("✓ Firewall configured successfully")
            
            return True
            
        except Exception as e:
            self.logger.warning(f"Failed to configure firewall: {e}")
            return False
    
    def generate_installation_summary(self) -> None:
        """Generate installation summary"""
        self.logger.info("=== INSTALLATION SUMMARY ===")
        
        hostname = socket.gethostname()
        ip_address = self.cert_manager.ip_address
        
        summary = f"""
Wazuh Installation Completed Successfully!

Server Information:
- Hostname: {hostname}
- IP Address: {ip_address}
- Installation Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Installed Components:
"""
        
        if self.installation_state.get('indexer_installed'):
            summary += "✓ Wazuh Indexer (OpenSearch) - Port 9200 (HTTPS)\n"
        
        if self.installation_state.get('manager_installed'):
            summary += "✓ Wazuh Manager - Port 1514 (Agents), Port 55000 (API)\n"
        
        if self.installation_state.get('dashboard_installed'):
            summary += "✓ Wazuh Dashboard - Port 443 (HTTPS)\n"
        
        summary += f"""
Access Information:
- Dashboard URL: https://{ip_address}/
- API URL: https://{ip_address}:55000/
- Default Credentials: admin/admin (Please change immediately!)

Certificate Files:
- Root CA: {CERT_DIR}/{CERT_CONFIG['root_ca']}
- Node Certificate: {CERT_DIR}/{CERT_CONFIG['node']}
- Admin Certificate: {CERT_DIR}/{CERT_CONFIG['admin']}

Next Steps:
1. Change default passwords
2. Configure agent enrollment
3. Setup monitoring rules
4. Review security settings

For support: https://documentation.wazuh.com/
"""
        
        self.logger.info(summary)
        
        # Save summary to file
        summary_file = f"{LOG_DIR}/installation_summary.txt"
        with open(summary_file, 'w') as f:
            f.write(summary)
        
        self.logger.info(f"Installation summary saved to: {summary_file}")
    
    def run(self) -> bool:
        """Run the complete installation process"""
        try:
            self.logger.info(f"Starting Wazuh installation - Version {VERSION}")
            self.logger.info(f"Author: {AUTHOR}")
            self.logger.info(f"Components to install: {self.args.components}")
            
            # Check requirements
            if not self.check_requirements():
                return False
            
            # Setup repositories
            if not self.setup_repositories():
                return False
            
            # Install components
            if not self.install_components():
                return False
            
            # Post-installation tasks
            if not self.post_installation_tasks():
                return False
            
            self.logger.info("🎉 Wazuh installation completed successfully!")
            return True
            
        except KeyboardInterrupt:
            self.logger.warning("Installation interrupted by user")
            return False
        except Exception as e:
            self.logger.error(f"Installation failed: {e}")
            return False

# =============================================================================
# COMMAND LINE INTERFACE
# =============================================================================

def create_argument_parser() -> argparse.ArgumentParser:
    """Create command line argument parser"""
    
    parser = argparse.ArgumentParser(
        description="Wazuh Server Installation Script",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  {sys.argv[0]} --components all                    # Install all components
  {sys.argv[0]} --components indexer               # Install only indexer
  {sys.argv[0]} --components manager               # Install only manager
  {sys.argv[0]} --components dashboard             # Install only dashboard
  {sys.argv[0]} --log-level DEBUG                  # Enable debug logging
  {sys.argv[0]} --configure-firewall               # Configure firewall rules

Author: {AUTHOR}
Version: {VERSION}
"""
    )
    
    parser.add_argument(
        '--components',
        choices=['all', 'indexer', 'manager', 'dashboard'],
        default='all',
        help='Components to install (default: all)'
    )
    
    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default='INFO',
        help='Logging level (default: INFO)'
    )
    
    parser.add_argument(
        '--log-file',
        help='Custom log file path'
    )
    
    parser.add_argument(
        '--configure-firewall',
        action='store_true',
        help='Configure firewall rules automatically'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version=f'Wazuh Installer {VERSION}'
    )
    
    return parser

def main():
    """Main entry point"""
    
    # Parse command line arguments
    parser = create_argument_parser()
    args = parser.parse_args()
    
    # Create installer instance
    installer = WazuhInstaller(args)
    
    # Run installation
    success = installer.run()
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()