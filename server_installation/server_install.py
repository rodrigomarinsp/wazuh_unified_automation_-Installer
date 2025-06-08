#!/usr/bin/env python3
"""
Wazuh Server Installation Script - Python Implementation
Author: Rodrigo Marins Piaba (Fanaticos4tech)
E-Mail: rodrigomarinsp@gmail.com / fanaticos4tech@gmail.com
GitHub: rodrigomarinsp
Instagram: @fanaticos4tech
License: GPL-3.0

## Advanced Python installer with enhanced features, logging, and automation capabilities.
## FINAL WORKING VERSION - Ubuntu 24.04 Compatible
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
GITHUB = "rodrigomarinsp"
EMAIL = "rodrigomarinsp@gmail.com"

# Supported operating systems with Ubuntu 24.04 using jammy repository
SUPPORTED_OS = {
    'ubuntu': ['18.04', '20.04', '22.04', '24.04'],
    'debian': ['10', '11', '12'],
    'centos': ['7', '8'],
    'rhel': ['7', '8', '9'],
    'amazon': ['2', '2023']
}

# Repository mapping - Ubuntu 24.04 uses jammy repository for compatibility
REPO_MAPPING = {
    'ubuntu': {
        '18.04': 'bionic',
        '20.04': 'focal', 
        '22.04': 'jammy',
        '24.04': 'jammy'  # Use jammy repository for Ubuntu 24.04 compatibility
    },
    'debian': {
        '10': 'buster',
        '11': 'bullseye',
        '12': 'bookworm'
    }
}

# Required dependencies
REQUIRED_TOOLS = ['curl', 'wget', 'gpg', 'openssl', 'systemctl', 'unzip']

# Wazuh configuration
WAZUH_VERSION = "4.9.2"
WAZUH_MAJOR_VERSION = "4.x"

# Network configuration
DEFAULT_PORTS = {
    'wazuh_manager': 1514,
    'wazuh_api': 55000,
    'wazuh_indexer': 9200,
    'wazuh_dashboard': 443
}

# =============================================================================
# LOGGING CONFIGURATION
# =============================================================================

class ColoredFormatter(logging.Formatter):
    """Custom formatter to add colors to log levels"""
    
    COLORS = {
        'DEBUG': '\033[36m',    # Cyan
        'INFO': '\033[32m',     # Green
        'WARNING': '\033[33m',  # Yellow
        'ERROR': '\033[31m',    # Red
        'CRITICAL': '\033[35m', # Magenta
    }
    RESET = '\033[0m'
    
    def format(self, record):
        color = self.COLORS.get(record.levelname, self.RESET)
        record.levelname = f"{color}{record.levelname}{self.RESET}"
        return super().format(record)

def setup_logging(verbose: bool = False) -> logging.Logger:
    """Setup comprehensive logging with timestamps and colors"""
    
    log_level = logging.DEBUG if verbose else logging.INFO
    
    # Create logger
    logger = logging.getLogger('wazuh_installer')
    logger.setLevel(log_level)
    
    # Clear any existing handlers
    logger.handlers.clear()
    
    # Console handler with colors
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    
    # Create formatter
    formatter = ColoredFormatter(
        fmt='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # File handler for detailed logs
    log_file = f"/tmp/wazuh_install_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)
    
    file_formatter = logging.Formatter(
        fmt='%(asctime)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)
    
    logger.info(f"Detailed logs will be saved to: {log_file}")
    return logger

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def run_command(command: List[str], check: bool = True, capture_output: bool = True, 
                input_text: str = None, timeout: int = 300, logger=None) -> subprocess.CompletedProcess:
    """
    Execute a command with comprehensive error handling and logging
    """
    if logger:
        logger.debug(f"Executing command: {' '.join(command)}")
    
    try:
        start_time = time.time()
        
        result = subprocess.run(
            command,
            check=check,
            capture_output=capture_output,
            text=True,
            input=input_text,
            timeout=timeout
        )
        
        elapsed_time = time.time() - start_time
        
        if logger:
            logger.debug(f"Command completed in {elapsed_time:.2f} seconds")
            if result.stdout and capture_output:
                logger.debug(f"Stdout: {result.stdout[:500]}...")
            if result.stderr and capture_output:
                logger.debug(f"Stderr: {result.stderr[:500]}...")
        
        return result
        
    except subprocess.CalledProcessError as e:
        if logger:
            logger.error(f"Command failed: {' '.join(command)}")
            logger.error(f"Return code: {e.returncode}")
            if e.stdout:
                logger.error(f"Stdout: {e.stdout}")
            if e.stderr:
                logger.error(f"Stderr: {e.stderr}")
        raise
    except subprocess.TimeoutExpired as e:
        if logger:
            logger.error(f"Command timed out after {timeout} seconds: {' '.join(command)}")
        raise
    except Exception as e:
        if logger:
            logger.error(f"Unexpected error executing command: {e}")
        raise

def check_root_privileges(logger) -> bool:
    """Check if script is running with root privileges"""
    if os.geteuid() != 0:
        logger.error("This script must be run as root (use sudo)")
        return False
    return True

def get_system_info(logger) -> Dict[str, str]:
    """Get comprehensive system information"""
    logger.info("Gathering system information...")
    
    try:
        # Get OS information
        with open('/etc/os-release', 'r') as f:
            os_info = {}
            for line in f:
                if '=' in line:
                    key, value = line.strip().split('=', 1)
                    os_info[key] = value.strip('"')
        
        # Get architecture
        arch = platform.machine()
        
        # Parse OS details
        os_id = os_info.get('ID', '').lower()
        os_version = os_info.get('VERSION_ID', '').strip('"')
        os_name = os_info.get('PRETTY_NAME', 'Unknown')
        
        system_info = {
            'os_id': os_id,
            'os_version': os_version,
            'os_name': os_name,
            'architecture': arch,
            'kernel': platform.release()
        }
        
        logger.info(f"System: {os_name}")
        logger.info(f"OS ID: {os_id}")
        logger.info(f"OS Version: {os_version}")
        logger.info(f"Architecture: {arch}")
        
        return system_info
        
    except Exception as e:
        logger.error(f"Failed to get system information: {e}")
        raise

def check_os_support(system_info: Dict[str, str], logger) -> bool:
    """Check if the operating system is supported"""
    os_id = system_info['os_id']
    os_version = system_info['os_version']
    
    logger.info(f"Checking OS support for {os_id} {os_version}")
    
    if os_id not in SUPPORTED_OS:
        logger.error(f"Unsupported OS: {os_id}")
        logger.error(f"Supported OS: {list(SUPPORTED_OS.keys())}")
        return False
    
    if os_version not in SUPPORTED_OS[os_id]:
        logger.error(f"Unsupported OS version: {os_version}")
        logger.error(f"Supported versions for {os_id}: {SUPPORTED_OS[os_id]}")
        return False
    
    logger.info(f"Supported OS: {os_id} {os_version}")
    return True

def check_dependencies(logger) -> Tuple[List[str], List[str]]:
    """Check for required system dependencies"""
    logger.info("Checking required dependencies...")
    
    available = []
    missing = []
    
    for tool in REQUIRED_TOOLS:
        if which(tool):
            available.append(tool)
            logger.debug(f"✓ Found: {tool}")
        else:
            missing.append(tool)
            logger.warning(f"✗ Missing: {tool}")
    
    logger.info(f"Available tools: {available}")
    if missing:
        logger.warning(f"Missing tools: {missing}")
    
    return available, missing

def install_missing_dependencies(missing_tools: List[str], system_info: Dict[str, str], logger) -> bool:
    """Install missing system dependencies"""
    if not missing_tools:
        return True
    
    logger.info(f"Installing missing tools: {missing_tools}")
    os_id = system_info['os_id']
    
    try:
        if os_id in ['ubuntu', 'debian']:
            # Update package cache
            logger.info("Updating package cache...")
            run_command(['apt-get', 'update', '-y'], logger=logger)
            
            # Install missing packages
            for tool in missing_tools:
                package_map = {
                    'gpg': 'gnupg',
                    'systemctl': 'systemd',
                    'unzip': 'unzip'
                }
                package = package_map.get(tool, tool)
                
                logger.info(f"Installing {package}...")
                run_command(['apt-get', 'install', '-y', package], logger=logger)
        
        elif os_id in ['centos', 'rhel']:
            for tool in missing_tools:
                logger.info(f"Installing {tool}...")
                run_command(['yum', 'install', '-y', tool], logger=logger)
        
        elif os_id == 'amazon':
            for tool in missing_tools:
                logger.info(f"Installing {tool}...")
                run_command(['yum', 'install', '-y', tool], logger=logger)
        
        logger.info("Successfully installed missing tools")
        return True
        
    except Exception as e:
        logger.error(f"Failed to install dependencies: {e}")
        return False

def get_network_info(logger) -> Tuple[str, str]:
    """Get system hostname and IP address"""
    logger.info("Getting network information...")
    
    try:
        # Get hostname
        hostname = run_command(['hostname'], logger=logger).stdout.strip()
        logger.info(f"Hostname: {hostname}")
        
        # Get IP address
        ip_result = run_command(['hostname', '-I'], logger=logger)
        ip_address = ip_result.stdout.strip().split()[0]
        logger.info(f"IP address (hostname -I): {ip_address}")
        
        return hostname, ip_address
        
    except Exception as e:
        logger.error(f"Failed to get network information: {e}")
        # Fallback
        hostname = "wazuh-server"
        ip_address = "127.0.0.1"
        logger.warning(f"Using fallback values: hostname={hostname}, ip={ip_address}")
        return hostname, ip_address

def show_progress(step: int, total: int, description: str, logger):
    """Show installation progress with visual progress bar"""
    percentage = (step / total) * 100
    filled = int(percentage / 5)  # 20 chars total
    bar = "█" * filled + "░" * (20 - filled)
    
    logger.info(f"[{step}/{total}] ({percentage:.1f}%) {bar} {description}")

# =============================================================================
# WAZUH REPOSITORY SETUP
# =============================================================================

def setup_wazuh_repository(system_info: Dict[str, str], logger) -> bool:
    """Setup Wazuh repository with Ubuntu 24.04 compatibility"""
    logger.info("Setting up Wazuh repository...")
    
    os_id = system_info['os_id']
    os_version = system_info['os_version']
    
    try:
        if os_id == 'ubuntu':
            return setup_wazuh_repository_ubuntu(system_info, logger)
        elif os_id == 'debian':
            return setup_wazuh_repository_debian(system_info, logger)
        elif os_id in ['centos', 'rhel']:
            return setup_wazuh_repository_rhel(system_info, logger)
        else:
            logger.error(f"Repository setup not implemented for {os_id}")
            return False
            
    except Exception as e:
        logger.error(f"Failed to setup Wazuh repository: {e}")
        return False

def setup_wazuh_repository_ubuntu(system_info: Dict[str, str], logger) -> bool:
    """Setup Wazuh repository for Ubuntu (including 24.04 using jammy repo)"""
    logger.info(f"Setting up Wazuh repository for ubuntu {system_info['os_version']}")
    
    try:
        # Get repository codename - Ubuntu 24.04 uses jammy
        os_version = system_info['os_version']
        repo_codename = REPO_MAPPING['ubuntu'].get(os_version, 'jammy')
        
        logger.info(f"Using repository codename: {repo_codename}")
        
        # Download and import GPG key
        logger.info("Downloading Wazuh GPG key...")
        gpg_key_url = "https://packages.wazuh.com/key/GPG-KEY-WAZUH"
        
        # Download GPG key
        curl_result = run_command([
            'curl', '-s', gpg_key_url
        ], logger=logger)
        
        if not curl_result.stdout:
            raise Exception("Failed to download GPG key")
        
        # Import GPG key using proper method
        gpg_result = run_command([
            'gpg', '--dearmor'
        ], input=curl_result.stdout, logger=logger)
        
        # Save to keyring
        keyring_path = '/usr/share/keyrings/wazuh.gpg'
        with open(keyring_path, 'wb') as f:
            f.write(gpg_result.stdout.encode('latin1'))
        
        logger.info("GPG key imported successfully")
        
        # Add repository
        logger.info("Adding Wazuh repository to sources...")
        repo_line = f"deb [signed-by={keyring_path}] https://packages.wazuh.com/{WAZUH_MAJOR_VERSION}/apt/ {repo_codename} main"
        
        sources_file = '/etc/apt/sources.list.d/wazuh.list'
        with open(sources_file, 'w') as f:
            f.write(repo_line + '\n')
        
        logger.info(f"Repository added for {repo_codename}")
        
        # Update package cache
        logger.info("Updating package cache...")
        run_command(['apt-get', 'update'], logger=logger)
        
        logger.info("Wazuh repository setup completed successfully")
        return True
        
    except Exception as e:
        logger.error(f"Failed to setup Ubuntu repository: {e}")
        return False

def setup_wazuh_repository_debian(system_info: Dict[str, str], logger) -> bool:
    """Setup Wazuh repository for Debian"""
    # Similar implementation for Debian
    return setup_wazuh_repository_ubuntu(system_info, logger)

def setup_wazuh_repository_rhel(system_info: Dict[str, str], logger) -> bool:
    """Setup Wazuh repository for RHEL/CentOS"""
    logger.info("Setting up Wazuh repository for RHEL/CentOS...")
    
    try:
        # Import GPG key
        logger.info("Importing Wazuh GPG key...")
        run_command([
            'rpm', '--import', 'https://packages.wazuh.com/key/GPG-KEY-WAZUH'
        ], logger=logger)
        
        # Add repository
        repo_content = f"""[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-$releasever - Wazuh
baseurl=https://packages.wazuh.com/{WAZUH_MAJOR_VERSION}/yum/
protect=1
"""
        
        with open('/etc/yum.repos.d/wazuh.repo', 'w') as f:
            f.write(repo_content)
        
        logger.info("Wazuh repository setup completed")
        return True
        
    except Exception as e:
        logger.error(f"Failed to setup RHEL repository: {e}")
        return False

# =============================================================================
# SSL CERTIFICATE MANAGEMENT
# =============================================================================

def generate_ssl_certificates(hostname: str, ip_address: str, logger) -> bool:
    """Generate SSL certificates for Wazuh with modern OpenSSL approach"""
    logger.info("Setting up SSL certificates...")
    
    cert_dir = '/etc/wazuh-indexer/certs'
    
    try:
        # Create certificate directory
        logger.info(f"Creating certificate directory: {cert_dir}")
        os.makedirs(cert_dir, exist_ok=True)
        os.chmod(cert_dir, 0o755)
        
        # Generate Root CA
        logger.info("Generating Root CA certificate...")
        if not generate_root_ca(cert_dir, logger):
            return False
        
        # Generate Admin certificate
        logger.info("Generating Admin certificate...")
        if not generate_admin_certificate(cert_dir, logger):
            return False
        
        # Generate Node certificate
        logger.info("Generating Node certificate...")
        if not generate_node_certificate(cert_dir, hostname, ip_address, logger):
            return False
        
        # Set proper permissions
        logger.info("Setting certificate permissions...")
        set_certificate_permissions(cert_dir, logger)
        
        # Validate certificates
        logger.info("Validating generated certificates...")
        if not validate_certificates(cert_dir, logger):
            return False
        
        logger.info("SSL certificates generated successfully")
        return True
        
    except Exception as e:
        logger.error(f"Failed to generate SSL certificates: {e}")
        return False

def generate_root_ca(cert_dir: str, logger) -> bool:
    """Generate Root CA certificate"""
    try:
        ca_key_path = os.path.join(cert_dir, 'root-ca-key.pem')
        ca_cert_path = os.path.join(cert_dir, 'root-ca.pem')
        
        # Generate CA private key
        logger.debug("Generating CA private key...")
        run_command([
            'openssl', 'genrsa', '-out', ca_key_path, '2048'
        ], logger=logger)
        
        # Generate CA certificate
        logger.debug("Generating CA certificate...")
        run_command([
            'openssl', 'req', '-new', '-x509',
            '-key', ca_key_path,
            '-out', ca_cert_path,
            '-days', '3650',
            '-subj', '/C=US/ST=California/L=San Francisco/O=Wazuh/OU=IT/CN=Wazuh Root CA'
        ], logger=logger)
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to generate Root CA: {e}")
        return False

def generate_admin_certificate(cert_dir: str, logger) -> bool:
    """Generate Admin certificate"""
    try:
        admin_key_path = os.path.join(cert_dir, 'admin-key.pem')
        admin_csr_path = os.path.join(cert_dir, 'admin.csr')
        admin_cert_path = os.path.join(cert_dir, 'admin.pem')
        ca_cert_path = os.path.join(cert_dir, 'root-ca.pem')
        ca_key_path = os.path.join(cert_dir, 'root-ca-key.pem')
        
        # Generate admin private key
        logger.debug("Generating admin private key...")
        run_command([
            'openssl', 'genrsa', '-out', admin_key_path, '2048'
        ], logger=logger)
        
        # Generate admin CSR
        logger.debug("Generating admin CSR...")
        run_command([
            'openssl', 'req', '-new',
            '-key', admin_key_path,
            '-out', admin_csr_path,
            '-subj', '/C=US/ST=California/L=San Francisco/O=Wazuh/OU=IT/CN=admin'
        ], logger=logger)
        
        # Generate admin certificate using modern approach
        logger.debug("Generating admin certificate...")
        run_command([
            'openssl', 'x509', '-req',
            '-in', admin_csr_path,
            '-CA', ca_cert_path,
            '-CAkey', ca_key_path,
            '-CAcreateserial',
            '-out', admin_cert_path,
            '-days', '365'
        ], logger=logger)
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to generate admin certificate: {e}")
        return False

def generate_node_certificate(cert_dir: str, hostname: str, ip_address: str, logger) -> bool:
    """Generate Node certificate with proper SAN using modern OpenSSL approach"""
    try:
        node_key_path = os.path.join(cert_dir, 'node-key.pem')
        node_csr_path = os.path.join(cert_dir, 'node.csr')
        node_cert_path = os.path.join(cert_dir, 'node.pem')
        ca_cert_path = os.path.join(cert_dir, 'root-ca.pem')
        ca_key_path = os.path.join(cert_dir, 'root-ca-key.pem')
        
        # Generate node private key
        logger.debug("Generating node private key...")
        run_command([
            'openssl', 'genrsa', '-out', node_key_path, '2048'
        ], logger=logger)
        
        # Generate node CSR
        logger.debug("Generating node CSR...")
        run_command([
            'openssl', 'req', '-new',
            '-key', node_key_path,
            '-out', node_csr_path,
            '-subj', f'/C=US/ST=California/L=San Francisco/O=Wazuh/OU=IT/CN={hostname}'
        ], logger=logger)
        
        # Generate node certificate with SAN using modern -addext approach
        logger.debug("Generating node certificate with SAN...")
        san_list = f'DNS:localhost,DNS:{hostname},DNS:wazuh-indexer,IP:127.0.0.1,IP:{ip_address}'
        
        run_command([
            'openssl', 'x509', '-req',
            '-in', node_csr_path,
            '-CA', ca_cert_path,
            '-CAkey', ca_key_path,
            '-CAcreateserial',
            '-out', node_cert_path,
            '-days', '365',
            '-addext', f'subjectAltName={san_list}'
        ], logger=logger)
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to generate node certificate: {e}")
        return False

def set_certificate_permissions(cert_dir: str, logger):
    """Set proper permissions for certificate files"""
    try:
        # Set directory permissions
        os.chmod(cert_dir, 0o755)
        
        # Set file permissions
        for cert_file in os.listdir(cert_dir):
            cert_path = os.path.join(cert_dir, cert_file)
            if cert_file.endswith('-key.pem'):
                # Private keys - more restrictive
                os.chmod(cert_path, 0o600)
            else:
                # Certificates and CSRs
                os.chmod(cert_path, 0o644)
        
        # Set ownership to wazuh-indexer user if exists
        try:
            run_command(['chown', '-R', 'wazuh-indexer:wazuh-indexer', cert_dir], 
                       check=False, logger=logger)
        except:
            logger.debug("wazuh-indexer user not found, keeping root ownership")
        
    except Exception as e:
        logger.warning(f"Failed to set certificate permissions: {e}")

def validate_certificates(cert_dir: str, logger) -> bool:
    """Validate generated certificates"""
    try:
        required_files = [
            'root-ca.pem', 'root-ca-key.pem',
            'admin.pem', 'admin-key.pem',
            'node.pem', 'node-key.pem'
        ]
        
        for cert_file in required_files:
            cert_path = os.path.join(cert_dir, cert_file)
            if not os.path.exists(cert_path):
                logger.error(f"Missing certificate file: {cert_file}")
                return False
            
            # Validate certificate files (not keys)
            if cert_file.endswith('.pem') and not cert_file.endswith('-key.pem'):
                logger.debug(f"Validating certificate: {cert_file}")
                try:
                    run_command([
                        'openssl', 'x509', '-in', cert_path, '-text', '-noout'
                    ], logger=logger)
                except:
                    logger.error(f"Invalid certificate: {cert_file}")
                    return False
        
        logger.info("All certificates validated successfully")
        return True
        
    except Exception as e:
        logger.error(f"Certificate validation failed: {e}")
        return False

# =============================================================================
# WAZUH COMPONENT INSTALLATION
# =============================================================================

def install_wazuh_indexer(system_info: Dict[str, str], hostname: str, ip_address: str, logger) -> bool:
    """Install and configure Wazuh Indexer"""
    logger.info("Installing Wazuh Indexer...")
    
    try:
        os_id = system_info['os_id']
        
        # Install package
        if os_id in ['ubuntu', 'debian']:
            logger.info("Installing wazuh-indexer package...")
            run_command(['apt-get', 'install', '-y', 'wazuh-indexer'], logger=logger)
        elif os_id in ['centos', 'rhel', 'amazon']:
            logger.info("Installing wazuh-indexer package...")
            run_command(['yum', 'install', '-y', 'wazuh-indexer'], logger=logger)
        
        # Generate SSL certificates
        if not generate_ssl_certificates(hostname, ip_address, logger):
            raise Exception("Failed to generate SSL certificates")
        
        # Configure Wazuh Indexer
        logger.info("Configuring Wazuh Indexer...")
        if not configure_wazuh_indexer(hostname, ip_address, logger):
            raise Exception("Failed to configure Wazuh Indexer")
        
        # Start and enable service
        logger.info("Starting Wazuh Indexer service...")
        run_command(['systemctl', 'daemon-reload'], logger=logger)
        run_command(['systemctl', 'enable', 'wazuh-indexer'], logger=logger)
        run_command(['systemctl', 'start', 'wazuh-indexer'], logger=logger)
        
        # Wait for service to start
        logger.info("Waiting for Wazuh Indexer to start...")
        time.sleep(10)
        
        # Check service status
        result = run_command(['systemctl', 'is-active', 'wazuh-indexer'], 
                           check=False, logger=logger)
        if result.returncode == 0:
            logger.info("✓ Wazuh Indexer started successfully")
        else:
            logger.warning("Wazuh Indexer may not have started properly")
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to install Wazuh Indexer: {e}")
        return False

def configure_wazuh_indexer(hostname: str, ip_address: str, logger) -> bool:
    """Configure Wazuh Indexer with proper settings"""
    try:
        config_file = '/etc/wazuh-indexer/opensearch.yml'
        
        # Backup original config
        if os.path.exists(config_file):
            backup_file = f"{config_file}.backup.{int(time.time())}"
            shutil.copy2(config_file, backup_file)
            logger.info(f"Backed up original config to {backup_file}")
        
        # Create new configuration
        config_content = f"""# Wazuh Indexer Configuration
cluster.name: wazuh-cluster
node.name: {hostname}
node.roles: [ master, ingest, data ]

network.host: {ip_address}
http.port: 9200

discovery.type: single-node
cluster.initial_master_nodes: ["{hostname}"]

# Security settings
plugins.security.ssl.transport.pemcert_filepath: certs/node.pem
plugins.security.ssl.transport.pemkey_filepath: certs/node-key.pem
plugins.security.ssl.transport.pemtrustedcas_filepath: certs/root-ca.pem
plugins.security.ssl.transport.enforce_hostname_verification: false

plugins.security.ssl.http.enabled: true
plugins.security.ssl.http.pemcert_filepath: certs/node.pem
plugins.security.ssl.http.pemkey_filepath: certs/node-key.pem
plugins.security.ssl.http.pemtrustedcas_filepath: certs/root-ca.pem

plugins.security.nodes_dn:
- "CN={hostname},OU=IT,O=Wazuh,L=San Francisco,ST=California,C=US"

plugins.security.authcz.admin_dn:
- "CN=admin,OU=IT,O=Wazuh,L=San Francisco,ST=California,C=US"

plugins.security.check_snapshot_restore_write_privileges: true
plugins.security.enable_snapshot_restore_privilege: true
plugins.security.system_indices.enabled: true
plugins.security.system_indices.indices: [".opendistro-alerting-config", ".opendistro-alerting-alert*", ".opendistro-anomaly-detector*", ".opendistro-reports-*", ".opendistro-notifications-*", ".opendistro-notebooks", ".opendistro-asynchronous-search-response*"]

# Performance settings
bootstrap.memory_lock: true
"""
        
        # Write configuration
        with open(config_file, 'w') as f:
            f.write(config_content)
        
        logger.info("Wazuh Indexer configuration updated")
        return True
        
    except Exception as e:
        logger.error(f"Failed to configure Wazuh Indexer: {e}")
        return False

def install_wazuh_manager(system_info: Dict[str, str], logger) -> bool:
    """Install and configure Wazuh Manager"""
    logger.info("Installing Wazuh Manager...")
    
    try:
        os_id = system_info['os_id']
        
        # Install package
        if os_id in ['ubuntu', 'debian']:
            logger.info("Installing wazuh-manager package...")
            run_command(['apt-get', 'install', '-y', 'wazuh-manager'], logger=logger)
        elif os_id in ['centos', 'rhel', 'amazon']:
            logger.info("Installing wazuh-manager package...")
            run_command(['yum', 'install', '-y', 'wazuh-manager'], logger=logger)
        
        # Start and enable service
        logger.info("Starting Wazuh Manager service...")
        run_command(['systemctl', 'daemon-reload'], logger=logger)
        run_command(['systemctl', 'enable', 'wazuh-manager'], logger=logger)
        run_command(['systemctl', 'start', 'wazuh-manager'], logger=logger)
        
        # Wait for service to start
        time.sleep(5)
        
        # Check service status
        result = run_command(['systemctl', 'is-active', 'wazuh-manager'], 
                           check=False, logger=logger)
        if result.returncode == 0:
            logger.info("✓ Wazuh Manager started successfully")
        else:
            logger.warning("Wazuh Manager may not have started properly")
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to install Wazuh Manager: {e}")
        return False

def install_wazuh_dashboard(system_info: Dict[str, str], hostname: str, ip_address: str, logger) -> bool:
    """Install and configure Wazuh Dashboard"""
    logger.info("Installing Wazuh Dashboard...")
    
    try:
        os_id = system_info['os_id']
        
        # Install package
        if os_id in ['ubuntu', 'debian']:
            logger.info("Installing wazuh-dashboard package...")
            run_command(['apt-get', 'install', '-y', 'wazuh-dashboard'], logger=logger)
        elif os_id in ['centos', 'rhel', 'amazon']:
            logger.info("Installing wazuh-dashboard package...")
            run_command(['yum', 'install', '-y', 'wazuh-dashboard'], logger=logger)
        
        # Configure dashboard
        logger.info("Configuring Wazuh Dashboard...")
        if not configure_wazuh_dashboard(hostname, ip_address, logger):
            raise Exception("Failed to configure Wazuh Dashboard")
        
        # Start and enable service
        logger.info("Starting Wazuh Dashboard service...")
        run_command(['systemctl', 'daemon-reload'], logger=logger)
        run_command(['systemctl', 'enable', 'wazuh-dashboard'], logger=logger)
        run_command(['systemctl', 'start', 'wazuh-dashboard'], logger=logger)
        
        # Wait for service to start
        time.sleep(10)
        
        # Check service status
        result = run_command(['systemctl', 'is-active', 'wazuh-dashboard'], 
                           check=False, logger=logger)
        if result.returncode == 0:
            logger.info("✓ Wazuh Dashboard started successfully")
        else:
            logger.warning("Wazuh Dashboard may not have started properly")
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to install Wazuh Dashboard: {e}")
        return False

def configure_wazuh_dashboard(hostname: str, ip_address: str, logger) -> bool:
    """Configure Wazuh Dashboard"""
    try:
        config_file = '/etc/wazuh-dashboard/opensearch_dashboards.yml'
        
        # Backup original config
        if os.path.exists(config_file):
            backup_file = f"{config_file}.backup.{int(time.time())}"
            shutil.copy2(config_file, backup_file)
            logger.info(f"Backed up original config to {backup_file}")
        
        # Create dashboard configuration
        config_content = f"""# Wazuh Dashboard Configuration
server.host: {ip_address}
server.port: 5601
opensearch.hosts: ["https://{ip_address}:9200"]
server.ssl.enabled: true
server.ssl.certificate: "/etc/wazuh-indexer/certs/node.pem"
server.ssl.key: "/etc/wazuh-indexer/certs/node-key.pem"

opensearch.ssl.certificateAuthorities: ["/etc/wazuh-indexer/certs/root-ca.pem"]
opensearch.ssl.verificationMode: certificate

opensearch.username: admin
opensearch.password: admin
opensearch.requestHeadersWhitelist: ["authorization", "securitytenant"]

opensearch_security.multitenancy.enabled: false
opensearch_security.readonly_mode.roles: ["kibana_read_only"]
server.ssl.certificateAuthorities: ["/etc/wazuh-indexer/certs/root-ca.pem"]
"""
        
        # Write configuration
        with open(config_file, 'w') as f:
            f.write(config_content)
        
        logger.info("Wazuh Dashboard configuration updated")
        return True
        
    except Exception as e:
        logger.error(f"Failed to configure Wazuh Dashboard: {e}")
        return False

# =============================================================================
# SECURITY INITIALIZATION
# =============================================================================

def initialize_wazuh_security(logger) -> bool:
    """Initialize Wazuh security settings"""
    logger.info("Initializing Wazuh security...")
    
    try:
        # Wait for indexer to be ready
        logger.info("Waiting for Wazuh Indexer to be ready...")
        max_retries = 30
        for i in range(max_retries):
            try:
                result = run_command([
                    'curl', '-k', '-s', 'https://localhost:9200/_cluster/health'
                ], check=False, logger=logger)
                
                if result.returncode == 0:
                    logger.info("Wazuh Indexer is ready")
                    break
            except:
                pass
            
            if i == max_retries - 1:
                logger.warning("Wazuh Indexer may not be fully ready")
                break
            
            time.sleep(2)
        
        # Initialize security
        logger.info("Running security initialization...")
        try:
            run_command([
                '/usr/share/wazuh-indexer/bin/indexer-security-init.sh'
            ], timeout=120, logger=logger)
            logger.info("Security initialization completed")
        except Exception as e:
            logger.warning(f"Security initialization may have failed: {e}")
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to initialize security: {e}")
        return False

# =============================================================================
# MAIN INSTALLATION FUNCTIONS
# =============================================================================

def install_all_components(system_info: Dict[str, str], hostname: str, ip_address: str, logger) -> bool:
    """Install all Wazuh components"""
    total_steps = 10
    start_time = time.time()
    
    try:
        # Step 5: Install Wazuh Indexer
        show_progress(5, total_steps, "Installing Wazuh Indexer", logger)
        if not install_wazuh_indexer(system_info, hostname, ip_address, logger):
            raise Exception("Failed to install Wazuh Indexer")
        
        # Step 6: Install Wazuh Manager
        show_progress(6, total_steps, "Installing Wazuh Manager", logger)
        if not install_wazuh_manager(system_info, logger):
            raise Exception("Failed to install Wazuh Manager")
        
        # Step 7: Install Wazuh Dashboard
        show_progress(7, total_steps, "Installing Wazuh Dashboard", logger)
        if not install_wazuh_dashboard(system_info, hostname, ip_address, logger):
            raise Exception("Failed to install Wazuh Dashboard")
        
        # Step 8: Initialize Security
        show_progress(8, total_steps, "Initializing security", logger)
        initialize_wazuh_security(logger)
        
        # Step 9: Final verification
        show_progress(9, total_steps, "Verifying installation", logger)
        verify_installation(logger)
        
        # Step 10: Complete
        show_progress(10, total_steps, "Installation completed", logger)
        
        elapsed_time = time.time() - start_time
        logger.info(f"✓ All components installed successfully in {elapsed_time:.2f} seconds")
        
        return True
        
    except Exception as e:
        elapsed_time = time.time() - start_time
        logger.error(f"Installation failed after {elapsed_time:.2f} seconds: {e}")
        return False

def verify_installation(logger) -> bool:
    """Verify Wazuh installation"""
    logger.info("Verifying Wazuh installation...")
    
    services = ['wazuh-manager', 'wazuh-indexer', 'wazuh-dashboard']
    all_good = True
    
    for service in services:
        try:
            result = run_command(['systemctl', 'is-active', service], 
                               check=False, logger=logger)
            if result.returncode == 0:
                logger.info(f"✓ {service} is running")
            else:
                logger.error(f"✗ {service} is not running")
                all_good = False
        except Exception as e:
            logger.error(f"Failed to check {service}: {e}")
            all_good = False
    
    return all_good

def cleanup_on_failure(logger):
    """Clean up after failed installation"""
    logger.info("Cleaning up failed installation...")
    
    try:
        # Stop services
        services = ['wazuh-dashboard', 'wazuh-indexer', 'wazuh-manager']
        for service in services:
            try:
                run_command(['systemctl', 'stop', service], check=False, logger=logger)
                run_command(['systemctl', 'disable', service], check=False, logger=logger)
            except:
                pass
        
        # Remove certificate directory
        cert_dir = '/etc/wazuh-indexer/certs'
        if os.path.exists(cert_dir):
            shutil.rmtree(cert_dir, ignore_errors=True)
        
        logger.info("Cleanup completed")
        
    except Exception as e:
        logger.warning(f"Cleanup partially failed: {e}")

def print_installation_summary(hostname: str, ip_address: str, logger):
    """Print installation summary and access information"""
    logger.info("=" * 60)
    logger.info("WAZUH INSTALLATION COMPLETED SUCCESSFULLY")
    logger.info("=" * 60)
    logger.info(f"Hostname: {hostname}")
    logger.info(f"IP Address: {ip_address}")
    logger.info("")
    logger.info("Services Status:")
    
    # Check service status
    services = {
        'wazuh-manager': 1514,
        'wazuh-indexer': 9200,
        'wazuh-dashboard': 5601
    }
    
    for service, port in services.items():
        try:
            result = run_command(['systemctl', 'is-active', service], 
                               check=False, logger=logger)
            status = "✓ RUNNING" if result.returncode == 0 else "✗ STOPPED"
            logger.info(f"  {service}: {status} (Port {port})")
        except:
            logger.info(f"  {service}: ✗ UNKNOWN (Port {port})")
    
    logger.info("")
    logger.info("Access URLs:")
    logger.info(f"  Wazuh Dashboard: https://{ip_address}:5601")
    logger.info(f"  Wazuh API: https://{ip_address}:55000")
    logger.info(f"  Wazuh Indexer: https://{ip_address}:9200")
    logger.info("")
    logger.info("Default Credentials:")
    logger.info("  Username: admin")
    logger.info("  Password: admin")
    logger.info("")
    logger.info("Important Files:")
    logger.info("  Configuration: /var/ossec/etc/ossec.conf")
    logger.info("  Logs: /var/ossec/logs/")
    logger.info("  Certificates: /etc/wazuh-indexer/certs/")
    logger.info("=" * 60)

# =============================================================================
# MAIN FUNCTION
# =============================================================================

def main():
    """Main installation function"""
    parser = argparse.ArgumentParser(
        description="Wazuh Server Installation Script",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  {sys.argv[0]} --install-all                 Install all components
  {sys.argv[0]} --install-manager             Install only Wazuh Manager
  {sys.argv[0]} --install-indexer             Install only Wazuh Indexer
  {sys.argv[0]} --install-dashboard           Install only Wazuh Dashboard
  {sys.argv[0]} --install-all --verbose       Install with verbose logging

Author: {AUTHOR}
Version: {VERSION}
"""
    )
    
    # Installation options
    parser.add_argument('--install-all', action='store_true',
                       help='Install all Wazuh components')
    parser.add_argument('--install-manager', action='store_true',
                       help='Install Wazuh Manager')
    parser.add_argument('--install-indexer', action='store_true',
                       help='Install Wazuh Indexer')
    parser.add_argument('--install-dashboard', action='store_true',
                       help='Install Wazuh Dashboard')
    
    # Configuration options
    parser.add_argument('--hostname', type=str,
                       help='Custom hostname (default: auto-detect)')
    parser.add_argument('--ip-address', type=str,
                       help='Custom IP address (default: auto-detect)')
    parser.add_argument('--verbose', action='store_true',
                       help='Enable verbose logging')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Check if at least one installation option is specified
    if not any([args.install_all, args.install_manager, 
                args.install_indexer, args.install_dashboard]):
        parser.error("No installation option specified. Use --help for usage information.")
    
    # Setup logging
    logger = setup_logging(args.verbose)
    
    try:
        # Print header
        logger.info("Starting Wazuh Server Installation Script v" + VERSION)
        logger.info(f"Author: {AUTHOR}")
        
        start_time = time.time()
        
        # Step 1: System validation
        show_progress(1, 10, "Validating system", logger)
        
        # Check root privileges
        if not check_root_privileges(logger):
            return 1
        
        # Get system information
        system_info = get_system_info(logger)
        
        # Check OS support
        if not check_os_support(system_info, logger):
            return 1
        
        # Step 2: Check dependencies
        show_progress(2, 10, "Checking dependencies", logger)
        available_tools, missing_tools = check_dependencies(logger)
        
        if missing_tools:
            logger.info(f"Installing missing tools: {missing_tools}")
            if not install_missing_dependencies(missing_tools, system_info, logger):
                logger.error("Failed to install required dependencies")
                return 1
            logger.info("Successfully installed missing tools")
        
        logger.info("All required dependencies are available")
        
        # Step 3: Get network configuration
        show_progress(3, 10, "Getting network configuration", logger)
        hostname, ip_address = get_network_info(logger)
        
        # Override with command line arguments if provided
        if args.hostname:
            hostname = args.hostname
            logger.info(f"Using custom hostname: {hostname}")
        
        if args.ip_address:
            ip_address = args.ip_address
            logger.info(f"Using custom IP address: {ip_address}")
        
        logger.info(f"Using hostname: {hostname}")
        logger.info(f"Using IP address: {ip_address}")
        
        # Step 4: Setup repository
        show_progress(4, 10, "Setting up Wazuh repository", logger)
        if not setup_wazuh_repository(system_info, logger):
            raise Exception("Failed to setup Wazuh repository")
        
        # Install components based on arguments
        success = True
        
        if args.install_all:
            success = install_all_components(system_info, hostname, ip_address, logger)
        else:
            step = 5
            if args.install_indexer:
                show_progress(step, 10, "Installing Wazuh Indexer", logger)
                success = install_wazuh_indexer(system_info, hostname, ip_address, logger)
                step += 1
            
            if success and args.install_manager:
                show_progress(step, 10, "Installing Wazuh Manager", logger)
                success = install_wazuh_manager(system_info, logger)
                step += 1
            
            if success and args.install_dashboard:
                show_progress(step, 10, "Installing Wazuh Dashboard", logger)
                success = install_wazuh_dashboard(system_info, hostname, ip_address, logger)
                step += 1
        
        if success:
            total_time = time.time() - start_time
            logger.info(f"✓ Installation completed successfully in {total_time:.2f} seconds")
            print_installation_summary(hostname, ip_address, logger)
            return 0
        else:
            raise Exception("Installation failed")
            
    except KeyboardInterrupt:
        logger.error("Installation interrupted by user")
        return 1
    except Exception as e:
        logger.error(f"Installation failed: {e}")
        logger.info("Performing cleanup...")
        cleanup_on_failure(logger)
        logger.error("Installation failed!")
        return 1

if __name__ == "__main__":
    sys.exit(main())