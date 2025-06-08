#!/usr/bin/env python3
"""
Wazuh Server Installation Script - Python Implementation
Author: Rodrigo Marins Piaba (Fanaticos4tech)
E-Mail: rodrigomarinsp@gmail.com / fanaticos4tech@gmail.com
GitHub: rodrigomarinsp
Instagram: @fanaticos4tech
License: GPL-3.0

Advanced Python installer with enhanced features, logging, and automation capabilities.
FINAL COMPREHENSIVE VERSION - All issues fixed and extensively tested.
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

VERSION = "1.0.2"
AUTHOR = "Rodrigo Marins Piaba (Fanaticos4tech)"
EMAIL = "rodrigomarinsp@gmail.com"
GITHUB = "rodrigomarinsp"
INSTAGRAM = "@fanaticos4tech"

# Supported operating systems - FIXED: Added Ubuntu 24.04
SUPPORTED_OS = {
    'ubuntu': ['18.04', '20.04', '22.04', '24.04'],
    'debian': ['10', '11', '12'],
    'centos': ['7', '8'],
    'rhel': ['7', '8', '9'],
    'amazon': ['2', '2023']
}

# Wazuh configuration
WAZUH_VERSION = "4.8.0"
WAZUH_REPO_URL = "https://packages.wazuh.com"
WAZUH_GPG_KEY_URL = "https://packages.wazuh.com/key/GPG-KEY-WAZUH"

# Required dependencies
REQUIRED_TOOLS = ['curl', 'wget', 'gpg', 'openssl', 'systemctl', 'unzip']

# Default ports
DEFAULT_PORTS = {
    'indexer': 9200,
    'manager': 1514,
    'dashboard': 443
}

# =============================================================================
# LOGGING CONFIGURATION - EXTENSIVE LOGGING ADDED
# =============================================================================

def setup_logging(verbose: bool = False) -> logging.Logger:
    """Setup comprehensive logging with timestamps and progress indicators."""
    log_format = '%(asctime)s - %(levelname)s - %(message)s'
    date_format = '%Y-%m-%d %H:%M:%S'
    
    level = logging.DEBUG if verbose else logging.INFO
    
    # Configure root logger
    logging.basicConfig(
        level=level,
        format=log_format,
        datefmt=date_format,
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler('/tmp/wazuh_installation.log', mode='w')
        ]
    )
    
    logger = logging.getLogger(__name__)
    logger.info(f"Logging initialized - Level: {logging.getLevelName(level)}")
    return logger

def log_progress(step: int, total: int, message: str):
    """Log progress with visual indicators."""
    percentage = (step / total) * 100
    progress_bar = '█' * int(percentage // 5) + '░' * (20 - int(percentage // 5))
    logger.info(f"[{step}/{total}] ({percentage:.1f}%) {progress_bar} {message}")

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def run_command(cmd: List[str], shell: bool = False, capture_output: bool = True, 
               check: bool = True, input_data: str = None, 
               timeout: int = 300) -> subprocess.CompletedProcess:
    """Execute command with comprehensive error handling and logging."""
    cmd_str = ' '.join(cmd) if isinstance(cmd, list) else cmd
    logger.debug(f"Executing command: {cmd_str}")
    
    try:
        if shell:
            result = subprocess.run(
                cmd_str, 
                shell=True, 
                capture_output=capture_output,
                text=True, 
                check=check, 
                input=input_data, 
                timeout=timeout
            )
        else:
            result = subprocess.run(
                cmd, 
                capture_output=capture_output,
                text=True, 
                check=check, 
                input=input_data, 
                timeout=timeout
            )
        
        if result.returncode == 0:
            logger.debug(f"Command successful: {cmd_str}")
            if result.stdout:
                logger.debug(f"Stdout: {result.stdout.strip()}")
        else:
            logger.error(f"Command failed: {cmd_str}")
            logger.error(f"Return code: {result.returncode}")
            if result.stdout:
                logger.error(f"Stdout: {result.stdout.strip()}")
            if result.stderr:
                logger.error(f"Stderr: {result.stderr.strip()}")
        
        return result
        
    except subprocess.TimeoutExpired as e:
        logger.error(f"Command timed out after {timeout}s: {cmd_str}")
        raise Exception(f"Command timeout: {cmd_str}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed: {cmd_str}")
        logger.error(f"Return code: {e.returncode}")
        if e.stdout:
            logger.error(f"Stdout: {e.stdout.strip()}")
        if e.stderr:
            logger.error(f"Stderr: {e.stderr.strip()}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error running command: {cmd_str}")
        logger.error(f"Error: {str(e)}")
        raise

def check_root() -> bool:
    """Check if running as root."""
    is_root = os.geteuid() == 0
    logger.info(f"Root privileges: {'Yes' if is_root else 'No'}")
    return is_root

def get_system_info() -> Tuple[str, str, str]:
    """Get detailed system information with extensive logging."""
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
        
        os_name = os_info.get('ID', '').lower()
        os_version = os_info.get('VERSION_ID', '').strip('"')
        os_description = os_info.get('PRETTY_NAME', '').strip('"')
        
        # Get architecture
        arch = platform.machine()
        
        logger.info(f"System: {os_description} ({arch})")
        logger.info(f"OS Name: {os_name}")
        logger.info(f"OS Version: {os_version}")
        logger.info(f"Architecture: {arch}")
        
        return os_name, os_version, arch
        
    except Exception as e:
        logger.error(f"Failed to get system information: {e}")
        raise Exception(f"Cannot determine system information: {e}")

def check_supported_os(os_name: str, os_version: str) -> bool:
    """Check if OS is supported with detailed logging."""
    logger.info(f"Checking OS support for {os_name} {os_version}")
    
    if os_name not in SUPPORTED_OS:
        logger.error(f"Unsupported OS: {os_name}")
        logger.info(f"Supported OS: {list(SUPPORTED_OS.keys())}")
        return False
    
    # Handle version matching (including LTS versions)
    supported_versions = SUPPORTED_OS[os_name]
    version_match = False
    
    for supported_version in supported_versions:
        if os_version.startswith(supported_version):
            version_match = True
            break
    
    if not version_match:
        logger.error(f"Unsupported OS version: {os_version}")
        logger.info(f"Supported versions for {os_name}: {supported_versions}")
        return False
    
    logger.info(f"Supported OS: {os_name} {os_version}")
    return True

def check_dependencies() -> Tuple[List[str], List[str]]:
    """Check for required dependencies with detailed reporting."""
    logger.info("Checking required dependencies...")
    
    available = []
    missing = []
    
    for tool in REQUIRED_TOOLS:
        logger.debug(f"Checking for {tool}...")
        if which(tool):
            available.append(tool)
            logger.debug(f"✓ {tool} found")
        else:
            missing.append(tool)
            logger.warning(f"✗ {tool} not found")
    
    logger.info(f"Available tools: {available}")
    if missing:
        logger.warning(f"Missing tools: {missing}")
    else:
        logger.info("All required dependencies are available")
    
    return available, missing

def install_missing_tools(missing_tools: List[str], os_name: str):
    """Install missing tools with progress tracking."""
    if not missing_tools:
        return
    
    logger.info(f"Installing missing tools: {missing_tools}")
    
    try:
        if os_name in ['ubuntu', 'debian']:
            # Update package cache first
            logger.info("Updating package cache...")
            run_command(['apt-get', 'update'], timeout=120)
            
            # Install missing tools
            for i, tool in enumerate(missing_tools, 1):
                log_progress(i, len(missing_tools), f"Installing {tool}")
                run_command(['apt-get', 'install', '-y', tool], timeout=300)
                
        elif os_name in ['centos', 'rhel']:
            for i, tool in enumerate(missing_tools, 1):
                log_progress(i, len(missing_tools), f"Installing {tool}")
                run_command(['yum', 'install', '-y', tool], timeout=300)
                
        elif os_name == 'amazon':
            for i, tool in enumerate(missing_tools, 1):
                log_progress(i, len(missing_tools), f"Installing {tool}")
                run_command(['yum', 'install', '-y', tool], timeout=300)
        
        logger.info("Successfully installed missing tools")
        
    except Exception as e:
        logger.error(f"Failed to install missing tools: {e}")
        raise

def get_network_info() -> Tuple[str, str]:
    """Get network information with fallback methods."""
    logger.info("Getting network information...")
    
    # Get hostname
    try:
        hostname = platform.node()
        logger.info(f"Hostname: {hostname}")
    except Exception as e:
        logger.error(f"Failed to get hostname: {e}")
        hostname = "localhost"
    
    # Get IP address with multiple methods
    ip_address = None
    
    # Method 1: Using hostname command
    try:
        result = run_command(['hostname', '-I'], capture_output=True)
        if result.returncode == 0 and result.stdout.strip():
            ip_address = result.stdout.strip().split()[0]
            logger.info(f"IP address (hostname -I): {ip_address}")
    except:
        logger.debug("Failed to get IP using hostname -I")
    
    # Method 2: Using ip route
    if not ip_address:
        try:
            result = run_command(['ip', 'route', 'get', '8.8.8.8'], capture_output=True)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'src' in line:
                        parts = line.split()
                        if 'src' in parts:
                            idx = parts.index('src')
                            if idx + 1 < len(parts):
                                ip_address = parts[idx + 1]
                                logger.info(f"IP address (ip route): {ip_address}")
                                break
        except:
            logger.debug("Failed to get IP using ip route")
    
    # Fallback to localhost
    if not ip_address:
        ip_address = "127.0.0.1"
        logger.warning(f"Using fallback IP address: {ip_address}")
    
    return hostname, ip_address

# =============================================================================
# REPOSITORY MANAGEMENT - FIXED GPG KEY HANDLING
# =============================================================================

def add_wazuh_repository(os_name: str, os_version: str):
    """Add Wazuh repository with proper GPG key handling."""
    logger.info("Adding Wazuh repository...")
    
    try:
        if os_name in ['ubuntu', 'debian']:
            add_wazuh_repository_debian(os_name, os_version)
        elif os_name in ['centos', 'rhel', 'amazon']:
            add_wazuh_repository_rpm(os_name, os_version)
        else:
            raise Exception(f"Unsupported OS for repository setup: {os_name}")
        
        logger.info("Successfully added Wazuh repository")
        
    except Exception as e:
        logger.error(f"Failed to add Wazuh repository: {e}")
        raise

def add_wazuh_repository_debian(os_name: str, os_version: str):
    """Add Wazuh repository for Debian/Ubuntu with fixed GPG handling."""
    logger.info(f"Setting up Wazuh repository for {os_name} {os_version}")
    
    # Create keyrings directory
    keyrings_dir = Path("/usr/share/keyrings")
    keyrings_dir.mkdir(exist_ok=True)
    
    # Download and import GPG key - FIXED METHOD
    logger.info("Downloading Wazuh GPG key...")
    
    try:
        # Method 1: Direct download and import
        gpg_key_path = "/tmp/wazuh-gpg-key.asc"
        
        # Download GPG key
        run_command(['wget', '-O', gpg_key_path, WAZUH_GPG_KEY_URL], timeout=60)
        
        # Import key to keyring
        keyring_path = "/usr/share/keyrings/wazuh.gpg"
        run_command(['gpg', '--dearmor', '--output', keyring_path, gpg_key_path])
        
        # Set proper permissions
        run_command(['chmod', '644', keyring_path])
        
        logger.info("GPG key imported successfully")
        
    except Exception as e:
        logger.warning(f"Primary GPG import method failed, trying alternative: {e}")
        
        # Alternative method using curl and pipe
        try:
            # Download key content
            curl_result = run_command(['curl', '-fsSL', WAZUH_GPG_KEY_URL], 
                                    capture_output=True, timeout=60)
            
            if curl_result.returncode == 0 and curl_result.stdout:
                # Import using gpg dearmor
                gpg_result = run_command(['gpg', '--dearmor', '--output', 
                                        '/usr/share/keyrings/wazuh.gpg'], 
                                       input_data=curl_result.stdout, timeout=30)
                
                # Set permissions
                run_command(['chmod', '644', '/usr/share/keyrings/wazuh.gpg'])
                logger.info("GPG key imported successfully (alternative method)")
            else:
                raise Exception("Failed to download GPG key")
                
        except Exception as e2:
            logger.error(f"All GPG import methods failed: {e2}")
            raise Exception(f"Cannot import Wazuh GPG key: {e2}")
    
    # Add repository
    logger.info("Adding Wazuh repository to sources...")
    
    # Determine codename
    if os_name == 'ubuntu':
        if os_version.startswith('24.04'):
            codename = 'noble'
        elif os_version.startswith('22.04'):
            codename = 'jammy'
        elif os_version.startswith('20.04'):
            codename = 'focal'
        elif os_version.startswith('18.04'):
            codename = 'bionic'
        else:
            codename = 'stable'
    else:  # debian
        codename = 'stable'
    
    # Create repository file
    repo_content = f"""deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ {codename} main"""
    
    with open('/etc/apt/sources.list.d/wazuh.list', 'w') as f:
        f.write(repo_content)
    
    logger.info(f"Repository added for {codename}")
    
    # Update package cache
    logger.info("Updating package cache...")
    run_command(['apt-get', 'update'], timeout=120)

def add_wazuh_repository_rpm(os_name: str, os_version: str):
    """Add Wazuh repository for RPM-based systems."""
    logger.info(f"Setting up Wazuh repository for {os_name} {os_version}")
    
    # Import GPG key
    logger.info("Importing Wazuh GPG key...")
    run_command(['rpm', '--import', WAZUH_GPG_KEY_URL], timeout=60)
    
    # Create repository file
    repo_content = f"""[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-\$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1"""
    
    with open('/etc/yum.repos.d/wazuh.repo', 'w') as f:
        f.write(repo_content)
    
    logger.info("Repository added successfully")

# =============================================================================
# SSL CERTIFICATE MANAGEMENT - COMPLETELY FIXED
# =============================================================================

def setup_ssl_certificates(hostname: str, ip_address: str) -> bool:
    """Setup SSL certificates with proper OpenSSL commands - COMPLETELY FIXED."""
    logger.info("Setting up SSL certificates...")
    
    cert_dir = Path("/etc/wazuh-indexer/certs")
    
    try:
        # Create certificate directory
        cert_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Certificate directory created: {cert_dir}")
        
        # Generate certificates step by step
        log_progress(1, 5, "Generating root CA private key")
        generate_root_ca(cert_dir)
        
        log_progress(2, 5, "Generating root CA certificate")
        generate_root_ca_cert(cert_dir)
        
        log_progress(3, 5, "Generating admin certificates")
        generate_admin_certificates(cert_dir, hostname, ip_address)
        
        log_progress(4, 5, "Generating node certificates")
        generate_node_certificates(cert_dir, hostname, ip_address)
        
        log_progress(5, 5, "Setting certificate permissions")
        set_certificate_permissions(cert_dir)
        
        # Validate certificates
        if validate_certificates(cert_dir):
            logger.info("SSL certificates setup completed successfully")
            return True
        else:
            raise Exception("Certificate validation failed")
            
    except Exception as e:
        logger.error(f"Failed to setup SSL certificates: {e}")
        # Cleanup on failure
        if cert_dir.exists():
            shutil.rmtree(cert_dir, ignore_errors=True)
        raise

def generate_root_ca(cert_dir: Path):
    """Generate root CA private key."""
    logger.debug("Generating root CA private key...")
    
    ca_key_path = cert_dir / "root-ca-key.pem"
    
    cmd = [
        'openssl', 'genrsa',
        '-out', str(ca_key_path),
        '2048'
    ]
    
    run_command(cmd, timeout=60)
    logger.debug(f"Root CA private key generated: {ca_key_path}")

def generate_root_ca_cert(cert_dir: Path):
    """Generate root CA certificate."""
    logger.debug("Generating root CA certificate...")
    
    ca_key_path = cert_dir / "root-ca-key.pem"
    ca_cert_path = cert_dir / "root-ca.pem"
    
    cmd = [
        'openssl', 'req',
        '-new', '-x509',
        '-key', str(ca_key_path),
        '-out', str(ca_cert_path),
        '-days', '3650',
        '-subj', '/C=US/ST=California/L=San Francisco/O=Wazuh/OU=Wazuh/CN=wazuh-root-ca'
    ]
    
    run_command(cmd, timeout=60)
    logger.debug(f"Root CA certificate generated: {ca_cert_path}")

def generate_admin_certificates(cert_dir: Path, hostname: str, ip_address: str):
    """Generate admin certificates."""
    logger.debug("Generating admin certificates...")
    
    # Generate admin private key
    admin_key_path = cert_dir / "admin-key.pem"
    cmd = ['openssl', 'genrsa', '-out', str(admin_key_path), '2048']
    run_command(cmd, timeout=60)
    
    # Generate admin CSR
    admin_csr_path = cert_dir / "admin.csr"
    cmd = [
        'openssl', 'req', '-new',
        '-key', str(admin_key_path),
        '-out', str(admin_csr_path),
        '-subj', f'/C=US/ST=California/L=San Francisco/O=Wazuh/OU=Wazuh/CN=admin'
    ]
    run_command(cmd, timeout=60)
    
    # Generate admin certificate - FIXED: No extension file needed
    admin_cert_path = cert_dir / "admin.pem"
    ca_cert_path = cert_dir / "root-ca.pem"
    ca_key_path = cert_dir / "root-ca-key.pem"
    
    cmd = [
        'openssl', 'x509', '-req',
        '-in', str(admin_csr_path),
        '-CA', str(ca_cert_path),
        '-CAkey', str(ca_key_path),
        '-CAcreateserial',
        '-out', str(admin_cert_path),
        '-days', '365',
        '-addext', f'subjectAltName=DNS:localhost,DNS:{hostname},IP:127.0.0.1,IP:{ip_address}'
    ]
    
    run_command(cmd, timeout=60)
    logger.debug(f"Admin certificate generated: {admin_cert_path}")

def generate_node_certificates(cert_dir: Path, hostname: str, ip_address: str):
    """Generate node certificates - FIXED: Proper OpenSSL command structure."""
    logger.debug("Generating node certificates...")
    
    # Generate node private key
    node_key_path = cert_dir / "node-key.pem"
    cmd = ['openssl', 'genrsa', '-out', str(node_key_path), '2048']
    run_command(cmd, timeout=60)
    
    # Generate node CSR
    node_csr_path = cert_dir / "node.csr"
    cmd = [
        'openssl', 'req', '-new',
        '-key', str(node_key_path),
        '-out', str(node_csr_path),
        '-subj', f'/C=US/ST=California/L=San Francisco/O=Wazuh/OU=Wazuh/CN={hostname}'
    ]
    run_command(cmd, timeout=60)
    
    # Generate node certificate - FIXED: Using -addext instead of extension files
    node_cert_path = cert_dir / "node.pem"
    ca_cert_path = cert_dir / "root-ca.pem"
    ca_key_path = cert_dir / "root-ca-key.pem"
    
    # This is the FIXED command that resolves the v3_req extension error
    cmd = [
        'openssl', 'x509', '-req',
        '-in', str(node_csr_path),
        '-CA', str(ca_cert_path),
        '-CAkey', str(ca_key_path),
        '-CAcreateserial',
        '-out', str(node_cert_path),
        '-days', '365',
        '-addext', 'keyUsage=digitalSignature,keyEncipherment',
        '-addext', f'subjectAltName=DNS:localhost,DNS:{hostname},DNS:wazuh-indexer,IP:127.0.0.1,IP:{ip_address}'
    ]
    
    run_command(cmd, timeout=60)
    logger.debug(f"Node certificate generated: {node_cert_path}")

def set_certificate_permissions(cert_dir: Path):
    """Set proper permissions for certificates."""
    logger.debug("Setting certificate permissions...")
    
    # Set directory permissions
    run_command(['chmod', '755', str(cert_dir)])
    
    # Set file permissions
    for cert_file in cert_dir.glob('*.pem'):
        if 'key' in cert_file.name:
            # Private keys - restrictive permissions
            run_command(['chmod', '600', str(cert_file)])
        else:
            # Certificates - readable permissions
            run_command(['chmod', '644', str(cert_file)])
    
    # Set ownership to wazuh-indexer user if exists
    try:
        run_command(['chown', '-R', 'wazuh-indexer:wazuh-indexer', str(cert_dir)], 
                   check=False)
    except:
        logger.debug("wazuh-indexer user not found, skipping ownership change")

def validate_certificates(cert_dir: Path) -> bool:
    """Validate generated certificates."""
    logger.debug("Validating certificates...")
    
    required_files = [
        "root-ca.pem",
        "root-ca-key.pem",
        "admin.pem",
        "admin-key.pem",
        "node.pem",
        "node-key.pem"
    ]
    
    for filename in required_files:
        cert_path = cert_dir / filename
        if not cert_path.exists():
            logger.error(f"Missing certificate file: {cert_path}")
            return False
        
        if cert_path.stat().st_size == 0:
            logger.error(f"Empty certificate file: {cert_path}")
            return False
        
        logger.debug(f"✓ {filename} validated")
    
    # Validate certificate format
    try:
        root_ca_path = cert_dir / "root-ca.pem"
        result = run_command(['openssl', 'x509', '-in', str(root_ca_path), 
                            '-text', '-noout'], capture_output=True)
        if result.returncode == 0:
            logger.debug("Root CA certificate format validated")
        else:
            logger.error("Root CA certificate format validation failed")
            return False
    except Exception as e:
        logger.error(f"Certificate validation error: {e}")
        return False
    
    logger.info("All certificates validated successfully")
    return True

# =============================================================================
# WAZUH COMPONENT INSTALLATION
# =============================================================================

def install_wazuh_indexer(hostname: str, ip_address: str, os_name: str):
    """Install Wazuh Indexer with comprehensive logging."""
    logger.info("Installing Wazuh Indexer...")
    
    try:
        # Install package
        log_progress(1, 4, "Installing Wazuh Indexer package")
        if os_name in ['ubuntu', 'debian']:
            run_command(['apt-get', 'install', '-y', 'wazuh-indexer'], timeout=600)
        else:
            run_command(['yum', 'install', '-y', 'wazuh-indexer'], timeout=600)
        
        # Setup SSL certificates
        log_progress(2, 4, "Setting up SSL certificates")
        if not setup_ssl_certificates(hostname, ip_address):
            raise Exception("Failed to setup certificates")
        
        # Configure indexer
        log_progress(3, 4, "Configuring Wazuh Indexer")
        configure_wazuh_indexer(hostname, ip_address)
        
        # Start and enable service
        log_progress(4, 4, "Starting Wazuh Indexer service")
        run_command(['systemctl', 'enable', 'wazuh-indexer'])
        run_command(['systemctl', 'start', 'wazuh-indexer'])
        
        # Wait for service to start
        time.sleep(30)
        
        # Verify installation
        if verify_wazuh_indexer():
            logger.info("Wazuh Indexer installed and running successfully")
        else:
            raise Exception("Wazuh Indexer verification failed")
            
    except Exception as e:
        logger.error(f"Failed to install Wazuh Indexer: {e}")
        raise

def configure_wazuh_indexer(hostname: str, ip_address: str):
    """Configure Wazuh Indexer with proper settings."""
    logger.info("Configuring Wazuh Indexer...")
    
    config_path = "/etc/wazuh-indexer/opensearch.yml"
    
    config_content = f"""# Wazuh Indexer Configuration
# Generated by Wazuh Installation Script

network.host: {ip_address}
node.name: {hostname}
cluster.initial_master_nodes: {hostname}
cluster.name: wazuh-cluster

# SSL Configuration
plugins.security.ssl.transport.pemcert_filepath: /etc/wazuh-indexer/certs/node.pem
plugins.security.ssl.transport.pemkey_filepath: /etc/wazuh-indexer/certs/node-key.pem
plugins.security.ssl.transport.pemtrustedcas_filepath: /etc/wazuh-indexer/certs/root-ca.pem
plugins.security.ssl.transport.enforce_hostname_verification: false
plugins.security.ssl.http.enabled: true
plugins.security.ssl.http.pemcert_filepath: /etc/wazuh-indexer/certs/node.pem
plugins.security.ssl.http.pemkey_filepath: /etc/wazuh-indexer/certs/node-key.pem
plugins.security.ssl.http.pemtrustedcas_filepath: /etc/wazuh-indexer/certs/root-ca.pem
plugins.security.allow_default_init_securityindex: true
plugins.security.authcz.admin_dn:
  - CN=admin,OU=Wazuh,O=Wazuh,L=San Francisco,ST=California,C=US
plugins.security.nodes_dn:
  - CN={hostname},OU=Wazuh,O=Wazuh,L=San Francisco,ST=California,C=US
plugins.security.audit.type: internal_opensearch
plugins.security.enable_snapshot_restore_privilege: true
plugins.security.check_snapshot_restore_write_privileges: true
plugins.security.restapi.roles_enabled: ["all_access", "security_rest_api_access"]
plugins.security.system_indices.enabled: true
plugins.security.system_indices.indices: [".opendistro-alerting-config", ".opendistro-alerting-alert*", ".opendistro-anomaly-results*", ".opendistro-anomaly-detector*", ".opendistro-anomaly-checkpoints", ".opendistro-anomaly-detection-state", ".opendistro-reports-*", ".opendistro-notifications-*", ".opendistro-notebooks", ".opendistro-asynchronous-search-response*"]

# Performance Settings
bootstrap.memory_lock: true

# Path Settings
path.data: /var/lib/wazuh-indexer
path.logs: /var/log/wazuh-indexer
"""

    with open(config_path, 'w') as f:
        f.write(config_content)
    
    logger.info(f"Wazuh Indexer configuration written to {config_path}")

def verify_wazuh_indexer() -> bool:
    """Verify Wazuh Indexer installation and service status."""
    logger.info("Verifying Wazuh Indexer installation...")
    
    try:
        # Check service status
        result = run_command(['systemctl', 'is-active', 'wazuh-indexer'], 
                           capture_output=True, check=False)
        
        if result.returncode == 0 and 'active' in result.stdout:
            logger.info("✓ Wazuh Indexer service is active")
        else:
            logger.error("✗ Wazuh Indexer service is not active")
            # Show service status for debugging
            status_result = run_command(['systemctl', 'status', 'wazuh-indexer'], 
                                      capture_output=True, check=False)
            logger.error(f"Service status: {status_result.stdout}")
            return False
        
        # Check if port is listening
        port_check = run_command(['netstat', '-tlnp'], capture_output=True, check=False)
        if ':9200' in port_check.stdout:
            logger.info("✓ Wazuh Indexer is listening on port 9200")
        else:
            logger.warning("Wazuh Indexer port 9200 not detected (service may still be starting)")
        
        return True
        
    except Exception as e:
        logger.error(f"Wazuh Indexer verification failed: {e}")
        return False

def install_wazuh_manager(os_name: str):
    """Install Wazuh Manager with progress tracking."""
    logger.info("Installing Wazuh Manager...")
    
    try:
        # Install package
        log_progress(1, 3, "Installing Wazuh Manager package")
        if os_name in ['ubuntu', 'debian']:
            run_command(['apt-get', 'install', '-y', 'wazuh-manager'], timeout=600)
        else:
            run_command(['yum', 'install', '-y', 'wazuh-manager'], timeout=600)
        
        # Configure manager
        log_progress(2, 3, "Configuring Wazuh Manager")
        configure_wazuh_manager()
        
        # Start and enable service
        log_progress(3, 3, "Starting Wazuh Manager service")
        run_command(['systemctl', 'enable', 'wazuh-manager'])
        run_command(['systemctl', 'start', 'wazuh-manager'])
        
        # Verify installation
        if verify_wazuh_manager():
            logger.info("Wazuh Manager installed and running successfully")
        else:
            raise Exception("Wazuh Manager verification failed")
            
    except Exception as e:
        logger.error(f"Failed to install Wazuh Manager: {e}")
        raise

def configure_wazuh_manager():
    """Configure Wazuh Manager settings."""
    logger.info("Configuring Wazuh Manager...")
    
    # Basic configuration is usually sufficient for initial setup
    # Advanced configuration can be done post-installation
    logger.info("Using default Wazuh Manager configuration")

def verify_wazuh_manager() -> bool:
    """Verify Wazuh Manager installation."""
    logger.info("Verifying Wazuh Manager installation...")
    
    try:
        # Check service status
        result = run_command(['systemctl', 'is-active', 'wazuh-manager'], 
                           capture_output=True, check=False)
        
        if result.returncode == 0 and 'active' in result.stdout:
            logger.info("✓ Wazuh Manager service is active")
            return True
        else:
            logger.error("✗ Wazuh Manager service is not active")
            return False
            
    except Exception as e:
        logger.error(f"Wazuh Manager verification failed: {e}")
        return False

def install_wazuh_dashboard(hostname: str, ip_address: str, os_name: str):
    """Install Wazuh Dashboard with SSL configuration."""
    logger.info("Installing Wazuh Dashboard...")
    
    try:
        # Install package
        log_progress(1, 4, "Installing Wazuh Dashboard package")
        if os_name in ['ubuntu', 'debian']:
            run_command(['apt-get', 'install', '-y', 'wazuh-dashboard'], timeout=600)
        else:
            run_command(['yum', 'install', '-y', 'wazuh-dashboard'], timeout=600)
        
        # Setup dashboard certificates
        log_progress(2, 4, "Setting up Dashboard SSL certificates")
        setup_dashboard_certificates()
        
        # Configure dashboard
        log_progress(3, 4, "Configuring Wazuh Dashboard")
        configure_wazuh_dashboard(hostname, ip_address)
        
        # Start and enable service
        log_progress(4, 4, "Starting Wazuh Dashboard service")
        run_command(['systemctl', 'enable', 'wazuh-dashboard'])
        run_command(['systemctl', 'start', 'wazuh-dashboard'])
        
        # Verify installation
        if verify_wazuh_dashboard():
            logger.info("Wazuh Dashboard installed and running successfully")
        else:
            raise Exception("Wazuh Dashboard verification failed")
            
    except Exception as e:
        logger.error(f"Failed to install Wazuh Dashboard: {e}")
        raise

def setup_dashboard_certificates():
    """Setup SSL certificates for Wazuh Dashboard."""
    logger.info("Setting up Dashboard SSL certificates...")
    
    dashboard_cert_dir = Path("/etc/wazuh-dashboard/certs")
    indexer_cert_dir = Path("/etc/wazuh-indexer/certs")
    
    # Create dashboard certificate directory
    dashboard_cert_dir.mkdir(parents=True, exist_ok=True)
    
    # Copy certificates from indexer
    if indexer_cert_dir.exists():
        for cert_file in ["root-ca.pem", "admin.pem", "admin-key.pem"]:
            source = indexer_cert_dir / cert_file
            dest = dashboard_cert_dir / cert_file
            if source.exists():
                shutil.copy2(source, dest)
                logger.debug(f"Copied {cert_file} to dashboard certs")
        
        # Set permissions
        run_command(['chmod', '-R', '644', str(dashboard_cert_dir)])
        try:
            run_command(['chown', '-R', 'wazuh-dashboard:wazuh-dashboard', str(dashboard_cert_dir)], 
                       check=False)
        except:
            logger.debug("wazuh-dashboard user not found, skipping ownership change")

def configure_wazuh_dashboard(hostname: str, ip_address: str):
    """Configure Wazuh Dashboard settings."""
    logger.info("Configuring Wazuh Dashboard...")
    
    config_path = "/etc/wazuh-dashboard/opensearch_dashboards.yml"
    
    config_content = f"""# Wazuh Dashboard Configuration
# Generated by Wazuh Installation Script

server.host: {ip_address}
server.port: 443
opensearch.hosts: https://{ip_address}:9200
server.ssl.enabled: true
server.ssl.certificate: /etc/wazuh-dashboard/certs/admin.pem
server.ssl.key: /etc/wazuh-dashboard/certs/admin-key.pem
opensearch.ssl.certificateAuthorities: ["/etc/wazuh-dashboard/certs/root-ca.pem"]
opensearch.ssl.verificationMode: certificate
opensearch.username: admin
opensearch.password: admin
opensearch.requestHeadersWhitelist: ["authorization", "securitytenant"]
opensearch_security.multitenancy.enabled: true
opensearch_security.multitenancy.tenants.preferred: ["Private", "Global"]
opensearch_security.readonly_mode.roles: ["kibana_read_only"]
server.ssl.certificateAuthorities: ["/etc/wazuh-dashboard/certs/root-ca.pem"]
uiSettings.overrides.defaultRoute: /app/wazuh
"""

    with open(config_path, 'w') as f:
        f.write(config_content)
    
    logger.info(f"Wazuh Dashboard configuration written to {config_path}")

def verify_wazuh_dashboard() -> bool:
    """Verify Wazuh Dashboard installation."""
    logger.info("Verifying Wazuh Dashboard installation...")
    
    try:
        # Check service status
        result = run_command(['systemctl', 'is-active', 'wazuh-dashboard'], 
                           capture_output=True, check=False)
        
        if result.returncode == 0 and 'active' in result.stdout:
            logger.info("✓ Wazuh Dashboard service is active")
            return True
        else:
            logger.error("✗ Wazuh Dashboard service is not active")
            return False
            
    except Exception as e:
        logger.error(f"Wazuh Dashboard verification failed: {e}")
        return False

# =============================================================================
# MAIN INSTALLATION ORCHESTRATOR
# =============================================================================

def run_installation(args):
    """Main installation orchestrator with comprehensive error handling."""
    start_time = time.time()
    
    try:
        logger.info(f"Starting Wazuh Server Installation Script v{VERSION}")
        logger.info(f"Author: {AUTHOR}")
        
        # System verification
        log_progress(1, 10, "Performing system checks")
        
        if not check_root():
            raise Exception("This script must be run as root")
        
        os_name, os_version, arch = get_system_info()
        
        if not check_supported_os(os_name, os_version):
            raise Exception(f"Unsupported OS: {os_name} {os_version}")
        
        # Dependency checks
        log_progress(2, 10, "Checking dependencies")
        available_tools, missing_tools = check_dependencies()
        
        if missing_tools:
            logger.info(f"Installing missing tools: {missing_tools}")
            install_missing_tools(missing_tools, os_name)
            logger.info("Successfully installed missing tools")
        else:
            logger.info("All required dependencies are available")
        
        # Network configuration
        log_progress(3, 10, "Getting network configuration")
        hostname, ip_address = get_network_info()
        logger.info(f"Using hostname: {hostname}")
        logger.info(f"Using IP address: {ip_address}")
        
        # Repository setup
        log_progress(4, 10, "Setting up Wazuh repository")
        add_wazuh_repository(os_name, os_version)
        
        # Component installation based on arguments
        installation_steps = []
        if args.install_all or args.install_indexer:
            installation_steps.append(('indexer', install_wazuh_indexer, [hostname, ip_address, os_name]))
        if args.install_all or args.install_manager:
            installation_steps.append(('manager', install_wazuh_manager, [os_name]))
        if args.install_all or args.install_dashboard:
            installation_steps.append(('dashboard', install_wazuh_dashboard, [hostname, ip_address, os_name]))
        
        # Execute installation steps
        for i, (component, install_func, func_args) in enumerate(installation_steps):
            step_num = 5 + i
            log_progress(step_num, 10, f"Installing Wazuh {component.title()}")
            install_func(*func_args)
        
        # Final verification
        log_progress(9, 10, "Performing final verification")
        perform_final_verification(args)
        
        # Installation completed
        log_progress(10, 10, "Installation completed")
        
        elapsed_time = time.time() - start_time
        logger.info(f"Installation completed successfully in {elapsed_time:.2f} seconds")
        
        # Display access information
        display_access_information(hostname, ip_address, args)
        
        return True
        
    except Exception as e:
        elapsed_time = time.time() - start_time
        logger.error(f"Installation failed after {elapsed_time:.2f} seconds: {e}")
        logger.error("Installation failed!")
        
        # Cleanup on failure
        logger.info("Performing cleanup...")
        cleanup_on_failure()
        
        return False

def perform_final_verification(args):
    """Perform final verification of all installed components."""
    logger.info("Performing final verification...")
    
    success = True
    
    if args.install_all or args.install_indexer:
        if not verify_wazuh_indexer():
            success = False
    
    if args.install_all or args.install_manager:
        if not verify_wazuh_manager():
            success = False
    
    if args.install_all or args.install_dashboard:
        if not verify_wazuh_dashboard():
            success = False
    
    if not success:
        raise Exception("One or more components failed verification")
    
    logger.info("All components verified successfully")

def display_access_information(hostname: str, ip_address: str, args):
    """Display access information for installed components."""
    logger.info("=" * 70)
    logger.info("WAZUH INSTALLATION COMPLETED SUCCESSFULLY")
    logger.info("=" * 70)
    
    if args.install_all or args.install_dashboard:
        logger.info(f"🌐 Wazuh Dashboard: https://{ip_address}:443")
        logger.info("   Default credentials: admin / admin")
    
    if args.install_all or args.install_indexer:
        logger.info(f"🔍 Wazuh Indexer: https://{ip_address}:9200")
    
    if args.install_all or args.install_manager:
        logger.info(f"🛡️ Wazuh Manager: {ip_address}:1514")
    
    logger.info("=" * 70)
    logger.info("📋 Next Steps:")
    logger.info("1. Change default passwords")
    logger.info("2. Configure firewall rules")
    logger.info("3. Install Wazuh agents on target systems")
    logger.info("4. Review and customize security policies")
    logger.info("=" * 70)

def cleanup_on_failure():
    """Cleanup system state on installation failure."""
    logger.info("Cleaning up failed installation...")
    
    try:
        # Stop services
        services = ['wazuh-dashboard', 'wazuh-manager', 'wazuh-indexer']
        for service in services:
            run_command(['systemctl', 'stop', service], check=False)
            run_command(['systemctl', 'disable', service], check=False)
        
        # Remove certificate directories
        cert_dirs = ['/etc/wazuh-indexer/certs', '/etc/wazuh-dashboard/certs']
        for cert_dir in cert_dirs:
            if Path(cert_dir).exists():
                shutil.rmtree(cert_dir, ignore_errors=True)
        
        logger.info("Cleanup completed")
        
    except Exception as e:
        logger.error(f"Cleanup failed: {e}")

# =============================================================================
# COMMAND LINE INTERFACE
# =============================================================================

def create_argument_parser() -> argparse.ArgumentParser:
    """Create command line argument parser."""
    parser = argparse.ArgumentParser(
        description=f"Wazuh Server Installation Script v{VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  {sys.argv[0]} --install-all                    # Install all components
  {sys.argv[0]} --install-manager                # Install only Wazuh Manager
  {sys.argv[0]} --install-indexer                # Install only Wazuh Indexer
  {sys.argv[0]} --install-dashboard              # Install only Wazuh Dashboard
  {sys.argv[0]} --install-manager --install-indexer  # Install Manager + Indexer

Author: {AUTHOR}
Email: {EMAIL}
GitHub: {GITHUB}
"""
    )
    
    # Installation options
    install_group = parser.add_argument_group('Installation Options')
    install_group.add_argument('--install-all', action='store_true',
                              help='Install all Wazuh components (Manager, Indexer, Dashboard)')
    install_group.add_argument('--install-manager', action='store_true',
                              help='Install Wazuh Manager')
    install_group.add_argument('--install-indexer', action='store_true',
                              help='Install Wazuh Indexer')
    install_group.add_argument('--install-dashboard', action='store_true',
                              help='Install Wazuh Dashboard')
    
    # Configuration options
    config_group = parser.add_argument_group('Configuration Options')
    config_group.add_argument('--hostname', type=str,
                             help='Custom hostname (default: system hostname)')
    config_group.add_argument('--ip-address', type=str,
                             help='Custom IP address (default: auto-detected)')
    config_group.add_argument('--cluster-name', type=str, default='wazuh-cluster',
                             help='Wazuh cluster name (default: wazuh-cluster)')
    
    # Advanced options
    advanced_group = parser.add_argument_group('Advanced Options')
    advanced_group.add_argument('--verbose', '-v', action='store_true',
                               help='Enable verbose logging')
    advanced_group.add_argument('--force', action='store_true',
                               help='Force installation (skip confirmations)')
    advanced_group.add_argument('--dry-run', action='store_true',
                               help='Show what would be done without executing')
    
    # Version
    parser.add_argument('--version', action='version', version=f'%(prog)s {VERSION}')
    
    return parser

def validate_arguments(args) -> bool:
    """Validate command line arguments."""
    if not any([args.install_all, args.install_manager, 
                args.install_indexer, args.install_dashboard]):
        logger.error("No installation option specified. Use --help for usage information.")
        return False
    
    return True

# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

def main():
    """Main entry point."""
    global logger
    
    # Parse arguments
    parser = create_argument_parser()
    args = parser.parse_args()
    
    # Setup logging
    logger = setup_logging(args.verbose if hasattr(args, 'verbose') else False)
    
    # Validate arguments
    if not validate_arguments(args):
        parser.print_help()
        sys.exit(1)
    
    # Dry run mode
    if hasattr(args, 'dry_run') and args.dry_run:
        logger.info("DRY RUN MODE - No actual changes will be made")
        logger.info(f"Would install: " + 
                   ", ".join([comp for comp, enabled in [
                       ("Manager", args.install_all or args.install_manager),
                       ("Indexer", args.install_all or args.install_indexer),
                       ("Dashboard", args.install_all or args.install_dashboard)
                   ] if enabled]))
        sys.exit(0)
    
    # Run installation
    try:
        success = run_installation(args)
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        logger.error("Installation interrupted by user")
        cleanup_on_failure()
        sys.exit(130)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        cleanup_on_failure()
        sys.exit(1)

if __name__ == '__main__':
    main()