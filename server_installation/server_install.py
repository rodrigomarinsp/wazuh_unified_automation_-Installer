#!/usr/bin/env python3
"""
Wazuh Server Installation Script - Python Implementation (FIXED VERSION)
Author: Rodrigo Marins Piaba (Fanaticos4tech)
E-Mail: rodrigomarinsp@gmail.com / fanaticos4tech@gmail.com
GitHub: rodrigomarinsp
Instagram: @fanaticos4tech
License: GPL-3.0

## Advanced Python installer with enhanced features, logging, and automation capabilities.
## FIXED: OpenSSL certificate generation v3_req extension error resolved
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
AUTHOR = "Rodrigo Marins Piaba (Fixed by AI Assistant)"
EMAIL = "rodrigomarinsp@gmail.com"
GITHUB = "rodrigomarinsp"
LICENSE = "GPL-3.0"

# Wazuh Configuration
WAZUH_MAJOR_VERSION = "4.7"
WAZUH_FULL_VERSION = "4.7.2"
WAZUH_REVISION = "1"

# OpenSearch Configuration
OPENSEARCH_VERSION = "2.10.0"

# Installation paths
WAZUH_MANAGER_PATH = "/var/ossec"
WAZUH_INDEXER_PATH = "/etc/wazuh-indexer"
WAZUH_DASHBOARD_PATH = "/etc/wazuh-dashboard"
CERTIFICATES_PATH = "/etc/wazuh-indexer/certs"

# Network Configuration
DEFAULT_CLUSTER_KEY = "c98b62a9b6169ac5f67dae55ae4a9088"
DEFAULT_API_USER = "wazuh-wui"
DEFAULT_API_PASSWORD = "MyS3cr37P4ssw0rd*"

# Logging Configuration
LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
LOG_LEVEL = logging.INFO

# =============================================================================
# LOGGING SETUP
# =============================================================================

def setup_logging(log_file: str = None, verbose: bool = False) -> logging.Logger:
    """
    Setup logging configuration
    """
    level = logging.DEBUG if verbose else LOG_LEVEL
    
    # Create logger
    logger = logging.getLogger('wazuh_installer')
    logger.setLevel(level)
    
    # Create formatters
    formatter = logging.Formatter(LOG_FORMAT)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # File handler
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    return logger

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def run_command(
    command: List[str],
    cwd: str = None,
    check: bool = True,
    capture_output: bool = True,
    timeout: int = 300,
    logger: logging.Logger = None
) -> subprocess.CompletedProcess:
    """
    Execute a system command with proper error handling
    """
    if logger:
        logger.debug(f"Executing command: {' '.join(command)}")
    
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            check=check,
            capture_output=capture_output,
            text=True,
            timeout=timeout
        )
        
        if logger and result.stdout:
            logger.debug(f"Command output: {result.stdout}")
            
        return result
        
    except subprocess.CalledProcessError as e:
        if logger:
            logger.error(f"Command failed: {' '.join(command)}")
            logger.error(f"Return code: {e.returncode}")
            logger.error(f"Stdout: {e.stdout}")
            logger.error(f"Stderr: {e.stderr}")
        raise
    except subprocess.TimeoutExpired as e:
        if logger:
            logger.error(f"Command timed out: {' '.join(command)}")
        raise

def check_root_privileges(logger: logging.Logger) -> bool:
    """
    Check if script is running with root privileges
    """
    if os.geteuid() != 0:
        logger.error("This script must be run as root")
        return False
    return True

def get_system_info(logger: logging.Logger) -> Dict[str, str]:
    """
    Get system information
    """
    info = {
        'os': platform.system(),
        'distribution': '',
        'version': '',
        'architecture': platform.machine(),
        'kernel': platform.release()
    }
    
    try:
        # Try to get Linux distribution info
        if info['os'] == 'Linux':
            with open('/etc/os-release', 'r') as f:
                os_release = f.read()
                
            for line in os_release.split('\n'):
                if line.startswith('ID='):
                    info['distribution'] = line.split('=')[1].strip('"')
                elif line.startswith('VERSION_ID='):
                    info['version'] = line.split('=')[1].strip('"')
                    
    except Exception as e:
        logger.warning(f"Could not determine distribution info: {e}")
    
    logger.info(f"System: {info['distribution']} {info['version']} ({info['architecture']})")
    return info

def validate_dependencies(logger: logging.Logger) -> bool:
    """
    Validate required dependencies
    """
    required_commands = ['curl', 'wget', 'openssl', 'systemctl']
    missing_commands = []
    
    for cmd in required_commands:
        if not which(cmd):
            missing_commands.append(cmd)
    
    if missing_commands:
        logger.error(f"Missing required dependencies: {', '.join(missing_commands)}")
        return False
    
    logger.info("All required dependencies are available")
    return True

# =============================================================================
# CERTIFICATE MANAGEMENT (FIXED)
# =============================================================================

def create_ssl_config_files(cert_path: str, hostname: str, ip_address: str, logger: logging.Logger) -> bool:
    """
    Create SSL configuration files with proper format (FIXED)
    """
    try:
        # Create root CA configuration
        root_ca_config = f"""[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
prompt = no

[req_distinguished_name]
C = US
ST = California
L = San Francisco
O = Wazuh
OU = IT Department
CN = Wazuh Root CA

[v3_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
"""

        # Create node certificate configuration (FIXED v3_req section)
        node_config = f"""[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = California
L = San Francisco
O = Wazuh
OU = IT Department
CN = {hostname}

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation,digitalSignature,keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = {hostname}
DNS.2 = localhost
IP.1 = {ip_address}
IP.2 = 127.0.0.1
"""

        # Create admin certificate configuration
        admin_config = f"""[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = California
L = San Francisco
O = Wazuh
OU = IT Department
CN = admin

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation,digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth
"""

        # Write configuration files
        config_files = {
            'root-ca.conf': root_ca_config,
            'node.conf': node_config,
            'admin.conf': admin_config
        }
        
        for filename, content in config_files.items():
            config_path = os.path.join(cert_path, filename)
            with open(config_path, 'w') as f:
                f.write(content)
            logger.debug(f"Created SSL config file: {config_path}")
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to create SSL config files: {e}")
        return False

def generate_ssl_certificates(cert_path: str, hostname: str, ip_address: str, logger: logging.Logger) -> bool:
    """
    Generate SSL certificates for Wazuh indexer (FIXED)
    """
    try:
        # Create certificates directory
        os.makedirs(cert_path, mode=0o755, exist_ok=True)
        
        # Create SSL configuration files
        if not create_ssl_config_files(cert_path, hostname, ip_address, logger):
            return False
        
        logger.info("Generating SSL certificates...")
        
        # Generate Root CA private key
        run_command([
            'openssl', 'genrsa', '-out', 
            os.path.join(cert_path, 'root-ca-key.pem'), '4096'
        ], logger=logger)
        
        # Generate Root CA certificate
        run_command([
            'openssl', 'req', '-new', '-x509', '-days', '3650',
            '-config', os.path.join(cert_path, 'root-ca.conf'),
            '-key', os.path.join(cert_path, 'root-ca-key.pem'),
            '-out', os.path.join(cert_path, 'root-ca.pem')
        ], logger=logger)
        
        # Generate node private key
        run_command([
            'openssl', 'genrsa', '-out',
            os.path.join(cert_path, 'node-key.pem'), '4096'
        ], logger=logger)
        
        # Generate node certificate signing request
        run_command([
            'openssl', 'req', '-new',
            '-config', os.path.join(cert_path, 'node.conf'),
            '-key', os.path.join(cert_path, 'node-key.pem'),
            '-out', os.path.join(cert_path, 'node.csr')
        ], logger=logger)
        
        # Generate node certificate (FIXED - using proper config file)
        run_command([
            'openssl', 'x509', '-req', '-in', os.path.join(cert_path, 'node.csr'),
            '-CA', os.path.join(cert_path, 'root-ca.pem'),
            '-CAkey', os.path.join(cert_path, 'root-ca-key.pem'),
            '-CAcreateserial', '-out', os.path.join(cert_path, 'node.pem'),
            '-days', '365', '-extensions', 'v3_req',
            '-extfile', os.path.join(cert_path, 'node.conf')
        ], logger=logger)
        
        # Generate admin private key
        run_command([
            'openssl', 'genrsa', '-out',
            os.path.join(cert_path, 'admin-key.pem'), '4096'
        ], logger=logger)
        
        # Generate admin certificate signing request
        run_command([
            'openssl', 'req', '-new',
            '-config', os.path.join(cert_path, 'admin.conf'),
            '-key', os.path.join(cert_path, 'admin-key.pem'),
            '-out', os.path.join(cert_path, 'admin.csr')
        ], logger=logger)
        
        # Generate admin certificate
        run_command([
            'openssl', 'x509', '-req', '-in', os.path.join(cert_path, 'admin.csr'),
            '-CA', os.path.join(cert_path, 'root-ca.pem'),
            '-CAkey', os.path.join(cert_path, 'root-ca-key.pem'),
            '-CAcreateserial', '-out', os.path.join(cert_path, 'admin.pem'),
            '-days', '365', '-extensions', 'v3_req',
            '-extfile', os.path.join(cert_path, 'admin.conf')
        ], logger=logger)
        
        # Set proper permissions
        for cert_file in ['root-ca.pem', 'node.pem', 'admin.pem', 'node-key.pem', 'admin-key.pem', 'root-ca-key.pem']:
            cert_file_path = os.path.join(cert_path, cert_file)
            if os.path.exists(cert_file_path):
                os.chmod(cert_file_path, 0o644 if cert_file.endswith('.pem') and 'key' not in cert_file else 0o600)
        
        # Change ownership to wazuh-indexer user if exists
        try:
            run_command(['chown', '-R', 'wazuh-indexer:wazuh-indexer', cert_path], logger=logger)
        except subprocess.CalledProcessError:
            logger.warning("Could not change certificate ownership to wazuh-indexer user")
        
        logger.info("SSL certificates generated successfully")
        return True
        
    except Exception as e:
        logger.error(f"Failed to generate SSL certificates: {e}")
        return False

def validate_certificates(cert_path: str, logger: logging.Logger) -> bool:
    """
    Validate generated certificates
    """
    required_files = [
        'root-ca.pem',
        'root-ca-key.pem', 
        'node.pem',
        'node-key.pem',
        'admin.pem',
        'admin-key.pem'
    ]
    
    try:
        for cert_file in required_files:
            cert_file_path = os.path.join(cert_path, cert_file)
            if not os.path.exists(cert_file_path):
                logger.error(f"Missing certificate file: {cert_file_path}")
                return False
            
            # Validate certificate files
            if cert_file.endswith('.pem') and 'key' not in cert_file:
                result = run_command([
                    'openssl', 'x509', '-in', cert_file_path, '-text', '-noout'
                ], logger=logger, capture_output=True)
                if result.returncode != 0:
                    logger.error(f"Invalid certificate file: {cert_file_path}")
                    return False
        
        logger.info("All certificates validated successfully")
        return True
        
    except Exception as e:
        logger.error(f"Certificate validation failed: {e}")
        return False

# =============================================================================
# WAZUH REPOSITORY MANAGEMENT
# =============================================================================

def add_wazuh_repository(system_info: Dict[str, str], logger: logging.Logger) -> bool:
    """
    Add Wazuh repository to the system
    """
    try:
        logger.info("Adding Wazuh repository...")
        
        if system_info['distribution'] in ['ubuntu', 'debian']:
            # Install required packages
            run_command(['apt-get', 'update'], logger=logger)
            run_command(['apt-get', 'install', '-y', 'curl', 'apt-transport-https', 'lsb-release', 'gnupg'], logger=logger)
            
            # Add GPG key
            run_command([
                'curl', '-s', 'https://packages.wazuh.com/key/GPG-KEY-WAZUH',
                '|', 'gpg', '--no-default-keyring', '--keyring', 'gnupg-ring:/usr/share/keyrings/wazuh.gpg',
                '--import'
            ], logger=logger)
            
            # Add repository
            repo_line = f"deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/{WAZUH_MAJOR_VERSION}/apt/ stable main"
            with open('/etc/apt/sources.list.d/wazuh.list', 'w') as f:
                f.write(repo_line + '\n')
            
            run_command(['apt-get', 'update'], logger=logger)
            
        elif system_info['distribution'] in ['centos', 'rhel', 'fedora', 'rocky', 'almalinux']:
            # Add repository file
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
            
            # Import GPG key
            run_command(['rpm', '--import', 'https://packages.wazuh.com/key/GPG-KEY-WAZUH'], logger=logger)
            
        else:
            logger.error(f"Unsupported distribution: {system_info['distribution']}")
            return False
        
        logger.info("Wazuh repository added successfully")
        return True
        
    except Exception as e:
        logger.error(f"Failed to add Wazuh repository: {e}")
        return False

# =============================================================================
# WAZUH MANAGER INSTALLATION
# =============================================================================

def install_wazuh_manager(system_info: Dict[str, str], logger: logging.Logger) -> bool:
    """
    Install Wazuh Manager
    """
    try:
        logger.info("Installing Wazuh Manager...")
        
        if system_info['distribution'] in ['ubuntu', 'debian']:
            run_command(['apt-get', 'install', '-y', 'wazuh-manager'], logger=logger)
        elif system_info['distribution'] in ['centos', 'rhel', 'fedora', 'rocky', 'almalinux']:
            run_command(['yum', 'install', '-y', 'wazuh-manager'], logger=logger)
        
        # Enable and start service
        run_command(['systemctl', 'daemon-reload'], logger=logger)
        run_command(['systemctl', 'enable', 'wazuh-manager'], logger=logger)
        run_command(['systemctl', 'start', 'wazuh-manager'], logger=logger)
        
        logger.info("Wazuh Manager installed successfully")
        return True
        
    except Exception as e:
        logger.error(f"Failed to install Wazuh Manager: {e}")
        return False

def configure_wazuh_manager(cluster_key: str, logger: logging.Logger) -> bool:
    """
    Configure Wazuh Manager
    """
    try:
        logger.info("Configuring Wazuh Manager...")
        
        config_file = '/var/ossec/etc/ossec.conf'
        
        # Read current configuration
        with open(config_file, 'r') as f:
            config_content = f.read()
        
        # Update cluster configuration
        cluster_config = f"""  
    wazuh
    master
    master
    {cluster_key}
    1516
    0.0.0.0
    
        NODE_IP
    
    no
    no
  """
        
        # Replace existing cluster configuration or add if not exists
        if '' in config_content:
            # Replace existing cluster configuration
            import re
            config_content = re.sub(
                r'.*?',
                cluster_config,
                config_content,
                flags=re.DOTALL
            )
        else:
            # Add cluster configuration before closing ossec_config tag
            config_content = config_content.replace(
                '',
                cluster_config + '\n'
            )
        
        # Write updated configuration
        with open(config_file, 'w') as f:
            f.write(config_content)
        
        # Restart service
        run_command(['systemctl', 'restart', 'wazuh-manager'], logger=logger)
        
        logger.info("Wazuh Manager configured successfully")
        return True
        
    except Exception as e:
        logger.error(f"Failed to configure Wazuh Manager: {e}")
        return False

# =============================================================================
# WAZUH INDEXER INSTALLATION
# =============================================================================

def install_wazuh_indexer(system_info: Dict[str, str], logger: logging.Logger) -> bool:
    """
    Install Wazuh Indexer
    """
    try:
        logger.info("Installing Wazuh Indexer...")
        
        if system_info['distribution'] in ['ubuntu', 'debian']:
            run_command(['apt-get', 'install', '-y', 'wazuh-indexer'], logger=logger)
        elif system_info['distribution'] in ['centos', 'rhel', 'fedora', 'rocky', 'almalinux']:
            run_command(['yum', 'install', '-y', 'wazuh-indexer'], logger=logger)
        
        logger.info("Wazuh Indexer installed successfully")
        return True
        
    except Exception as e:
        logger.error(f"Failed to install Wazuh Indexer: {e}")
        return False

def configure_wazuh_indexer(hostname: str, ip_address: str, logger: logging.Logger) -> bool:
    """
    Configure Wazuh Indexer
    """
    try:
        logger.info("Configuring Wazuh Indexer...")
        
        config_file = '/etc/wazuh-indexer/opensearch.yml'
        
        # Backup original configuration
        if os.path.exists(config_file):
            shutil.copy(config_file, f"{config_file}.backup")
        
        # Create new configuration
        config_content = f"""network.host: {ip_address}
node.name: {hostname}
cluster.initial_master_nodes:
- {hostname}
cluster.name: wazuh-cluster

# TLS/SSL settings
plugins.security.ssl.transport.pemcert_filepath: {CERTIFICATES_PATH}/node.pem
plugins.security.ssl.transport.pemkey_filepath: {CERTIFICATES_PATH}/node-key.pem
plugins.security.ssl.transport.pemtrustedcas_filepath: {CERTIFICATES_PATH}/root-ca.pem
plugins.security.ssl.transport.enforce_hostname_verification: false
plugins.security.ssl.transport.resolve_hostname: false

plugins.security.ssl.http.enabled: true
plugins.security.ssl.http.pemcert_filepath: {CERTIFICATES_PATH}/node.pem
plugins.security.ssl.http.pemkey_filepath: {CERTIFICATES_PATH}/node-key.pem
plugins.security.ssl.http.pemtrustedcas_filepath: {CERTIFICATES_PATH}/root-ca.pem

plugins.security.allow_unsafe_democertificates: false
plugins.security.allow_default_init_securityindex: true
plugins.security.authcz.admin_dn:
- 'CN=admin,OU=IT Department,O=Wazuh,L=San Francisco,ST=California,C=US'

plugins.security.audit.type: internal_opensearch
plugins.security.enable_snapshot_restore_privilege: true
plugins.security.check_snapshot_restore_write_privileges: true
plugins.security.restapi.roles_enabled: ["all_access", "security_rest_api_access"]
plugins.security.system_indices.enabled: true
plugins.security.system_indices.indices: [".opendistro-alerting-config", ".opendistro-alerting-alert*", ".opendistro-anomaly-results*", ".opendistro-anomaly-detector*", ".opendistro-anomaly-checkpoints", ".opendistro-anomaly-detection-state", ".opendistro-reports-*", ".opendistro-notifications-*", ".opendistro-notebooks", ".opensearch-observability", ".opendistro-asynchronous-search-response*", ".replication-metadata-store"]

cluster.routing.allocation.disk.threshold_enabled: false
path.data: /var/lib/wazuh-indexer
path.logs: /var/log/wazuh-indexer

discovery.seed_hosts:
- {ip_address}

bootstrap.memory_lock: true
"""
        
        # Write configuration
        with open(config_file, 'w') as f:
            f.write(config_content)
        
        # Set proper permissions
        os.chmod(config_file, 0o660)
        try:
            run_command(['chown', 'wazuh-indexer:wazuh-indexer', config_file], logger=logger)
        except subprocess.CalledProcessError:
            logger.warning("Could not change configuration file ownership")
        
        logger.info("Wazuh Indexer configured successfully")
        return True
        
    except Exception as e:
        logger.error(f"Failed to configure Wazuh Indexer: {e}")
        return False

def start_wazuh_indexer(logger: logging.Logger) -> bool:
    """
    Start Wazuh Indexer service
    """
    try:
        logger.info("Starting Wazuh Indexer...")
        
        # Enable and start service
        run_command(['systemctl', 'daemon-reload'], logger=logger)
        run_command(['systemctl', 'enable', 'wazuh-indexer'], logger=logger)
        run_command(['systemctl', 'start', 'wazuh-indexer'], logger=logger)
        
        # Wait for service to start
        time.sleep(30)
        
        # Check service status
        result = run_command(['systemctl', 'is-active', 'wazuh-indexer'], logger=logger, check=False)
        if result.returncode == 0 and result.stdout.strip() == 'active':
            logger.info("Wazuh Indexer started successfully")
            return True
        else:
            logger.error("Wazuh Indexer failed to start properly")
            return False
        
    except Exception as e:
        logger.error(f"Failed to start Wazuh Indexer: {e}")
        return False

# =============================================================================
# WAZUH DASHBOARD INSTALLATION
# =============================================================================

def install_wazuh_dashboard(system_info: Dict[str, str], logger: logging.Logger) -> bool:
    """
    Install Wazuh Dashboard
    """
    try:
        logger.info("Installing Wazuh Dashboard...")
        
        if system_info['distribution'] in ['ubuntu', 'debian']:
            run_command(['apt-get', 'install', '-y', 'wazuh-dashboard'], logger=logger)
        elif system_info['distribution'] in ['centos', 'rhel', 'fedora', 'rocky', 'almalinux']:
            run_command(['yum', 'install', '-y', 'wazuh-dashboard'], logger=logger)
        
        logger.info("Wazuh Dashboard installed successfully")
        return True
        
    except Exception as e:
        logger.error(f"Failed to install Wazuh Dashboard: {e}")
        return False

def configure_wazuh_dashboard(hostname: str, ip_address: str, logger: logging.Logger) -> bool:
    """
    Configure Wazuh Dashboard
    """
    try:
        logger.info("Configuring Wazuh Dashboard...")
        
        config_file = '/etc/wazuh-dashboard/opensearch_dashboards.yml'
        
        # Backup original configuration
        if os.path.exists(config_file):
            shutil.copy(config_file, f"{config_file}.backup")
        
        # Create new configuration
        config_content = f"""server.host: {ip_address}
server.port: 443
opensearch.hosts: https://{ip_address}:9200
opensearch.ssl.verificationMode: certificate
opensearch.ssl.certificateAuthorities: ["{CERTIFICATES_PATH}/root-ca.pem"]
opensearch.ssl.certificate: "{CERTIFICATES_PATH}/node.pem"
opensearch.ssl.key: "{CERTIFICATES_PATH}/node-key.pem"
opensearch.username: kibanaserver
opensearch.password: kibanaserver
opensearch.requestHeadersWhitelist: ["authorization", "securitytenant"]

opensearch_security.multitenancy.enabled: true
opensearch_security.multitenancy.tenants.preferred: ["Private", "Global"]
opensearch_security.readonly_mode.roles: ["kibana_read_only"]

server.ssl.enabled: true
server.ssl.certificate: "{CERTIFICATES_PATH}/node.pem"
server.ssl.key: "{CERTIFICATES_PATH}/node-key.pem"

uiSettings.overrides.defaultRoute: /app/wz-home
"""
        
        # Write configuration
        with open(config_file, 'w') as f:
            f.write(config_content)
        
        # Set proper permissions
        os.chmod(config_file, 0o660)
        try:
            run_command(['chown', 'wazuh-dashboard:wazuh-dashboard', config_file], logger=logger)
        except subprocess.CalledProcessError:
            logger.warning("Could not change dashboard configuration file ownership")
        
        logger.info("Wazuh Dashboard configured successfully")
        return True
        
    except Exception as e:
        logger.error(f"Failed to configure Wazuh Dashboard: {e}")
        return False

def start_wazuh_dashboard(logger: logging.Logger) -> bool:
    """
    Start Wazuh Dashboard service
    """
    try:
        logger.info("Starting Wazuh Dashboard...")
        
        # Enable and start service
        run_command(['systemctl', 'daemon-reload'], logger=logger)
        run_command(['systemctl', 'enable', 'wazuh-dashboard'], logger=logger)
        run_command(['systemctl', 'start', 'wazuh-dashboard'], logger=logger)
        
        # Wait for service to start
        time.sleep(20)
        
        # Check service status
        result = run_command(['systemctl', 'is-active', 'wazuh-dashboard'], logger=logger, check=False)
        if result.returncode == 0 and result.stdout.strip() == 'active':
            logger.info("Wazuh Dashboard started successfully")
            return True
        else:
            logger.error("Wazuh Dashboard failed to start properly")
            return False
        
    except Exception as e:
        logger.error(f"Failed to start Wazuh Dashboard: {e}")
        return False

# =============================================================================
# INITIALIZATION AND SECURITY SETUP
# =============================================================================

def initialize_wazuh_indexer_security(logger: logging.Logger) -> bool:
    """
    Initialize Wazuh Indexer security
    """
    try:
        logger.info("Initializing Wazuh Indexer security...")
        
        # Run security initialization
        result = run_command([
            '/usr/share/wazuh-indexer/bin/indexer-security-init.sh',
            '-A', '-J', '-P', '-B', '-S', '-D', '-F'
        ], logger=logger, check=False, timeout=120)
        
        if result.returncode == 0:
            logger.info("Wazuh Indexer security initialized successfully")
            return True
        else:
            logger.warning("Security initialization completed with warnings")
            return True  # Often returns non-zero but still works
        
    except Exception as e:
        logger.error(f"Failed to initialize Wazuh Indexer security: {e}")
        return False

# =============================================================================
# MAIN INSTALLATION PROCESS
# =============================================================================

def main():
    """
    Main installation process
    """
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="Wazuh Server Installation Script (FIXED VERSION)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  {sys.argv[0]} --install-all
  {sys.argv[0]} --install-manager --install-indexer
  {sys.argv[0]} --install-dashboard --hostname myhost --ip 192.168.1.100

Author: {AUTHOR}
License: {LICENSE}
Version: {VERSION}
        """
    )
    
    parser.add_argument('--install-all', action='store_true',
                        help='Install all Wazuh components')
    parser.add_argument('--install-manager', action='store_true',
                        help='Install Wazuh Manager')
    parser.add_argument('--install-indexer', action='store_true',
                        help='Install Wazuh Indexer')
    parser.add_argument('--install-dashboard', action='store_true',
                        help='Install Wazuh Dashboard')
    parser.add_argument('--hostname', type=str,
                        help='Hostname for certificates')
    parser.add_argument('--ip', type=str,
                        help='IP address for binding')
    parser.add_argument('--cluster-key', type=str, default=DEFAULT_CLUSTER_KEY,
                        help='Cluster key for Manager')
    parser.add_argument('--log-file', type=str,
                        help='Log file path')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Enable verbose logging')
    parser.add_argument('--version', action='version', version=f'%(prog)s {VERSION}')
    
    args = parser.parse_args()
    
    # Setup logging
    logger = setup_logging(args.log_file, args.verbose)
    
    logger.info(f"Starting Wazuh Server Installation Script v{VERSION}")
    logger.info(f"Author: {AUTHOR}")
    
    # Check root privileges
    if not check_root_privileges(logger):
        sys.exit(1)
    
    # Get system information
    system_info = get_system_info(logger)
    
    # Validate dependencies
    if not validate_dependencies(logger):
        sys.exit(1)
    
    # Determine what to install
    install_manager = args.install_all or args.install_manager
    install_indexer = args.install_all or args.install_indexer
    install_dashboard = args.install_all or args.install_dashboard
    
    if not (install_manager or install_indexer or install_dashboard):
        logger.error("No installation option specified. Use --help for usage information.")
        sys.exit(1)
    
    # Get hostname and IP
    hostname = args.hostname or subprocess.getoutput('hostname -f')
    ip_address = args.ip or subprocess.getoutput("hostname -I | awk '{print $1}'")
    
    logger.info(f"Using hostname: {hostname}")
    logger.info(f"Using IP address: {ip_address}")
    
    try:
        # Add Wazuh repository
        if not add_wazuh_repository(system_info, logger):
            sys.exit(1)
        
        # Generate SSL certificates if indexer or dashboard will be installed
        if install_indexer or install_dashboard:
            if not generate_ssl_certificates(CERTIFICATES_PATH, hostname, ip_address, logger):
                logger.error("Failed to setup certificates")
                sys.exit(1)
            
            if not validate_certificates(CERTIFICATES_PATH, logger):
                logger.error("Certificate validation failed")
                sys.exit(1)
        
        # Install Wazuh Manager
        if install_manager:
            if not install_wazuh_manager(system_info, logger):
                sys.exit(1)
            
            if not configure_wazuh_manager(args.cluster_key, logger):
                sys.exit(1)
        
        # Install Wazuh Indexer
        if install_indexer:
            if not install_wazuh_indexer(system_info, logger):
                sys.exit(1)
            
            if not configure_wazuh_indexer(hostname, ip_address, logger):
                sys.exit(1)
            
            if not start_wazuh_indexer(logger):
                sys.exit(1)
            
            # Initialize security
            if not initialize_wazuh_indexer_security(logger):
                logger.warning("Security initialization failed, but continuing...")
        
        # Install Wazuh Dashboard
        if install_dashboard:
            if not install_wazuh_dashboard(system_info, logger):
                sys.exit(1)
            
            if not configure_wazuh_dashboard(hostname, ip_address, logger):
                sys.exit(1)
            
            if not start_wazuh_dashboard(logger):
                sys.exit(1)
        
        logger.info("="*60)
        logger.info("Wazuh installation completed successfully!")
        logger.info("="*60)
        
        if install_dashboard:
            logger.info(f"Wazuh Dashboard: https://{ip_address}")
            logger.info("Default credentials: admin / admin")
        
        if install_manager:
            logger.info(f"Wazuh Manager: {ip_address}:1514")
            logger.info("API: https://{ip_address}:55000")
        
        if install_indexer:
            logger.info(f"Wazuh Indexer: https://{ip_address}:9200")
        
        logger.info("="*60)
        
    except KeyboardInterrupt:
        logger.error("Installation interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Installation failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()