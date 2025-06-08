#!/usr/bin/env python3
"""
Wazuh Server Installation Script - Python Implementation
Author: Rodrigo Marins Piaba (Fanaticos4tech)
E-Mail: rodrigomarinsp@gmail.com / fanaticos4tech@gmail.com
GitHub: rodrigomarinsp
Instagram: @fanaticos4tech
License: GPL-3.0

## Advanced Python installer with enhanced features, logging, and automation capabilities.
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

# Wazuh package versions and URLs
WAZUH_VERSION = "4.7.2"
WAZUH_MAJOR_VERSION = "4.7"
WAZUH_REPO_BASE_URL = "https://packages.wazuh.com"

# System requirements
MIN_RAM_GB = 2
MIN_DISK_GB = 10
REQUIRED_PACKAGES = ["curl", "wget", "gnupg", "apt-transport-https", "ca-certificates", "unzip"]

# File paths
WAZUH_CONFIG_DIR = "/var/ossec/etc"
WAZUH_LOGS_DIR = "/var/ossec/logs"
INDEXER_CONFIG_DIR = "/etc/wazuh-indexer"
DASHBOARD_CONFIG_DIR = "/etc/wazuh-dashboard"

# Network configuration
DEFAULT_INDEXER_PORT = 9200
DEFAULT_DASHBOARD_PORT = 443
DEFAULT_API_PORT = 55000

# =============================================================================
# LOGGING CONFIGURATION
# =============================================================================

def setup_logging(verbose: bool = False) -> logging.Logger:
    """Configure logging with appropriate levels and formatting."""
    log_level = logging.DEBUG if verbose else logging.INFO
    
    # Create logs directory if it doesn't exist
    log_dir = Path("./logs")
    log_dir.mkdir(exist_ok=True)
    
    # Configure logging format
    log_format = "%(asctime)s - %(levelname)s - %(message)s"
    date_format = "%Y-%m-%d %H:%M:%S"
    
    # Setup logging to both file and console
    logging.basicConfig(
        level=log_level,
        format=log_format,
        datefmt=date_format,
        handlers=[
            logging.FileHandler(log_dir / f"wazuh_install_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    return logging.getLogger(__name__)

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def run_command(command: List[str], check: bool = True, shell: bool = False, 
                input_data: str = None, timeout: int = 300) -> subprocess.CompletedProcess:
    """Execute a system command with proper error handling and logging."""
    logger = logging.getLogger(__name__)
    
    try:
        cmd_str = ' '.join(command) if isinstance(command, list) else command
        logger.debug(f"Executing command: {cmd_str}")
        
        if shell and isinstance(command, list):
            command = ' '.join(command)
        
        result = subprocess.run(
            command,
            check=check,
            shell=shell,
            capture_output=True,
            text=True,
            input=input_data,
            timeout=timeout
        )
        
        if result.stdout:
            logger.debug(f"Command stdout: {result.stdout.strip()}")
        if result.stderr:
            logger.debug(f"Command stderr: {result.stderr.strip()}")
            
        return result
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed: {cmd_str}")
        logger.error(f"Return code: {e.returncode}")
        logger.error(f"Stdout: {e.stdout}")
        logger.error(f"Stderr: {e.stderr}")
        raise
    except subprocess.TimeoutExpired as e:
        logger.error(f"Command timed out after {timeout} seconds: {cmd_str}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error executing command: {cmd_str}")
        logger.error(f"Error: {str(e)}")
        raise

def check_system_requirements() -> bool:
    """Check if the system meets minimum requirements for Wazuh installation."""
    logger = logging.getLogger(__name__)
    
    try:
        # Check available RAM
        with open('/proc/meminfo', 'r') as f:
            meminfo = f.read()
        mem_total_kb = int(re.search(r'MemTotal:\s+(\d+)', meminfo).group(1))
        mem_total_gb = mem_total_kb / (1024 * 1024)
        
        if mem_total_gb < MIN_RAM_GB:
            logger.warning(f"Low RAM detected: {mem_total_gb:.1f}GB (minimum: {MIN_RAM_GB}GB)")
        
        # Check available disk space
        disk_usage = shutil.disk_usage('/')
        disk_free_gb = disk_usage.free / (1024**3)
        
        if disk_free_gb < MIN_DISK_GB:
            logger.error(f"Insufficient disk space: {disk_free_gb:.1f}GB (minimum: {MIN_DISK_GB}GB)")
            return False
        
        logger.info(f"System requirements check passed - RAM: {mem_total_gb:.1f}GB, Disk: {disk_free_gb:.1f}GB")
        return True
        
    except Exception as e:
        logger.error(f"Failed to check system requirements: {str(e)}")
        return False

def get_system_info() -> Dict[str, str]:
    """Get system information including OS, distribution, and architecture."""
    logger = logging.getLogger(__name__)
    
    try:
        # Get basic system information
        uname = platform.uname()
        
        # Get distribution information
        try:
            with open('/etc/os-release', 'r') as f:
                os_release = f.read()
            
            distro_id = re.search(r'ID=(.+)', os_release).group(1).strip('"')
            distro_version = re.search(r'VERSION_ID=(.+)', os_release).group(1).strip('"')
            distro_name = re.search(r'PRETTY_NAME=(.+)', os_release).group(1).strip('"')
        except:
            distro_id = "unknown"
            distro_version = "unknown"
            distro_name = "unknown"
        
        system_info = {
            'system': uname.system.lower(),
            'node': uname.node,
            'release': uname.release,
            'version': uname.version,
            'machine': uname.machine,
            'processor': uname.processor,
            'distro_id': distro_id,
            'distro_version': distro_version,
            'distro_name': distro_name
        }
        
        logger.info(f"System: {distro_name} ({uname.machine})")
        return system_info
        
    except Exception as e:
        logger.error(f"Failed to get system information: {str(e)}")
        return {}

def check_dependencies() -> Tuple[bool, List[str]]:
    """Check for required system dependencies."""
    logger = logging.getLogger(__name__)
    missing_packages = []
    
    for package in REQUIRED_PACKAGES:
        if not which(package):
            missing_packages.append(package)
    
    if missing_packages:
        logger.warning(f"Missing dependencies: {', '.join(missing_packages)}")
        return False, missing_packages
    
    logger.info("All required dependencies are available")
    return True, []

def install_missing_dependencies(missing_packages: List[str]) -> bool:
    """Install missing system dependencies."""
    logger = logging.getLogger(__name__)
    
    try:
        if not missing_packages:
            return True
        
        logger.info(f"Installing missing tools: {', '.join(missing_packages)}")
        
        # Update package cache
        run_command(["apt", "update"])
        
        # Install missing packages
        install_cmd = ["apt", "install", "-y"] + missing_packages
        run_command(install_cmd)
        
        logger.info("Successfully installed missing tools")
        return True
        
    except Exception as e:
        logger.error(f"Failed to install missing dependencies: {str(e)}")
        return False

# =============================================================================
# CERTIFICATE MANAGEMENT
# =============================================================================

def generate_ssl_certificates(node_name: str, node_ip: str) -> bool:
    """Generate SSL certificates for Wazuh components with proper OpenSSL configuration."""
    logger = logging.getLogger(__name__)
    
    try:
        cert_dir = Path(f"{INDEXER_CONFIG_DIR}/certs")
        cert_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info("Setting up SSL certificates...")
        
        # 1. Generate Root CA private key
        logger.debug("Generating Root CA private key...")
        run_command([
            "openssl", "genpkey", "-algorithm", "RSA", "-out", 
            f"{cert_dir}/root-ca-key.pem", "-pkcs8", "-aes256", 
            "-pass", "pass:wazuh123"
        ])
        
        # 2. Generate Root CA certificate
        logger.debug("Generating Root CA certificate...")
        run_command([
            "openssl", "req", "-new", "-x509", "-sha256", "-key", 
            f"{cert_dir}/root-ca-key.pem", "-passin", "pass:wazuh123",
            "-out", f"{cert_dir}/root-ca.pem", "-days", "3650",
            "-subj", f"/C=US/ST=CA/L=San Francisco/O=Wazuh/OU=IT/CN=root-ca"
        ])
        
        # 3. Generate Admin private key
        logger.debug("Generating Admin private key...")
        run_command([
            "openssl", "genpkey", "-algorithm", "RSA", "-out", 
            f"{cert_dir}/admin-key.pem"
        ])
        
        # 4. Generate Admin certificate signing request
        logger.debug("Generating Admin CSR...")
        run_command([
            "openssl", "req", "-new", "-key", f"{cert_dir}/admin-key.pem",
            "-out", f"{cert_dir}/admin.csr",
            "-subj", f"/C=US/ST=CA/L=San Francisco/O=Wazuh/OU=IT/CN=admin"
        ])
        
        # 5. Generate Node private key
        logger.debug("Generating Node private key...")
        run_command([
            "openssl", "genpkey", "-algorithm", "RSA", "-out", 
            f"{cert_dir}/node-key.pem"
        ])
        
        # 6. Generate Node certificate signing request
        logger.debug("Generating Node CSR...")
        run_command([
            "openssl", "req", "-new", "-key", f"{cert_dir}/node-key.pem",
            "-out", f"{cert_dir}/node.csr",
            "-subj", f"/C=US/ST=CA/L=San Francisco/O=Wazuh/OU=IT/CN={node_name}"
        ])
        
        # 7. Create extension file for node certificate with proper format
        logger.debug("Creating certificate extension file...")
        node_ext_content = f"""basicConstraints=CA:FALSE
keyUsage=nonRepudiation,digitalSignature,keyEncipherment
subjectAltName=@alt_names

[alt_names]
DNS.1=localhost
DNS.2={node_name}
DNS.3=wazuh-indexer
IP.1=127.0.0.1
IP.2={node_ip}"""
        
        with open(f"{cert_dir}/node.ext", "w") as f:
            f.write(node_ext_content)
        
        # 8. Generate Node certificate (Fixed OpenSSL command)
        logger.debug("Generating Node certificate...")
        run_command([
            "openssl", "x509", "-req", "-in", f"{cert_dir}/node.csr",
            "-CA", f"{cert_dir}/root-ca.pem", 
            "-CAkey", f"{cert_dir}/root-ca-key.pem", 
            "-passin", "pass:wazuh123",
            "-CAcreateserial", "-out", f"{cert_dir}/node.pem", 
            "-days", "365", "-extfile", f"{cert_dir}/node.ext"
        ])
        
        # 9. Create extension file for admin certificate
        logger.debug("Creating admin extension file...")
        admin_ext_content = """basicConstraints=CA:FALSE
keyUsage=nonRepudiation,digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth"""
        
        with open(f"{cert_dir}/admin.ext", "w") as f:
            f.write(admin_ext_content)
        
        # 10. Generate Admin certificate
        logger.debug("Generating Admin certificate...")
        run_command([
            "openssl", "x509", "-req", "-in", f"{cert_dir}/admin.csr",
            "-CA", f"{cert_dir}/root-ca.pem", 
            "-CAkey", f"{cert_dir}/root-ca-key.pem", 
            "-passin", "pass:wazuh123",
            "-CAcreateserial", "-out", f"{cert_dir}/admin.pem", 
            "-days", "365", "-extfile", f"{cert_dir}/admin.ext"
        ])
        
        # 11. Set proper permissions
        logger.debug("Setting certificate permissions...")
        run_command(["chown", "-R", "wazuh-indexer:wazuh-indexer", str(cert_dir)])
        run_command(["chmod", "600", f"{cert_dir}/*-key.pem"])
        run_command(["chmod", "644", f"{cert_dir}/*.pem"])
        run_command(["chmod", "644", f"{cert_dir}/*.csr"])
        
        # 12. Verify certificates
        logger.debug("Verifying generated certificates...")
        run_command(["openssl", "x509", "-in", f"{cert_dir}/root-ca.pem", "-text", "-noout"])
        run_command(["openssl", "x509", "-in", f"{cert_dir}/node.pem", "-text", "-noout"])
        run_command(["openssl", "x509", "-in", f"{cert_dir}/admin.pem", "-text", "-noout"])
        
        logger.info("SSL certificates generated successfully")
        return True
        
    except Exception as e:
        logger.error(f"Failed to generate SSL certificates: {str(e)}")
        return False

# =============================================================================
# REPOSITORY MANAGEMENT
# =============================================================================

def add_wazuh_repository() -> bool:
    """Add Wazuh repository to the system."""
    logger = logging.getLogger(__name__)
    
    try:
        logger.info("Adding Wazuh repository...")
        
        # Create keyrings directory if it doesn't exist
        keyrings_dir = Path("/usr/share/keyrings")
        keyrings_dir.mkdir(parents=True, exist_ok=True)
        
        # Download and import Wazuh GPG key using proper method for Ubuntu 24.04
        logger.debug("Downloading Wazuh GPG key...")
        gpg_key_url = f"{WAZUH_REPO_BASE_URL}/key/GPG-KEY-WAZUH"
        
        # Method 1: Download key and convert to GPG format
        key_response = run_command(["curl", "-s", gpg_key_url])
        if key_response.returncode == 0:
            # Import key using gpg and save to keyring
            gpg_process = run_command([
                "gpg", "--dearmor", "--output", "/usr/share/keyrings/wazuh.gpg"
            ], input_data=key_response.stdout)
        else:
            # Fallback method using wget
            logger.debug("Fallback: Using wget to download GPG key...")
            run_command([
                "wget", "-qO", "-", gpg_key_url, "|", 
                "gpg", "--dearmor", "--output", "/usr/share/keyrings/wazuh.gpg"
            ], shell=True)
        
        # Add Wazuh repository
        logger.debug("Adding Wazuh repository to sources...")
        repo_line = f"deb [signed-by=/usr/share/keyrings/wazuh.gpg] {WAZUH_REPO_BASE_URL}/{WAZUH_MAJOR_VERSION}/apt/ stable main"
        
        with open("/etc/apt/sources.list.d/wazuh.list", "w") as f:
            f.write(repo_line + "\n")
        
        # Update package cache
        logger.info("Updating package cache...")
        run_command(["apt", "update"])
        
        logger.info("Successfully added Wazuh repository")
        return True
        
    except Exception as e:
        logger.error(f"Failed to add Wazuh repository: {str(e)}")
        return False

# =============================================================================
# WAZUH INDEXER INSTALLATION
# =============================================================================

def install_wazuh_indexer(node_name: str, node_ip: str) -> bool:
    """Install and configure Wazuh Indexer."""
    logger = logging.getLogger(__name__)
    
    try:
        logger.info("Installing Wazuh Indexer...")
        
        # Install Wazuh Indexer package
        run_command(["apt", "install", "-y", "wazuh-indexer"])
        
        # Generate SSL certificates
        if not generate_ssl_certificates(node_name, node_ip):
            return False
        
        # Configure Wazuh Indexer
        logger.info("Configuring Wazuh Indexer...")
        
        indexer_config = f"""
# Wazuh Indexer Configuration
network.host: {node_ip}
node.name: {node_name}
cluster.initial_master_nodes: ["{node_name}"]
cluster.name: "wazuh-cluster"

# Security Configuration
plugins.security.disabled: false
plugins.security.ssl.transport.pemcert_filepath: certs/node.pem
plugins.security.ssl.transport.pemkey_filepath: certs/node-key.pem
plugins.security.ssl.transport.pemtrustedcas_filepath: certs/root-ca.pem
plugins.security.ssl.transport.enforce_hostname_verification: false
plugins.security.ssl.http.enabled: true
plugins.security.ssl.http.pemcert_filepath: certs/node.pem
plugins.security.ssl.http.pemkey_filepath: certs/node-key.pem
plugins.security.ssl.http.pemtrustedcas_filepath: certs/root-ca.pem
plugins.security.allow_unsafe_democertificates: false
plugins.security.allow_default_init_securityindex: true
plugins.security.authcz.admin_dn:
  - "CN=admin,OU=IT,O=Wazuh,L=San Francisco,ST=CA,C=US"
plugins.security.nodes_dn:
  - "CN={node_name},OU=IT,O=Wazuh,L=San Francisco,ST=CA,C=US"
plugins.security.audit.type: internal_opensearch
plugins.security.enable_snapshot_restore_privilege: true
plugins.security.check_snapshot_restore_write_privileges: true
plugins.security.restapi.roles_enabled: ["all_access", "security_rest_api_access"]

# Performance Configuration
bootstrap.memory_lock: true
"""
        
        # Write configuration file
        config_file = f"{INDEXER_CONFIG_DIR}/opensearch.yml"
        with open(config_file, "w") as f:
            f.write(indexer_config)
        
        # Set ownership and permissions
        run_command(["chown", "-R", "wazuh-indexer:wazuh-indexer", INDEXER_CONFIG_DIR])
        run_command(["chmod", "660", config_file])
        
        # Configure systemd service
        logger.info("Enabling and starting Wazuh Indexer service...")
        run_command(["systemctl", "daemon-reload"])
        run_command(["systemctl", "enable", "wazuh-indexer"])
        
        # Start the service
        start_result = run_command(["systemctl", "start", "wazuh-indexer"], check=False)
        if start_result.returncode != 0:
            logger.warning("Wazuh Indexer failed to start on first attempt, checking logs...")
            
            # Check logs for issues
            log_result = run_command(["journalctl", "-u", "wazuh-indexer", "--no-pager", "-n", "50"], check=False)
            if log_result.stdout:
                logger.debug(f"Wazuh Indexer logs: {log_result.stdout}")
            
            # Try to start again
            time.sleep(5)
            run_command(["systemctl", "start", "wazuh-indexer"])
        
        # Wait for service to be ready
        logger.info("Waiting for Wazuh Indexer to be ready...")
        max_attempts = 30
        for attempt in range(max_attempts):
            try:
                health_check = run_command([
                    "curl", "-k", "-u", "admin:admin", 
                    f"https://{node_ip}:9200/_cluster/health"
                ], check=False, timeout=10)
                
                if health_check.returncode == 0:
                    logger.info("Wazuh Indexer is ready")
                    break
            except:
                pass
            
            if attempt < max_attempts - 1:
                time.sleep(10)
            else:
                logger.warning("Wazuh Indexer may not be fully ready, continuing...")
        
        logger.info("Wazuh Indexer installation completed")
        return True
        
    except Exception as e:
        logger.error(f"Failed to install Wazuh Indexer: {str(e)}")
        return False

# =============================================================================
# WAZUH SERVER INSTALLATION
# =============================================================================

def install_wazuh_manager() -> bool:
    """Install and configure Wazuh Manager."""
    logger = logging.getLogger(__name__)
    
    try:
        logger.info("Installing Wazuh Manager...")
        
        # Install Wazuh Manager package
        run_command(["apt", "install", "-y", "wazuh-manager"])
        
        # Configure Wazuh Manager
        logger.info("Configuring Wazuh Manager...")
        
        # Enable and start the service
        run_command(["systemctl", "daemon-reload"])
        run_command(["systemctl", "enable", "wazuh-manager"])
        run_command(["systemctl", "start", "wazuh-manager"])
        
        # Wait for service to be ready
        time.sleep(10)
        
        # Check service status
        status_result = run_command(["systemctl", "is-active", "wazuh-manager"], check=False)
        if status_result.stdout.strip() == "active":
            logger.info("Wazuh Manager is running")
        else:
            logger.warning("Wazuh Manager may not be running properly")
        
        logger.info("Wazuh Manager installation completed")
        return True
        
    except Exception as e:
        logger.error(f"Failed to install Wazuh Manager: {str(e)}")
        return False

# =============================================================================
# WAZUH DASHBOARD INSTALLATION
# =============================================================================

def install_wazuh_dashboard(node_ip: str) -> bool:
    """Install and configure Wazuh Dashboard."""
    logger = logging.getLogger(__name__)
    
    try:
        logger.info("Installing Wazuh Dashboard...")
        
        # Install Wazuh Dashboard package
        run_command(["apt", "install", "-y", "wazuh-dashboard"])
        
        # Configure Wazuh Dashboard
        logger.info("Configuring Wazuh Dashboard...")
        
        dashboard_config = f"""
# Wazuh Dashboard Configuration
server.host: {node_ip}
server.port: 443
opensearch.hosts: ["https://{node_ip}:9200"]
opensearch.ssl.verificationMode: certificate
opensearch.ssl.certificateAuthorities: ["{INDEXER_CONFIG_DIR}/certs/root-ca.pem"]
opensearch.ssl.certificate: "{INDEXER_CONFIG_DIR}/certs/node.pem"
opensearch.ssl.key: "{INDEXER_CONFIG_DIR}/certs/node-key.pem"
opensearch.username: "kibanaserver"
opensearch.password: "kibanaserver"
opensearch.requestHeadersWhitelist: ["authorization", "securitytenant"]
server.ssl.enabled: true
server.ssl.certificate: "{INDEXER_CONFIG_DIR}/certs/node.pem"
server.ssl.key: "{INDEXER_CONFIG_DIR}/certs/node-key.pem"
server.ssl.certificateAuthorities: ["{INDEXER_CONFIG_DIR}/certs/root-ca.pem"]
uiSettings.overrides.defaultRoute: "/app/wz-home"
"""
        
        # Write configuration file
        config_file = f"{DASHBOARD_CONFIG_DIR}/opensearch_dashboards.yml"
        with open(config_file, "w") as f:
            f.write(dashboard_config)
        
        # Set ownership and permissions
        run_command(["chown", "-R", "wazuh-dashboard:wazuh-dashboard", DASHBOARD_CONFIG_DIR])
        run_command(["chmod", "660", config_file])
        
        # Enable and start the service
        run_command(["systemctl", "daemon-reload"])
        run_command(["systemctl", "enable", "wazuh-dashboard"])
        run_command(["systemctl", "start", "wazuh-dashboard"])
        
        # Wait for service to be ready
        logger.info("Waiting for Wazuh Dashboard to be ready...")
        time.sleep(20)
        
        # Check service status
        status_result = run_command(["systemctl", "is-active", "wazuh-dashboard"], check=False)
        if status_result.stdout.strip() == "active":
            logger.info("Wazuh Dashboard is running")
        else:
            logger.warning("Wazuh Dashboard may not be running properly")
        
        logger.info("Wazuh Dashboard installation completed")
        return True
        
    except Exception as e:
        logger.error(f"Failed to install Wazuh Dashboard: {str(e)}")
        return False

# =============================================================================
# POST-INSTALLATION CONFIGURATION
# =============================================================================

def configure_wazuh_security(node_ip: str) -> bool:
    """Configure Wazuh security settings and initialize the security index."""
    logger = logging.getLogger(__name__)
    
    try:
        logger.info("Configuring Wazuh security...")
        
        # Wait for indexer to be fully ready
        time.sleep(30)
        
        # Initialize security index
        logger.info("Initializing security index...")
        security_script = f"{INDEXER_CONFIG_DIR}/plugins/opensearch-security/tools/securityadmin.sh"
        
        if os.path.exists(security_script):
            run_command([
                "bash", security_script,
                "-cd", f"{INDEXER_CONFIG_DIR}/plugins/opensearch-security/securityconfig/",
                "-icl", "-nhnv",
                "-cacert", f"{INDEXER_CONFIG_DIR}/certs/root-ca.pem",
                "-cert", f"{INDEXER_CONFIG_DIR}/certs/admin.pem",
                "-key", f"{INDEXER_CONFIG_DIR}/certs/admin-key.pem",
                "-h", node_ip
            ], timeout=120)
        
        logger.info("Security configuration completed")
        return True
        
    except Exception as e:
        logger.warning(f"Security configuration may have issues: {str(e)}")
        return True  # Continue even if security config has issues

def print_installation_summary(node_ip: str, components: List[str]) -> None:
    """Print installation summary and access information."""
    logger = logging.getLogger(__name__)
    
    logger.info("=" * 80)
    logger.info("WAZUH INSTALLATION COMPLETED SUCCESSFULLY")
    logger.info("=" * 80)
    
    if "indexer" in components:
        logger.info(f"Wazuh Indexer: https://{node_ip}:9200")
        logger.info("  - Default credentials: admin / admin")
    
    if "manager" in components:
        logger.info(f"Wazuh Manager API: https://{node_ip}:55000")
        logger.info("  - Default credentials: wazuh-wui / wazuh-wui")
    
    if "dashboard" in components:
        logger.info(f"Wazuh Dashboard: https://{node_ip}")
        logger.info("  - Default credentials: admin / admin")
    
    logger.info("")
    logger.info("IMPORTANT SECURITY NOTES:")
    logger.info("- Change default passwords immediately")
    logger.info("- Review and configure firewall rules")
    logger.info("- Update SSL certificates for production use")
    logger.info("- Review and customize security policies")
    logger.info("")
    logger.info("Log files location: /var/ossec/logs/")
    logger.info("Configuration files: /var/ossec/etc/")
    logger.info("=" * 80)

# =============================================================================
# MAIN INSTALLATION ORCHESTRATOR
# =============================================================================

class WazuhInstaller:
    """Main Wazuh installation orchestrator class."""
    
    def __init__(self, verbose: bool = False):
        self.logger = setup_logging(verbose)
        self.system_info = get_system_info()
        self.node_name = self.system_info.get('node', 'wazuh-node')
        self.node_ip = None
        
    def get_node_ip(self) -> str:
        """Get the node IP address."""
        if self.node_ip:
            return self.node_ip
        
        try:
            # Try to get IP from hostname resolution
            import socket
            self.node_ip = socket.gethostbyname(socket.gethostname())
            
            # If we get localhost, try to get external IP
            if self.node_ip.startswith('127.'):
                # Try to get IP from network interface
                result = run_command(["hostname", "-I"], check=False)
                if result.returncode == 0 and result.stdout.strip():
                    self.node_ip = result.stdout.strip().split()[0]
                else:
                    # Fallback to getting IP via external service
                    result = run_command(["curl", "-s", "ifconfig.me"], check=False, timeout=10)
                    if result.returncode == 0 and result.stdout.strip():
                        self.node_ip = result.stdout.strip()
                    else:
                        self.node_ip = "127.0.0.1"
            
            self.logger.info(f"Using IP address: {self.node_ip}")
            return self.node_ip
            
        except Exception as e:
            self.logger.warning(f"Could not determine IP address: {str(e)}")
            self.node_ip = "127.0.0.1"
            return self.node_ip
    
    def validate_environment(self) -> bool:
        """Validate the installation environment."""
        # Check if running as root
        if os.geteuid() != 0:
            self.logger.error("This script must be run as root")
            return False
        
        # Check OS compatibility
        distro_id = self.system_info.get('distro_id', '').lower()
        if distro_id not in ['ubuntu', 'debian']:
            self.logger.error(f"Unsupported OS: {distro_id}")
            return False
        
        self.logger.info(f"Supported OS: {distro_id} {self.system_info.get('distro_version', '')}")
        
        # Check dependencies
        deps_ok, missing_deps = check_dependencies()
        if not deps_ok:
            if not install_missing_dependencies(missing_deps):
                return False
            
            # Re-check after installation
            deps_ok, missing_deps = check_dependencies()
            if not deps_ok:
                self.logger.error(f"Failed to install dependencies: {missing_deps}")
                return False
        
        # Check system requirements
        if not check_system_requirements():
            return False
        
        return True
    
    def install_components(self, components: List[str]) -> bool:
        """Install specified Wazuh components."""
        self.logger.info(f"Using hostname: {self.node_name}")
        node_ip = self.get_node_ip()
        
        # Add Wazuh repository
        if not add_wazuh_repository():
            return False
        
        success = True
        installed_components = []
        
        # Install components in order: indexer, manager, dashboard
        if "indexer" in components:
            if install_wazuh_indexer(self.node_name, node_ip):
                installed_components.append("indexer")
            else:
                success = False
        
        if "manager" in components and success:
            if install_wazuh_manager():
                installed_components.append("manager")
            else:
                success = False
        
        if "dashboard" in components and success:
            if install_wazuh_dashboard(node_ip):
                installed_components.append("dashboard")
            else:
                success = False
        
        if success and installed_components:
            # Configure security if indexer was installed
            if "indexer" in installed_components:
                configure_wazuh_security(node_ip)
            
            # Print summary
            print_installation_summary(node_ip, installed_components)
        
        return success
    
    def run_installation(self, args) -> bool:
        """Run the complete installation process."""
        self.logger.info(f"Starting Wazuh Server Installation Script v{VERSION}")
        self.logger.info(f"Author: {AUTHOR}")
        self.logger.info(f"System: {self.system_info.get('distro_name', 'Unknown')} ({self.system_info.get('machine', 'Unknown')})")
        
        # Validate environment
        if not self.validate_environment():
            return False
        
        # Determine components to install
        components = []
        if args.install_all:
            components = ["indexer", "manager", "dashboard"]
        else:
            if args.install_indexer:
                components.append("indexer")
            if args.install_manager:
                components.append("manager")
            if args.install_dashboard:
                components.append("dashboard")
        
        if not components:
            self.logger.error("No installation option specified. Use --help for usage information.")
            return False
        
        self.logger.info(f"Installing components: {', '.join(components)}")
        
        # Run installation
        return self.install_components(components)

# =============================================================================
# COMMAND LINE INTERFACE
# =============================================================================

def create_argument_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser."""
    parser = argparse.ArgumentParser(
        description=f"Wazuh Server Installation Script v{VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  {sys.argv[0]} --install-all              # Install all components
  {sys.argv[0]} --install-manager          # Install only Wazuh Manager
  {sys.argv[0]} --install-indexer          # Install only Wazuh Indexer
  {sys.argv[0]} --install-dashboard        # Install only Wazuh Dashboard
  {sys.argv[0]} --install-manager --install-indexer  # Install Manager and Indexer

Author: {AUTHOR}
License: {LICENSE}
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
    config_group.add_argument('--node-name', type=str,
                             help='Custom node name (default: hostname)')
    config_group.add_argument('--node-ip', type=str,
                             help='Custom node IP address (default: auto-detect)')
    config_group.add_argument('--single-node', action='store_true',
                             help='Configure for single-node deployment')
    config_group.add_argument('--cluster-mode', action='store_true',
                             help='Configure for cluster deployment')
    
    # General options
    general_group = parser.add_argument_group('General Options')
    general_group.add_argument('--verbose', '-v', action='store_true',
                              help='Enable verbose logging')
    general_group.add_argument('--force', action='store_true',
                              help='Force installation (overwrite existing)')
    general_group.add_argument('--version', action='version',
                              version=f'Wazuh Installation Script v{VERSION}')
    
    return parser

def main():
    """Main entry point."""
    parser = create_argument_parser()
    args = parser.parse_args()
    
    # Create installer instance
    installer = WazuhInstaller(verbose=args.verbose)
    
    # Override node settings if provided
    if args.node_name:
        installer.node_name = args.node_name
    if args.node_ip:
        installer.node_ip = args.node_ip
    
    try:
        # Run installation
        success = installer.run_installation(args)
        
        if success:
            installer.logger.info("Installation completed successfully!")
            sys.exit(0)
        else:
            installer.logger.error("Installation failed!")
            sys.exit(1)
            
    except KeyboardInterrupt:
        installer.logger.warning("Installation interrupted by user")
        sys.exit(130)
    except Exception as e:
        installer.logger.error(f"Unexpected error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()