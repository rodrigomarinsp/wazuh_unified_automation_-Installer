#!/usr/bin/env python3
"""
Wazuh Server Installation Script - Python Implementation
Author: Rodrigo Marins Piaba (Fanaticos4tech)
Fixed by: AI Assistant for GPG Key Import Issues
E-Mail: rodrigomarinsp@gmail.com / fanaticos4tech@gmail.com
GitHub: rodrigomarinsp
Instagram: @fanaticos4tech
License: GPL-3.0

## Advanced Python installer with enhanced features, logging, and automation capabilities.
## Fixed version addressing GPG key import and repository setup issues for Ubuntu 24.04
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

# Wazuh configuration
WAZUH_VERSION = "4.8.0"
WAZUH_MAJOR_VERSION = "4.x"
WAZUH_REPO_URL = "https://packages.wazuh.com"
WAZUH_GPG_KEY_URL = f"{WAZUH_REPO_URL}/key/GPG-KEY-WAZUH"

# Default paths
DEFAULT_INSTALL_DIR = "/var/ossec"
DEFAULT_LOG_DIR = "/var/log/wazuh-installer"
DEFAULT_CONFIG_DIR = "/etc/wazuh-installer"
DEFAULT_CERT_DIR = "/etc/wazuh-indexer/certs"

# Service names
WAZUH_MANAGER_SERVICE = "wazuh-manager"
WAZUH_INDEXER_SERVICE = "wazuh-indexer"
WAZUH_DASHBOARD_SERVICE = "wazuh-dashboard"

# Network configuration
DEFAULT_INDEXER_PORT = 9200
DEFAULT_DASHBOARD_PORT = 443
DEFAULT_API_PORT = 55000

# =============================================================================
# LOGGING CONFIGURATION
# =============================================================================

def setup_logging(log_level: str = "INFO", log_file: Optional[str] = None) -> logging.Logger:
    """
    Setup logging configuration with both console and file output.
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional log file path
        
    Returns:
        Configured logger instance
    """
    # Create logs directory if it doesn't exist
    if log_file:
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, mode=0o755, exist_ok=True)
    
    # Configure logging format
    log_format = "%(asctime)s - %(levelname)s - %(message)s"
    date_format = "%Y-%m-%d %H:%M:%S"
    
    # Setup root logger
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format=log_format,
        datefmt=date_format,
        handlers=[]
    )
    
    logger = logging.getLogger(__name__)
    logger.handlers.clear()
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(getattr(logging, log_level.upper()))
    console_formatter = logging.Formatter(log_format, date_format)
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    # File handler (if specified)
    if log_file:
        file_handler = logging.FileHandler(log_file, mode='a', encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(log_format, date_format)
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
    
    return logger

# =============================================================================
# SYSTEM UTILITIES
# =============================================================================

class SystemInfo:
    """System information and detection utilities."""
    
    @staticmethod
    def get_os_info() -> Dict[str, str]:
        """Get detailed OS information."""
        try:
            # Try to read from /etc/os-release
            if os.path.exists('/etc/os-release'):
                os_info = {}
                with open('/etc/os-release', 'r') as f:
                    for line in f:
                        if '=' in line:
                            key, value = line.strip().split('=', 1)
                            os_info[key] = value.strip('"')
                
                return {
                    'distribution': os_info.get('ID', 'unknown'),
                    'version': os_info.get('VERSION_ID', 'unknown'),
                    'codename': os_info.get('VERSION_CODENAME', 'unknown'),
                    'description': os_info.get('PRETTY_NAME', 'unknown'),
                    'architecture': platform.machine()
                }
        except Exception:
            pass
        
        # Fallback to platform module
        return {
            'distribution': platform.system().lower(),
            'version': platform.release(),
            'codename': 'unknown',
            'description': platform.platform(),
            'architecture': platform.machine()
        }
    
    @staticmethod
    def is_supported_os() -> Tuple[bool, str]:
        """Check if the current OS is supported."""
        os_info = SystemInfo.get_os_info()
        distribution = os_info['distribution'].lower()
        version = os_info['version']
        
        supported_os = {
            'ubuntu': ['18.04', '20.04', '22.04', '24.04'],
            'debian': ['9', '10', '11', '12'],
            'centos': ['7', '8'],
            'rhel': ['7', '8', '9'],
            'rocky': ['8', '9'],
            'almalinux': ['8', '9']
        }
        
        if distribution in supported_os:
            if version in supported_os[distribution] or any(version.startswith(v) for v in supported_os[distribution]):
                return True, f"Supported OS: {distribution} {version}"
            else:
                return False, f"Unsupported version: {distribution} {version}"
        else:
            return False, f"Unsupported distribution: {distribution}"
    
    @staticmethod
    def get_network_info() -> Dict[str, str]:
        """Get network interface information."""
        try:
            # Get hostname
            hostname = subprocess.check_output(['hostname'], universal_newlines=True).strip()
            
            # Get primary IP address
            ip_result = subprocess.check_output([
                'hostname', '-I'
            ], universal_newlines=True).strip()
            
            primary_ip = ip_result.split()[0] if ip_result else '127.0.0.1'
            
            return {
                'hostname': hostname,
                'primary_ip': primary_ip,
                'all_ips': ip_result.split()
            }
        except Exception as e:
            return {
                'hostname': 'localhost',
                'primary_ip': '127.0.0.1',
                'all_ips': ['127.0.0.1']
            }

class CommandExecutor:
    """Utility class for executing system commands."""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
    
    def run_command(self, command: List[str], cwd: Optional[str] = None, 
                   env: Optional[Dict[str, str]] = None, timeout: int = 300,
                   check: bool = True) -> subprocess.CompletedProcess:
        """
        Execute a system command with proper logging and error handling.
        
        Args:
            command: Command and arguments as list
            cwd: Working directory
            env: Environment variables
            timeout: Command timeout in seconds
            check: Whether to raise exception on non-zero exit code
            
        Returns:
            CompletedProcess instance
            
        Raises:
            subprocess.CalledProcessError: If command fails and check=True
        """
        self.logger.debug(f"Executing command: {' '.join(command)}")
        
        try:
            result = subprocess.run(
                command,
                cwd=cwd,
                env=env,
                timeout=timeout,
                check=check,
                capture_output=True,
                universal_newlines=True
            )
            
            if result.stdout:
                self.logger.debug(f"Command stdout: {result.stdout}")
            if result.stderr:
                self.logger.debug(f"Command stderr: {result.stderr}")
                
            return result
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Command failed: {' '.join(command)}")
            self.logger.error(f"Return code: {e.returncode}")
            self.logger.error(f"Stdout: {e.stdout}")
            self.logger.error(f"Stderr: {e.stderr}")
            raise
        except subprocess.TimeoutExpired as e:
            self.logger.error(f"Command timed out after {timeout}s: {' '.join(command)}")
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error executing command: {e}")
            raise

    def run_shell_command(self, command: str, cwd: Optional[str] = None,
                         env: Optional[Dict[str, str]] = None, timeout: int = 300,
                         check: bool = True) -> subprocess.CompletedProcess:
        """
        Execute a shell command string.
        
        Args:
            command: Shell command string
            cwd: Working directory
            env: Environment variables
            timeout: Command timeout in seconds
            check: Whether to raise exception on non-zero exit code
            
        Returns:
            CompletedProcess instance
        """
        self.logger.debug(f"Executing shell command: {command}")
        
        try:
            result = subprocess.run(
                command,
                shell=True,
                cwd=cwd,
                env=env,
                timeout=timeout,
                check=check,
                capture_output=True,
                universal_newlines=True
            )
            
            if result.stdout:
                self.logger.debug(f"Command stdout: {result.stdout}")
            if result.stderr:
                self.logger.debug(f"Command stderr: {result.stderr}")
                
            return result
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Shell command failed: {command}")
            self.logger.error(f"Return code: {e.returncode}")
            self.logger.error(f"Stdout: {e.stdout}")
            self.logger.error(f"Stderr: {e.stderr}")
            raise
        except subprocess.TimeoutExpired as e:
            self.logger.error(f"Shell command timed out after {timeout}s: {command}")
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error executing shell command: {e}")
            raise

# =============================================================================
# DEPENDENCY CHECKER
# =============================================================================

class DependencyChecker:
    """Check and install required system dependencies."""
    
    def __init__(self, logger: logging.Logger, executor: CommandExecutor):
        self.logger = logger
        self.executor = executor
        
    def check_required_tools(self) -> List[str]:
        """Check for required system tools."""
        required_tools = [
            'curl', 'wget', 'gpg', 'apt-get', 'systemctl', 
            'openssl', 'tar', 'unzip', 'hostname'
        ]
        
        missing_tools = []
        for tool in required_tools:
            if not which(tool):
                missing_tools.append(tool)
                
        return missing_tools
    
    def install_missing_tools(self, missing_tools: List[str]) -> bool:
        """Install missing system tools."""
        if not missing_tools:
            return True
            
        self.logger.info(f"Installing missing tools: {', '.join(missing_tools)}")
        
        try:
            # Update package cache
            self.executor.run_command(['apt-get', 'update'])
            
            # Install missing tools
            install_cmd = ['apt-get', 'install', '-y'] + missing_tools
            self.executor.run_command(install_cmd)
            
            self.logger.info("Successfully installed missing tools")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to install missing tools: {e}")
            return False
    
    def check_system_requirements(self) -> bool:
        """Check overall system requirements."""
        # Check OS support
        os_supported, os_message = SystemInfo.is_supported_os()
        if not os_supported:
            self.logger.error(os_message)
            return False
        
        self.logger.info(os_message)
        
        # Check and install missing tools
        missing_tools = self.check_required_tools()
        if missing_tools:
            if not self.install_missing_tools(missing_tools):
                return False
        
        self.logger.info("All required dependencies are available")
        return True

# =============================================================================
# REPOSITORY MANAGEMENT
# =============================================================================

class RepositoryManager:
    """Manage Wazuh package repositories."""
    
    def __init__(self, logger: logging.Logger, executor: CommandExecutor):
        self.logger = logger
        self.executor = executor
        
    def add_wazuh_repository(self) -> bool:
        """Add Wazuh repository to the system."""
        try:
            self.logger.info("Adding Wazuh repository...")
            
            # Create keyrings directory if it doesn't exist
            keyrings_dir = "/usr/share/keyrings"
            if not os.path.exists(keyrings_dir):
                os.makedirs(keyrings_dir, mode=0o755, exist_ok=True)
            
            # Download GPG key to temporary file
            temp_key_file = "/tmp/wazuh-gpg-key"
            self.logger.debug("Downloading Wazuh GPG key...")
            
            try:
                self.executor.run_command([
                    'curl', '-s', '-o', temp_key_file, WAZUH_GPG_KEY_URL
                ])
            except Exception as e:
                self.logger.error(f"Failed to download GPG key: {e}")
                return False
            
            # Import GPG key
            self.logger.debug("Importing Wazuh GPG key...")
            try:
                # Create GPG keyring
                keyring_path = "/usr/share/keyrings/wazuh.gpg"
                
                # Import the key using gpg
                self.executor.run_shell_command(
                    f"gpg --no-default-keyring --keyring {keyring_path} --import {temp_key_file}"
                )
                
                # Set proper permissions
                os.chmod(keyring_path, 0o644)
                
            except Exception as e:
                self.logger.error(f"Failed to import GPG key: {e}")
                return False
            finally:
                # Clean up temporary file
                if os.path.exists(temp_key_file):
                    os.remove(temp_key_file)
            
            # Get OS information for repository URL
            os_info = SystemInfo.get_os_info()
            distribution = os_info['distribution']
            codename = os_info['codename']
            
            # Add repository
            repo_line = f"deb [signed-by=/usr/share/keyrings/wazuh.gpg] {WAZUH_REPO_URL}/{WAZUH_MAJOR_VERSION}/apt/ stable main"
            sources_file = "/etc/apt/sources.list.d/wazuh.list"
            
            self.logger.debug(f"Adding repository: {repo_line}")
            with open(sources_file, 'w') as f:
                f.write(repo_line + '\n')
            
            # Update package cache
            self.logger.info("Updating package cache...")
            self.executor.run_command(['apt-get', 'update'])
            
            self.logger.info("Successfully added Wazuh repository")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to add Wazuh repository: {e}")
            return False

# =============================================================================
# SSL CERTIFICATE MANAGEMENT
# =============================================================================

class CertificateManager:
    """Manage SSL certificates for Wazuh components."""
    
    def __init__(self, logger: logging.Logger, executor: CommandExecutor):
        self.logger = logger
        self.executor = executor
        
    def setup_certificates(self, node_name: str, node_ip: str) -> bool:
        """Setup SSL certificates for Wazuh indexer."""
        try:
            self.logger.info("Setting up SSL certificates...")
            
            # Create certificates directory
            cert_dir = Path(DEFAULT_CERT_DIR)
            cert_dir.mkdir(parents=True, exist_ok=True)
            
            # Generate root CA
            if not self._generate_root_ca(cert_dir):
                return False
                
            # Generate node certificates
            if not self._generate_node_certificate(cert_dir, node_name, node_ip):
                return False
                
            # Generate admin certificates
            if not self._generate_admin_certificate(cert_dir):
                return False
                
            # Set proper permissions
            self._set_certificate_permissions(cert_dir)
            
            self.logger.info("Successfully setup SSL certificates")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to setup certificates: {e}")
            return False
    
    def _generate_root_ca(self, cert_dir: Path) -> bool:
        """Generate root CA certificate."""
        try:
            self.logger.debug("Generating root CA certificate...")
            
            # Generate private key
            self.executor.run_command([
                'openssl', 'genrsa', '-out', 
                str(cert_dir / 'root-ca-key.pem'), '2048'
            ])
            
            # Generate root certificate
            self.executor.run_command([
                'openssl', 'req', '-new', '-x509', '-sha256', '-days', '365',
                '-key', str(cert_dir / 'root-ca-key.pem'),
                '-out', str(cert_dir / 'root-ca.pem'),
                '-subj', '/C=US/ST=CA/L=San Francisco/O=Wazuh/OU=IT/CN=root-ca'
            ])
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to generate root CA: {e}")
            return False
    
    def _generate_node_certificate(self, cert_dir: Path, node_name: str, node_ip: str) -> bool:
        """Generate node certificate."""
        try:
            self.logger.debug(f"Generating node certificate for {node_name}...")
            
            # Create OpenSSL config for node certificate
            node_ext_content = f"""basicConstraints=CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = {node_name}
DNS.3 = wazuh-indexer
IP.1 = 127.0.0.1
IP.2 = {node_ip}"""
            
            ext_file = cert_dir / 'node.ext'
            with open(ext_file, 'w') as f:
                f.write(node_ext_content)
            
            # Generate private key
            self.executor.run_command([
                'openssl', 'genrsa', '-out', 
                str(cert_dir / 'node-key.pem'), '2048'
            ])
            
            # Generate certificate signing request
            self.executor.run_command([
                'openssl', 'req', '-new', '-sha256',
                '-key', str(cert_dir / 'node-key.pem'),
                '-out', str(cert_dir / 'node.csr'),
                '-subj', f'/C=US/ST=CA/L=San Francisco/O=Wazuh/OU=IT/CN={node_name}'
            ])
            
            # Generate certificate
            self.executor.run_command([
                'openssl', 'x509', '-req', '-in', str(cert_dir / 'node.csr'),
                '-CA', str(cert_dir / 'root-ca.pem'),
                '-CAkey', str(cert_dir / 'root-ca-key.pem'),
                '-CAcreateserial', '-out', str(cert_dir / 'node.pem'),
                '-days', '365', '-extensions', 'v3_req', '-extfile', str(ext_file)
            ])
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to generate node certificate: {e}")
            return False
    
    def _generate_admin_certificate(self, cert_dir: Path) -> bool:
        """Generate admin certificate."""
        try:
            self.logger.debug("Generating admin certificate...")
            
            # Generate private key
            self.executor.run_command([
                'openssl', 'genrsa', '-out', 
                str(cert_dir / 'admin-key.pem'), '2048'
            ])
            
            # Generate certificate signing request
            self.executor.run_command([
                'openssl', 'req', '-new', '-sha256',
                '-key', str(cert_dir / 'admin-key.pem'),
                '-out', str(cert_dir / 'admin.csr'),
                '-subj', '/C=US/ST=CA/L=San Francisco/O=Wazuh/OU=IT/CN=admin'
            ])
            
            # Generate certificate
            self.executor.run_command([
                'openssl', 'x509', '-req', '-in', str(cert_dir / 'admin.csr'),
                '-CA', str(cert_dir / 'root-ca.pem'),
                '-CAkey', str(cert_dir / 'root-ca-key.pem'),
                '-CAcreateserial', '-out', str(cert_dir / 'admin.pem'),
                '-days', '365'
            ])
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to generate admin certificate: {e}")
            return False
    
    def _set_certificate_permissions(self, cert_dir: Path) -> None:
        """Set proper permissions for certificate files."""
        try:
            # Set directory permissions
            os.chmod(cert_dir, 0o755)
            
            # Set certificate file permissions
            for cert_file in cert_dir.glob('*.pem'):
                if 'key' in cert_file.name:
                    os.chmod(cert_file, 0o600)  # Private keys
                else:
                    os.chmod(cert_file, 0o644)  # Certificates
                    
            # Change ownership to wazuh-indexer user if exists
            try:
                import pwd
                wazuh_user = pwd.getpwnam('wazuh-indexer')
                for cert_file in cert_dir.glob('*'):
                    os.chown(cert_file, wazuh_user.pw_uid, wazuh_user.pw_gid)
            except (KeyError, ImportError):
                # User doesn't exist yet or pwd module not available
                pass
                
        except Exception as e:
            self.logger.warning(f"Failed to set certificate permissions: {e}")

# =============================================================================
# WAZUH COMPONENT INSTALLERS
# =============================================================================

class WazuhManagerInstaller:
    """Install and configure Wazuh Manager."""
    
    def __init__(self, logger: logging.Logger, executor: CommandExecutor):
        self.logger = logger
        self.executor = executor
        
    def install(self) -> bool:
        """Install Wazuh Manager."""
        try:
            self.logger.info("Installing Wazuh Manager...")
            
            # Install package
            self.executor.run_command([
                'apt-get', 'install', '-y', f'wazuh-manager={WAZUH_VERSION}-1'
            ])
            
            # Enable and start service
            self.executor.run_command(['systemctl', 'daemon-reload'])
            self.executor.run_command(['systemctl', 'enable', WAZUH_MANAGER_SERVICE])
            self.executor.run_command(['systemctl', 'start', WAZUH_MANAGER_SERVICE])
            
            # Verify installation
            if self._verify_installation():
                self.logger.info("Wazuh Manager installed successfully")
                return True
            else:
                self.logger.error("Wazuh Manager installation verification failed")
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to install Wazuh Manager: {e}")
            return False
    
    def _verify_installation(self) -> bool:
        """Verify Wazuh Manager installation."""
        try:
            # Check if service is running
            result = self.executor.run_command([
                'systemctl', 'is-active', WAZUH_MANAGER_SERVICE
            ], check=False)
            
            return result.returncode == 0
            
        except Exception:
            return False

class WazuhIndexerInstaller:
    """Install and configure Wazuh Indexer."""
    
    def __init__(self, logger: logging.Logger, executor: CommandExecutor, cert_manager: CertificateManager):
        self.logger = logger
        self.executor = executor
        self.cert_manager = cert_manager
        
    def install(self, node_name: str, node_ip: str) -> bool:
        """Install Wazuh Indexer."""
        try:
            self.logger.info("Installing Wazuh Indexer...")
            
            # Setup certificates first
            if not self.cert_manager.setup_certificates(node_name, node_ip):
                return False
            
            # Install package
            self.executor.run_command([
                'apt-get', 'install', '-y', f'wazuh-indexer={WAZUH_VERSION}-1'
            ])
            
            # Configure indexer
            if not self._configure_indexer(node_name, node_ip):
                return False
            
            # Enable and start service
            self.executor.run_command(['systemctl', 'daemon-reload'])
            self.executor.run_command(['systemctl', 'enable', WAZUH_INDEXER_SERVICE])
            self.executor.run_command(['systemctl', 'start', WAZUH_INDEXER_SERVICE])
            
            # Wait for service to start
            time.sleep(10)
            
            # Initialize security
            if not self._initialize_security():
                return False
            
            # Verify installation
            if self._verify_installation():
                self.logger.info("Wazuh Indexer installed successfully")
                return True
            else:
                self.logger.error("Wazuh Indexer installation verification failed")
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to install Wazuh Indexer: {e}")
            return False
    
    def _configure_indexer(self, node_name: str, node_ip: str) -> bool:
        """Configure Wazuh Indexer."""
        try:
            config_file = "/etc/wazuh-indexer/opensearch.yml"
            
            config_content = f"""network.host: {node_ip}
node.name: {node_name}
cluster.initial_master_nodes: {node_name}
cluster.name: wazuh-cluster

# SSL/TLS configuration
plugins.security.ssl.transport.pemcert_filepath: {DEFAULT_CERT_DIR}/node.pem
plugins.security.ssl.transport.pemkey_filepath: {DEFAULT_CERT_DIR}/node-key.pem
plugins.security.ssl.transport.pemtrustedcas_filepath: {DEFAULT_CERT_DIR}/root-ca.pem
plugins.security.ssl.transport.enforce_hostname_verification: false
plugins.security.ssl.http.enabled: true
plugins.security.ssl.http.pemcert_filepath: {DEFAULT_CERT_DIR}/node.pem
plugins.security.ssl.http.pemkey_filepath: {DEFAULT_CERT_DIR}/node-key.pem
plugins.security.ssl.http.pemtrustedcas_filepath: {DEFAULT_CERT_DIR}/root-ca.pem
plugins.security.allow_unsafe_democertificates: false
plugins.security.allow_default_init_securityindex: true
plugins.security.authcz.admin_dn:
  - 'CN=admin,OU=IT,O=Wazuh,L=San Francisco,ST=CA,C=US'
plugins.security.nodes_dn:
  - 'CN={node_name},OU=IT,O=Wazuh,L=San Francisco,ST=CA,C=US'
plugins.security.audit.type: internal_opensearch
plugins.security.enable_snapshot_restore_privilege: true
plugins.security.check_snapshot_restore_write_privileges: true
plugins.security.restapi.roles_enabled: ["all_access", "security_rest_api_access"]
cluster.routing.allocation.disk.threshold_enabled: false
"""
            
            with open(config_file, 'w') as f:
                f.write(config_content)
                
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to configure Wazuh Indexer: {e}")
            return False
    
    def _initialize_security(self) -> bool:
        """Initialize Wazuh Indexer security."""
        try:
            self.logger.info("Initializing Wazuh Indexer security...")
            
            # Run security initialization script
            self.executor.run_command([
                '/usr/share/wazuh-indexer/bin/indexer-security-init.sh'
            ])
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to initialize security: {e}")
            return False
    
    def _verify_installation(self) -> bool:
        """Verify Wazuh Indexer installation."""
        try:
            # Check if service is running
            result = self.executor.run_command([
                'systemctl', 'is-active', WAZUH_INDEXER_SERVICE
            ], check=False)
            
            return result.returncode == 0
            
        except Exception:
            return False

class WazuhDashboardInstaller:
    """Install and configure Wazuh Dashboard."""
    
    def __init__(self, logger: logging.Logger, executor: CommandExecutor):
        self.logger = logger
        self.executor = executor
        
    def install(self, indexer_ip: str) -> bool:
        """Install Wazuh Dashboard."""
        try:
            self.logger.info("Installing Wazuh Dashboard...")
            
            # Install package
            self.executor.run_command([
                'apt-get', 'install', '-y', f'wazuh-dashboard={WAZUH_VERSION}-1'
            ])
            
            # Configure dashboard
            if not self._configure_dashboard(indexer_ip):
                return False
            
            # Enable and start service
            self.executor.run_command(['systemctl', 'daemon-reload'])
            self.executor.run_command(['systemctl', 'enable', WAZUH_DASHBOARD_SERVICE])
            self.executor.run_command(['systemctl', 'start', WAZUH_DASHBOARD_SERVICE])
            
            # Verify installation
            if self._verify_installation():
                self.logger.info("Wazuh Dashboard installed successfully")
                return True
            else:
                self.logger.error("Wazuh Dashboard installation verification failed")
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to install Wazuh Dashboard: {e}")
            return False
    
    def _configure_dashboard(self, indexer_ip: str) -> bool:
        """Configure Wazuh Dashboard."""
        try:
            config_file = "/etc/wazuh-dashboard/opensearch_dashboards.yml"
            
            config_content = f"""server.host: 0.0.0.0
server.port: 443
opensearch.hosts: https://{indexer_ip}:9200
opensearch.ssl.verificationMode: certificate
opensearch.ssl.certificateAuthorities: ["{DEFAULT_CERT_DIR}/root-ca.pem"]
opensearch.ssl.certificate: "{DEFAULT_CERT_DIR}/node.pem"
opensearch.ssl.key: "{DEFAULT_CERT_DIR}/node-key.pem"
opensearch.username: admin
opensearch.password: admin
opensearch.requestHeadersWhitelist: ["authorization", "securitytenant"]
server.ssl.enabled: true
server.ssl.certificate: "{DEFAULT_CERT_DIR}/node.pem"
server.ssl.key: "{DEFAULT_CERT_DIR}/node-key.pem"
opensearch_security.multitenancy.enabled: true
opensearch_security.multitenancy.tenants.preferred: ["Private", "Global"]
opensearch_security.readonly_mode.roles: ["kibana_read_only"]
uiSettings.overrides.defaultRoute: /app/wz-home
"""
            
            with open(config_file, 'w') as f:
                f.write(config_content)
                
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to configure Wazuh Dashboard: {e}")
            return False
    
    def _verify_installation(self) -> bool:
        """Verify Wazuh Dashboard installation."""
        try:
            # Check if service is running
            result = self.executor.run_command([
                'systemctl', 'is-active', WAZUH_DASHBOARD_SERVICE
            ], check=False)
            
            return result.returncode == 0
            
        except Exception:
            return False

# =============================================================================
# MAIN INSTALLER CLASS
# =============================================================================

class WazuhInstaller:
    """Main Wazuh installation orchestrator."""
    
    def __init__(self, args: argparse.Namespace):
        self.args = args
        
        # Setup logging
        log_file = os.path.join(DEFAULT_LOG_DIR, f"wazuh-install-{datetime.now().strftime('%Y%m%d-%H%M%S')}.log")
        self.logger = setup_logging(args.log_level, log_file)
        
        # Initialize utilities
        self.executor = CommandExecutor(self.logger)
        self.dependency_checker = DependencyChecker(self.logger, self.executor)
        self.repo_manager = RepositoryManager(self.logger, self.executor)
        self.cert_manager = CertificateManager(self.logger, self.executor)
        
        # Initialize component installers
        self.manager_installer = WazuhManagerInstaller(self.logger, self.executor)
        self.indexer_installer = WazuhIndexerInstaller(self.logger, self.executor, self.cert_manager)
        self.dashboard_installer = WazuhDashboardInstaller(self.logger, self.executor)
        
        # Get system information
        self.network_info = SystemInfo.get_network_info()
        self.node_name = args.node_name or self.network_info['hostname']
        self.node_ip = args.node_ip or self.network_info['primary_ip']
    
    def run(self) -> bool:
        """Run the installation process."""
        try:
            self.logger.info(f"Starting Wazuh Server Installation Script v{VERSION}")
            self.logger.info(f"Author: {AUTHOR}")
            
            # Display system information
            os_info = SystemInfo.get_os_info()
            self.logger.info(f"System: {os_info['distribution']} {os_info['version']} ({os_info['architecture']})")
            
            # Check system requirements
            if not self.dependency_checker.check_system_requirements():
                return False
            
            self.logger.info(f"Using hostname: {self.node_name}")
            self.logger.info(f"Using IP address: {self.node_ip}")
            
            # Add Wazuh repository
            if not self.repo_manager.add_wazuh_repository():
                return False
            
            # Install components based on arguments
            if self.args.install_all or self.args.install_indexer:
                if not self.indexer_installer.install(self.node_name, self.node_ip):
                    return False
            
            if self.args.install_all or self.args.install_manager:
                if not self.manager_installer.install():
                    return False
            
            if self.args.install_all or self.args.install_dashboard:
                if not self.dashboard_installer.install(self.node_ip):
                    return False
            
            self.logger.info("Wazuh installation completed successfully!")
            self._display_post_installation_info()
            
            return True
            
        except KeyboardInterrupt:
            self.logger.error("Installation interrupted by user")
            return False
        except Exception as e:
            self.logger.error(f"Installation failed: {e}")
            return False
    
    def _display_post_installation_info(self) -> None:
        """Display post-installation information."""
        self.logger.info("=" * 60)
        self.logger.info("WAZUH INSTALLATION SUMMARY")
        self.logger.info("=" * 60)
        
        if self.args.install_all or self.args.install_dashboard:
            self.logger.info(f"Wazuh Dashboard: https://{self.node_ip}")
            self.logger.info("Default credentials: admin/admin")
        
        if self.args.install_all or self.args.install_indexer:
            self.logger.info(f"Wazuh Indexer: https://{self.node_ip}:9200")
        
        if self.args.install_all or self.args.install_manager:
            self.logger.info(f"Wazuh Manager API: https://{self.node_ip}:55000")
        
        self.logger.info("")
        self.logger.info("IMPORTANT:")
        self.logger.info("- Change default passwords after first login")
        self.logger.info("- Configure firewall rules for required ports")
        self.logger.info("- Review and customize configuration files as needed")
        self.logger.info("=" * 60)

# =============================================================================
# COMMAND LINE INTERFACE
# =============================================================================

def create_argument_parser() -> argparse.ArgumentParser:
    """Create and configure argument parser."""
    parser = argparse.ArgumentParser(
        description="Wazuh Server Installation Script",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  {sys.argv[0]} --install-all                    # Install all components
  {sys.argv[0]} --install-manager                # Install only Manager
  {sys.argv[0]} --install-indexer                # Install only Indexer
  {sys.argv[0]} --install-dashboard              # Install only Dashboard
  {sys.argv[0]} --install-all --node-name=wazuh-server --node-ip=192.168.1.100

Author: {AUTHOR}
Version: {VERSION}
License: {LICENSE}
        """
    )
    
    # Installation options
    install_group = parser.add_argument_group('Installation Options')
    install_group.add_argument(
        '--install-all',
        action='store_true',
        help='Install all Wazuh components (Manager, Indexer, Dashboard)'
    )
    install_group.add_argument(
        '--install-manager',
        action='store_true',
        help='Install Wazuh Manager'
    )
    install_group.add_argument(
        '--install-indexer',
        action='store_true',
        help='Install Wazuh Indexer'
    )
    install_group.add_argument(
        '--install-dashboard',
        action='store_true',
        help='Install Wazuh Dashboard'
    )
    
    # Configuration options
    config_group = parser.add_argument_group('Configuration Options')
    config_group.add_argument(
        '--node-name',
        help='Node name (default: system hostname)'
    )
    config_group.add_argument(
        '--node-ip',
        help='Node IP address (default: primary IP)'
    )
    config_group.add_argument(
        '--config-file',
        help='Custom configuration file path'
    )
    
    # Logging options
    log_group = parser.add_argument_group('Logging Options')
    log_group.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        default='INFO',
        help='Set logging level (default: INFO)'
    )
    log_group.add_argument(
        '--log-file',
        help='Custom log file path'
    )
    
    # Miscellaneous options
    misc_group = parser.add_argument_group('Miscellaneous Options')
    misc_group.add_argument(
        '--version',
        action='version',
        version=f'%(prog)s {VERSION}'
    )
    misc_group.add_argument(
        '--dry-run',
        action='store_true',
        help='Show what would be done without executing'
    )
    
    return parser

def main() -> int:
    """Main entry point."""
    parser = create_argument_parser()
    args = parser.parse_args()
    
    # Check if any installation option was specified
    installation_options = [
        args.install_all,
        args.install_manager,
        args.install_indexer,
        args.install_dashboard
    ]
    
    if not any(installation_options):
        logger = logging.getLogger(__name__)
        logger.error("No installation option specified. Use --help for usage information.")
        return 1
    
    # Check for root privileges
    if os.geteuid() != 0:
        logger = logging.getLogger(__name__)
        logger.error("This script must be run as root. Use sudo.")
        return 1
    
    # Create installer and run
    installer = WazuhInstaller(args)
    
    if installer.run():
        return 0
    else:
        return 1

if __name__ == "__main__":
    sys.exit(main())
            