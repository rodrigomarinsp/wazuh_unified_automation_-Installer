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

# Wazuh configuration
WAZUH_VERSION = "4.8.2"
WAZUH_REVISION = "1"

# Supported operating systems - FIXED TO INCLUDE UBUNTU 24.04
SUPPORTED_OS = {
    'ubuntu': ['18.04', '20.04', '22.04', '24.04'],  # Added 24.04 support
    'debian': ['10', '11', '12'],
    'centos': ['7', '8'],
    'rhel': ['7', '8', '9'],
    'fedora': ['35', '36', '37', '38']
}

# Network configuration
DEFAULT_PORTS = {
    'wazuh_manager': {
        'api': 55000,
        'registration': 1515,
        'cluster': 1516,
        'syslog': 514
    },
    'wazuh_indexer': {
        'api': 9200,
        'performance': 9600
    },
    'wazuh_dashboard': {
        'web': 443
    }
}

# File paths
PATHS = {
    'wazuh_manager': {
        'config': '/var/ossec/etc/ossec.conf',
        'logs': '/var/ossec/logs',
        'rules': '/var/ossec/ruleset/rules',
        'decoders': '/var/ossec/ruleset/decoders'
    },
    'wazuh_indexer': {
        'config': '/etc/wazuh-indexer/opensearch.yml',
        'data': '/var/lib/wazuh-indexer',
        'logs': '/var/log/wazuh-indexer',
        'certs': '/etc/wazuh-indexer/certs'
    },
    'wazuh_dashboard': {
        'config': '/etc/wazuh-dashboard/opensearch_dashboards.yml',
        'data': '/var/lib/wazuh-dashboard',
        'logs': '/var/log/wazuh-dashboard'
    }
}

# =============================================================================
# LOGGING CONFIGURATION
# =============================================================================

def setup_logging(log_level: str = 'INFO', log_file: Optional[str] = None) -> logging.Logger:
    """Configure logging with enhanced formatting and optional file output."""
    
    # Create custom formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Configure root logger
    logger = logging.getLogger()
    logger.setLevel(getattr(logging, log_level.upper()))
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # Optional file handler
    if log_file:
        try:
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        except Exception as e:
            logger.warning(f"Could not setup file logging: {e}")
    
    return logger

# =============================================================================
# SYSTEM UTILITIES
# =============================================================================

class SystemInfo:
    """Enhanced system information gathering and validation."""
    
    def __init__(self):
        self.os_info = self._get_os_info()
        self.hardware_info = self._get_hardware_info()
        self.network_info = self._get_network_info()
    
    def _get_os_info(self) -> Dict[str, str]:
        """Get detailed operating system information."""
        try:
            # Get basic platform info
            system = platform.system().lower()
            
            if system == 'linux':
                # Try to get distribution info
                try:
                    with open('/etc/os-release', 'r') as f:
                        os_release = {}
                        for line in f:
                            if '=' in line:
                                key, value = line.strip().split('=', 1)
                                os_release[key] = value.strip('"')
                    
                    # Extract distribution and version
                    distro = os_release.get('ID', '').lower()
                    version = os_release.get('VERSION_ID', '').strip('"')
                    name = os_release.get('PRETTY_NAME', '')
                    
                    return {
                        'system': system,
                        'distribution': distro,
                        'version': version,
                        'name': name,
                        'architecture': platform.machine()
                    }
                    
                except Exception as e:
                    logging.warning(f"Could not read /etc/os-release: {e}")
            
            # Fallback for other systems or if os-release is not available
            return {
                'system': system,
                'distribution': 'unknown',
                'version': platform.release(),
                'name': platform.platform(),
                'architecture': platform.machine()
            }
            
        except Exception as e:
            logging.error(f"Error getting OS info: {e}")
            return {
                'system': 'unknown',
                'distribution': 'unknown',
                'version': 'unknown',
                'name': 'unknown',
                'architecture': 'unknown'
            }
    
    def _get_hardware_info(self) -> Dict[str, str]:
        """Get hardware information."""
        try:
            # Memory info
            with open('/proc/meminfo', 'r') as f:
                meminfo = f.read()
                mem_total = re.search(r'MemTotal:\s+(\d+)', meminfo)
                mem_total_gb = int(mem_total.group(1)) // 1024 // 1024 if mem_total else 0
            
            # CPU info
            cpu_count = os.cpu_count()
            
            # Disk space
            disk_usage = shutil.disk_usage('/')
            disk_free_gb = disk_usage.free // 1024 // 1024 // 1024
            
            return {
                'memory_gb': str(mem_total_gb),
                'cpu_cores': str(cpu_count),
                'disk_free_gb': str(disk_free_gb)
            }
            
        except Exception as e:
            logging.warning(f"Could not get hardware info: {e}")
            return {
                'memory_gb': 'unknown',
                'cpu_cores': 'unknown',
                'disk_free_gb': 'unknown'
            }
    
    def _get_network_info(self) -> Dict[str, str]:
        """Get network configuration."""
        try:
            # Get hostname
            hostname = platform.node()
            
            # Try to get IP address
            import socket
            ip_address = socket.gethostbyname(hostname)
            
            return {
                'hostname': hostname,
                'ip_address': ip_address
            }
            
        except Exception as e:
            logging.warning(f"Could not get network info: {e}")
            return {
                'hostname': 'localhost',
                'ip_address': '127.0.0.1'
            }
    
    def is_supported_os(self) -> bool:
        """Check if the current OS is supported."""
        distro = self.os_info.get('distribution', '')
        version = self.os_info.get('version', '')
        
        if distro in SUPPORTED_OS:
            return version in SUPPORTED_OS[distro]
        
        return False
    
    def check_minimum_requirements(self) -> Tuple[bool, List[str]]:
        """Check if system meets minimum requirements."""
        issues = []
        
        try:
            # Memory check (minimum 2GB)
            memory_gb = int(self.hardware_info.get('memory_gb', '0'))
            if memory_gb < 2:
                issues.append(f"Insufficient memory: {memory_gb}GB (minimum 2GB required)")
            
            # Disk space check (minimum 10GB)
            disk_free_gb = int(self.hardware_info.get('disk_free_gb', '0'))
            if disk_free_gb < 10:
                issues.append(f"Insufficient disk space: {disk_free_gb}GB (minimum 10GB required)")
            
            # CPU check (minimum 1 core, but 2 recommended)
            cpu_cores = int(self.hardware_info.get('cpu_cores', '0'))
            if cpu_cores < 1:
                issues.append(f"Insufficient CPU cores: {cpu_cores} (minimum 1 required)")
            elif cpu_cores < 2:
                logging.warning(f"Only {cpu_cores} CPU core available. 2+ cores recommended for better performance.")
        
        except (ValueError, TypeError):
            issues.append("Could not determine system resources")
        
        return len(issues) == 0, issues

# =============================================================================
# DEPENDENCY MANAGEMENT
# =============================================================================

class DependencyManager:
    """Enhanced dependency checking and installation."""
    
    REQUIRED_COMMANDS = [
        'curl', 'wget', 'tar', 'unzip', 'systemctl', 'openssl'
    ]
    
    OPTIONAL_COMMANDS = [
        'htop', 'iotop', 'netstat', 'ss'
    ]
    
    def __init__(self, system_info: SystemInfo):
        self.system_info = system_info
        self.missing_required = []
        self.missing_optional = []
    
    def check_dependencies(self) -> bool:
        """Check for required and optional dependencies."""
        logging.info("Checking system dependencies...")
        
        # Check required commands
        for cmd in self.REQUIRED_COMMANDS:
            if not which(cmd):
                self.missing_required.append(cmd)
        
        # Check optional commands
        for cmd in self.OPTIONAL_COMMANDS:
            if not which(cmd):
                self.missing_optional.append(cmd)
        
        if self.missing_required:
            logging.warning(f"Missing required tools: {', '.join(self.missing_required)}")
            return False
        
        if self.missing_optional:
            logging.info(f"Missing optional tools: {', '.join(self.missing_optional)}")
        
        logging.info("All required dependencies are available")
        return True
    
    def install_missing_dependencies(self) -> bool:
        """Install missing dependencies based on the distribution."""
        if not self.missing_required:
            return True
        
        distro = self.system_info.os_info.get('distribution', '')
        
        try:
            if distro in ['ubuntu', 'debian']:
                return self._install_debian_packages()
            elif distro in ['centos', 'rhel', 'fedora']:
                return self._install_rpm_packages()
            else:
                logging.error(f"Automatic dependency installation not supported for {distro}")
                return False
        
        except Exception as e:
            logging.error(f"Failed to install dependencies: {e}")
            return False
    
    def _install_debian_packages(self) -> bool:
        """Install packages on Debian/Ubuntu systems."""
        package_map = {
            'curl': 'curl',
            'wget': 'wget',
            'tar': 'tar',
            'unzip': 'unzip',
            'systemctl': 'systemd',
            'openssl': 'openssl'
        }
        
        packages = [package_map.get(cmd, cmd) for cmd in self.missing_required]
        
        logging.info(f"Installing missing tools: {', '.join(packages)}")
        
        # Update package cache
        result = subprocess.run(['apt-get', 'update'], capture_output=True, text=True)
        if result.returncode != 0:
            logging.warning("Could not update package cache")
        
        # Install packages
        cmd = ['apt-get', 'install', '-y'] + packages
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            logging.info("Successfully installed missing tools")
            return True
        else:
            logging.error(f"Failed to install packages: {result.stderr}")
            return False
    
    def _install_rpm_packages(self) -> bool:
        """Install packages on RPM-based systems."""
        package_map = {
            'curl': 'curl',
            'wget': 'wget',
            'tar': 'tar',
            'unzip': 'unzip',
            'systemctl': 'systemd',
            'openssl': 'openssl'
        }
        
        packages = [package_map.get(cmd, cmd) for cmd in self.missing_required]
        
        logging.info(f"Installing missing tools: {', '.join(packages)}")
        
        # Try yum first, then dnf
        for pkg_manager in ['dnf', 'yum']:
            if which(pkg_manager):
                cmd = [pkg_manager, 'install', '-y'] + packages
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if result.returncode == 0:
                    logging.info("Successfully installed missing tools")
                    return True
                else:
                    logging.error(f"Failed to install packages with {pkg_manager}: {result.stderr}")
        
        return False

# =============================================================================
# CERTIFICATE MANAGEMENT - FIXED VERSION
# =============================================================================

class CertificateManager:
    """Enhanced SSL certificate management with proper OpenSSL handling."""
    
    def __init__(self, cert_dir: str, node_name: str, node_ip: str):
        self.cert_dir = Path(cert_dir)
        self.node_name = node_name
        self.node_ip = node_ip
    
    def setup_certificates(self) -> bool:
        """Set up SSL certificates for Wazuh components."""
        try:
            logging.info("Setting up SSL certificates...")
            
            # Create certificate directory
            self.cert_dir.mkdir(parents=True, exist_ok=True)
            os.chmod(self.cert_dir, 0o755)
            
            # Generate root CA
            if not self._generate_root_ca():
                return False
            
            # Generate node certificates
            if not self._generate_node_certificate():
                return False
            
            # Generate admin certificates
            if not self._generate_admin_certificate():
                return False
            
            # Set proper permissions
            self._set_certificate_permissions()
            
            logging.info("SSL certificates setup completed successfully")
            return True
            
        except Exception as e:
            logging.error(f"Failed to setup certificates: {e}")
            return False
    
    def _generate_root_ca(self) -> bool:
        """Generate root Certificate Authority."""
        try:
            ca_key = self.cert_dir / "root-ca-key.pem"
            ca_cert = self.cert_dir / "root-ca.pem"
            
            # Generate private key
            cmd = [
                'openssl', 'genrsa',
                '-out', str(ca_key),
                '2048'
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                logging.error(f"Failed to generate CA private key: {result.stderr}")
                return False
            
            # Generate certificate
            cmd = [
                'openssl', 'req', '-new', '-x509',
                '-key', str(ca_key),
                '-out', str(ca_cert),
                '-days', '365',
                '-subj', '/C=US/ST=State/L=City/O=Wazuh/CN=Wazuh Root CA'
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                logging.error(f"Failed to generate CA certificate: {result.stderr}")
                return False
            
            logging.info("Root CA generated successfully")
            return True
            
        except Exception as e:
            logging.error(f"Error generating root CA: {e}")
            return False
    
    def _generate_node_certificate(self) -> bool:
        """Generate node certificate with proper SAN extensions - FIXED VERSION."""
        try:
            node_key = self.cert_dir / "node-key.pem"
            node_csr = self.cert_dir / "node.csr"
            node_cert = self.cert_dir / "node.pem"
            ca_cert = self.cert_dir / "root-ca.pem"
            ca_key = self.cert_dir / "root-ca-key.pem"
            
            # Generate private key
            cmd = [
                'openssl', 'genrsa',
                '-out', str(node_key),
                '2048'
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                logging.error(f"Failed to generate node private key: {result.stderr}")
                return False
            
            # Generate certificate signing request
            cmd = [
                'openssl', 'req', '-new',
                '-key', str(node_key),
                '-out', str(node_csr),
                '-subj', f'/C=US/ST=State/L=City/O=Wazuh/CN={self.node_name}'
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                logging.error(f"Failed to generate node CSR: {result.stderr}")
                return False
            
            # Generate certificate with SAN extensions - FIXED COMMAND
            san_extension = f'subjectAltName=DNS:localhost,DNS:{self.node_name},DNS:wazuh-indexer,IP:127.0.0.1,IP:{self.node_ip}'
            
            cmd = [
                'openssl', 'x509', '-req',
                '-in', str(node_csr),
                '-CA', str(ca_cert),
                '-CAkey', str(ca_key),
                '-CAcreateserial',
                '-out', str(node_cert),
                '-days', '365',
                '-addext', san_extension  # Using -addext instead of -extensions and -extfile
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                logging.error(f"Failed to generate node certificate: {result.stderr}")
                return False
            
            # Clean up CSR file
            node_csr.unlink(missing_ok=True)
            
            logging.info("Node certificate generated successfully")
            return True
            
        except Exception as e:
            logging.error(f"Error generating node certificate: {e}")
            return False
    
    def _generate_admin_certificate(self) -> bool:
        """Generate admin certificate."""
        try:
            admin_key = self.cert_dir / "admin-key.pem"
            admin_csr = self.cert_dir / "admin.csr"
            admin_cert = self.cert_dir / "admin.pem"
            ca_cert = self.cert_dir / "root-ca.pem"
            ca_key = self.cert_dir / "root-ca-key.pem"
            
            # Generate private key
            cmd = [
                'openssl', 'genrsa',
                '-out', str(admin_key),
                '2048'
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                logging.error(f"Failed to generate admin private key: {result.stderr}")
                return False
            
            # Generate certificate signing request
            cmd = [
                'openssl', 'req', '-new',
                '-key', str(admin_key),
                '-out', str(admin_csr),
                '-subj', '/C=US/ST=State/L=City/O=Wazuh/CN=admin'
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                logging.error(f"Failed to generate admin CSR: {result.stderr}")
                return False
            
            # Generate certificate
            cmd = [
                'openssl', 'x509', '-req',
                '-in', str(admin_csr),
                '-CA', str(ca_cert),
                '-CAkey', str(ca_key),
                '-CAcreateserial',
                '-out', str(admin_cert),
                '-days', '365'
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                logging.error(f"Failed to generate admin certificate: {result.stderr}")
                return False
            
            # Clean up CSR file
            admin_csr.unlink(missing_ok=True)
            
            logging.info("Admin certificate generated successfully")
            return True
            
        except Exception as e:
            logging.error(f"Error generating admin certificate: {e}")
            return False
    
    def _set_certificate_permissions(self):
        """Set appropriate permissions on certificate files."""
        try:
            # Set directory permissions
            os.chmod(self.cert_dir, 0o755)
            
            # Set file permissions
            for cert_file in self.cert_dir.glob("*.pem"):
                if "key" in cert_file.name:
                    os.chmod(cert_file, 0o600)  # Private keys - more restrictive
                else:
                    os.chmod(cert_file, 0o644)  # Certificates - readable
            
            logging.info("Certificate permissions set successfully")
            
        except Exception as e:
            logging.warning(f"Could not set certificate permissions: {e}")

# =============================================================================
# WAZUH COMPONENT INSTALLERS
# =============================================================================

class WazuhInstaller:
    """Main Wazuh installation orchestrator."""
    
    def __init__(self, system_info: SystemInfo):
        self.system_info = system_info
        self.node_name = system_info.network_info['hostname']
        self.node_ip = system_info.network_info['ip_address']
        
    def install_all(self) -> bool:
        """Install all Wazuh components."""
        try:
            logging.info("Starting complete Wazuh installation...")
            
            # Add repository
            if not self._add_wazuh_repository():
                return False
            
            # Install indexer first
            if not self.install_indexer():
                return False
            
            # Install manager
            if not self.install_manager():
                return False
            
            # Install dashboard
            if not self.install_dashboard():
                return False
            
            # Configure components
            if not self._configure_components():
                return False
            
            logging.info("Wazuh installation completed successfully!")
            return True
            
        except Exception as e:
            logging.error(f"Installation failed: {e}")
            return False
    
    def _add_wazuh_repository(self) -> bool:
        """Add Wazuh repository to the system."""
        try:
            logging.info("Adding Wazuh repository...")
            
            distro = self.system_info.os_info.get('distribution', '')
            
            if distro in ['ubuntu', 'debian']:
                return self._add_debian_repository()
            elif distro in ['centos', 'rhel', 'fedora']:
                return self._add_rpm_repository()
            else:
                logging.error(f"Unsupported distribution: {distro}")
                return False
                
        except Exception as e:
            logging.error(f"Failed to add Wazuh repository: {e}")
            return False
    
    def _add_debian_repository(self) -> bool:
        """Add Wazuh repository for Debian/Ubuntu systems."""
        try:
            # Download and import GPG key - FIXED METHOD
            logging.info("Downloading Wazuh GPG key...")
            curl_process = subprocess.run(
                ['curl', '-s', 'https://packages.wazuh.com/key/GPG-KEY-WAZUH'],
                capture_output=True, text=True
            )
            
            if curl_process.returncode != 0:
                logging.error("Failed to download Wazuh GPG key")
                return False
            
            # Import the key using proper method
            gpg_process = subprocess.run(
                ['gpg', '--dearmor'],
                input=curl_process.stdout,
                text=True,
                capture_output=True
            )
            
            if gpg_process.returncode != 0:
                logging.error("Failed to process GPG key")
                return False
            
            # Write the key to the keyring
            keyring_path = '/usr/share/keyrings/wazuh.gpg'
            with open(keyring_path, 'wb') as f:
                f.write(gpg_process.stdout.encode('latin1'))
            
            # Add repository
            repo_line = f"deb [signed-by={keyring_path}] https://packages.wazuh.com/4.x/apt/ stable main"
            
            with open('/etc/apt/sources.list.d/wazuh.list', 'w') as f:
                f.write(repo_line + '\n')
            
            # Update package cache
            logging.info("Updating package cache...")
            result = subprocess.run(['apt-get', 'update'], capture_output=True, text=True)
            
            if result.returncode == 0:
                logging.info("Successfully added Wazuh repository")
                return True
            else:
                logging.error(f"Failed to update package cache: {result.stderr}")
                return False
                
        except Exception as e:
            logging.error(f"Error adding Debian repository: {e}")
            return False
    
    def _add_rpm_repository(self) -> bool:
        """Add Wazuh repository for RPM-based systems."""
        try:
            # Import GPG key
            cmd = ['rpm', '--import', 'https://packages.wazuh.com/key/GPG-KEY-WAZUH']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                logging.error(f"Failed to import GPG key: {result.stderr}")
                return False
            
            # Add repository
            repo_content = """[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-\$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1"""
            
            with open('/etc/yum.repos.d/wazuh.repo', 'w') as f:
                f.write(repo_content)
            
            logging.info("Successfully added Wazuh repository")
            return True
            
        except Exception as e:
            logging.error(f"Error adding RPM repository: {e}")
            return False
    
    def install_indexer(self) -> bool:
        """Install and configure Wazuh Indexer."""
        try:
            logging.info("Installing Wazuh Indexer...")
            
            # Install package
            distro = self.system_info.os_info.get('distribution', '')
            
            if distro in ['ubuntu', 'debian']:
                cmd = ['apt-get', 'install', '-y', 'wazuh-indexer']
            else:
                cmd = ['yum', 'install', '-y', 'wazuh-indexer']
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                logging.error(f"Failed to install Wazuh Indexer: {result.stderr}")
                return False
            
            # Setup certificates
            cert_manager = CertificateManager(
                PATHS['wazuh_indexer']['certs'],
                self.node_name,
                self.node_ip
            )
            
            if not cert_manager.setup_certificates():
                logging.error("Failed to setup certificates")
                return False
            
            # Configure indexer
            if not self._configure_indexer():
                return False
            
            # Start and enable service
            subprocess.run(['systemctl', 'daemon-reload'])
            subprocess.run(['systemctl', 'enable', 'wazuh-indexer'])
            
            result = subprocess.run(['systemctl', 'start', 'wazuh-indexer'], capture_output=True, text=True)
            if result.returncode != 0:
                logging.error(f"Failed to start Wazuh Indexer: {result.stderr}")
                return False
            
            # Wait for service to be ready
            time.sleep(10)
            
            # Verify service is running
            result = subprocess.run(['systemctl', 'is-active', 'wazuh-indexer'], capture_output=True, text=True)
            if result.returncode == 0 and 'active' in result.stdout:
                logging.info("Wazuh Indexer installed and started successfully")
                return True
            else:
                logging.error("Wazuh Indexer is not running properly")
                return False
                
        except Exception as e:
            logging.error(f"Failed to install Wazuh Indexer: {e}")
            return False
    
    def _configure_indexer(self) -> bool:
        """Configure Wazuh Indexer."""
        try:
            config_content = f"""network.host: 0.0.0.0
node.name: {self.node_name}
cluster.initial_master_nodes: ["{self.node_name}"]
cluster.name: wazuh-cluster

plugins.security.ssl.transport.pemcert_filepath: certs/node.pem
plugins.security.ssl.transport.pemkey_filepath: certs/node-key.pem
plugins.security.ssl.transport.pemtrustedcas_filepath: certs/root-ca.pem
plugins.security.ssl.transport.enforce_hostname_verification: false
plugins.security.ssl.http.enabled: true
plugins.security.ssl.http.pemcert_filepath: certs/node.pem
plugins.security.ssl.http.pemkey_filepath: certs/node-key.pem
plugins.security.ssl.http.pemtrustedcas_filepath: certs/root-ca.pem
plugins.security.allow_default_init_securityindex: true
plugins.security.authcz.admin_dn:
  - "CN=admin,O=Wazuh,L=City,ST=State,C=US"
plugins.security.nodes_dn:
  - "CN={self.node_name},O=Wazuh,L=City,ST=State,C=US"
plugins.security.audit.type: internal_opensearch
plugins.security.enable_snapshot_restore_privilege: true
plugins.security.check_snapshot_restore_write_privileges: true
plugins.security.restapi.roles_enabled: ["all_access", "security_rest_api_access"]
cluster.routing.allocation.disk.threshold_enabled: false
"""
            
            config_path = PATHS['wazuh_indexer']['config']
            with open(config_path, 'w') as f:
                f.write(config_content)
            
            # Set ownership
            subprocess.run(['chown', 'wazuh-indexer:wazuh-indexer', config_path])
            
            logging.info("Wazuh Indexer configured successfully")
            return True
            
        except Exception as e:
            logging.error(f"Failed to configure Wazuh Indexer: {e}")
            return False
    
    def install_manager(self) -> bool:
        """Install and configure Wazuh Manager."""
        try:
            logging.info("Installing Wazuh Manager...")
            
            # Install package
            distro = self.system_info.os_info.get('distribution', '')
            
            if distro in ['ubuntu', 'debian']:
                cmd = ['apt-get', 'install', '-y', 'wazuh-manager']
            else:
                cmd = ['yum', 'install', '-y', 'wazuh-manager']
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                logging.error(f"Failed to install Wazuh Manager: {result.stderr}")
                return False
            
            # Configure manager
            if not self._configure_manager():
                return False
            
            # Start and enable service
            subprocess.run(['systemctl', 'daemon-reload'])
            subprocess.run(['systemctl', 'enable', 'wazuh-manager'])
            
            result = subprocess.run(['systemctl', 'start', 'wazuh-manager'], capture_output=True, text=True)
            if result.returncode != 0:
                logging.error(f"Failed to start Wazuh Manager: {result.stderr}")
                return False
            
            logging.info("Wazuh Manager installed and started successfully")
            return True
            
        except Exception as e:
            logging.error(f"Failed to install Wazuh Manager: {e}")
            return False
    
    def _configure_manager(self) -> bool:
        """Configure Wazuh Manager."""
        try:
            # Basic configuration is usually sufficient for initial setup
            # The default configuration will be used
            logging.info("Using default Wazuh Manager configuration")
            return True
            
        except Exception as e:
            logging.error(f"Failed to configure Wazuh Manager: {e}")
            return False
    
    def install_dashboard(self) -> bool:
        """Install and configure Wazuh Dashboard."""
        try:
            logging.info("Installing Wazuh Dashboard...")
            
            # Install package
            distro = self.system_info.os_info.get('distribution', '')
            
            if distro in ['ubuntu', 'debian']:
                cmd = ['apt-get', 'install', '-y', 'wazuh-dashboard']
            else:
                cmd = ['yum', 'install', '-y', 'wazuh-dashboard']
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                logging.error(f"Failed to install Wazuh Dashboard: {result.stderr}")
                return False
            
            # Configure dashboard
            if not self._configure_dashboard():
                return False
            
            # Start and enable service
            subprocess.run(['systemctl', 'daemon-reload'])
            subprocess.run(['systemctl', 'enable', 'wazuh-dashboard'])
            
            result = subprocess.run(['systemctl', 'start', 'wazuh-dashboard'], capture_output=True, text=True)
            if result.returncode != 0:
                logging.error(f"Failed to start Wazuh Dashboard: {result.stderr}")
                return False
            
            logging.info("Wazuh Dashboard installed and started successfully")
            return True
            
        except Exception as e:
            logging.error(f"Failed to install Wazuh Dashboard: {e}")
            return False
    
    def _configure_dashboard(self) -> bool:
        """Configure Wazuh Dashboard."""
        try:
            config_content = f"""server.host: 0.0.0.0
server.port: 443
opensearch.hosts: https://{self.node_ip}:9200
opensearch.ssl.verificationMode: certificate
opensearch.ssl.certificateAuthorities: ["/etc/wazuh-indexer/certs/root-ca.pem"]
opensearch.ssl.certificate: "/etc/wazuh-indexer/certs/node.pem"
opensearch.ssl.key: "/etc/wazuh-indexer/certs/node-key.pem"
opensearch.username: admin
opensearch.password: admin
opensearch.requestHeadersWhitelist: ["authorization", "securitytenant"]
server.ssl.enabled: true
server.ssl.certificate: "/etc/wazuh-indexer/certs/node.pem"
server.ssl.key: "/etc/wazuh-indexer/certs/node-key.pem"
opensearch_security.multitenancy.enabled: true
opensearch_security.multitenancy.tenants.preferred: ["Private", "Global"]
opensearch_security.readonly_mode.roles: ["kibana_read_only"]
"""
            
            config_path = PATHS['wazuh_dashboard']['config']
            with open(config_path, 'w') as f:
                f.write(config_content)
            
            # Set ownership
            subprocess.run(['chown', 'wazuh-dashboard:wazuh-dashboard', config_path])
            
            logging.info("Wazuh Dashboard configured successfully")
            return True
            
        except Exception as e:
            logging.error(f"Failed to configure Wazuh Dashboard: {e}")
            return False
    
    def _configure_components(self) -> bool:
        """Final configuration and integration of all components."""
        try:
            logging.info("Performing final configuration...")
            
            # Wait for all services to be fully ready
            time.sleep(15)
            
            # Initialize security index (if needed)
            try:
                subprocess.run([
                    '/usr/share/wazuh-indexer/bin/indexer-security-init.sh'
                ], capture_output=True, text=True, timeout=60)
            except subprocess.TimeoutExpired:
                logging.warning("Security initialization took longer than expected")
            except Exception as e:
                logging.warning(f"Security initialization warning: {e}")
            
            logging.info("Final configuration completed")
            return True
            
        except Exception as e:
            logging.error(f"Failed final configuration: {e}")
            return False

# =============================================================================
# MAIN APPLICATION
# =============================================================================

def main():
    """Main application entry point."""
    parser = argparse.ArgumentParser(
        description="Wazuh Server Installation Script",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  {sys.argv[0]} --install-all                    # Install all components
  {sys.argv[0]} --install-manager               # Install only Wazuh Manager
  {sys.argv[0]} --install-indexer               # Install only Wazuh Indexer
  {sys.argv[0]} --install-dashboard             # Install only Wazuh Dashboard
  {sys.argv[0]} --check-system                  # Check system requirements only

Author: {AUTHOR}
Version: {VERSION}
        """
    )
    
    # Installation options
    parser.add_argument('--install-all', action='store_true',
                       help='Install all Wazuh components (Manager, Indexer, Dashboard)')
    parser.add_argument('--install-manager', action='store_true',
                       help='Install Wazuh Manager only')
    parser.add_argument('--install-indexer', action='store_true',
                       help='Install Wazuh Indexer only')
    parser.add_argument('--install-dashboard', action='store_true',
                       help='Install Wazuh Dashboard only')
    
    # System options
    parser.add_argument('--check-system', action='store_true',
                       help='Check system requirements and exit')
    parser.add_argument('--force', action='store_true',
                       help='Force installation even if requirements are not met')
    
    # Configuration options
    parser.add_argument('--node-name', type=str,
                       help='Custom node name (default: hostname)')
    parser.add_argument('--node-ip', type=str,
                       help='Custom node IP address (default: auto-detected)')
    
    # Logging options
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                       default='INFO', help='Set logging level')
    parser.add_argument('--log-file', type=str,
                       help='Save logs to file')
    parser.add_argument('--verbose', action='store_true',
                       help='Enable verbose output (same as --log-level DEBUG)')
    
    args = parser.parse_args()
    
    # Setup logging
    log_level = 'DEBUG' if args.verbose else args.log_level
    logger = setup_logging(log_level, args.log_file)
    
    # Print header
    print(f"Wazuh Server Installation Script v{VERSION}")
    print(f"Author: {AUTHOR}")
    
    try:
        # Get system information
        system_info = SystemInfo()
        
        logging.info(f"System: {system_info.os_info.get('name', 'Unknown')}")
        
        # Check if installation option is specified
        if not any([args.install_all, args.install_manager, args.install_indexer, 
                   args.install_dashboard, args.check_system]):
            logging.error("No installation option specified. Use --help for usage information.")
            return 1
        
        # Check OS support
        if not system_info.is_supported_os():
            distro = system_info.os_info.get('distribution', 'unknown')
            version = system_info.os_info.get('version', 'unknown')
            logging.error(f"Unsupported OS: {version}")
            if not args.force:
                logging.error("Use --force to bypass this check")
                return 1
            else:
                logging.warning("Forcing installation on unsupported OS")
        else:
            logging.info(f"Supported OS: {system_info.os_info.get('distribution')} {system_info.os_info.get('version')}")
        
        # Check dependencies
        dep_manager = DependencyManager(system_info)
        if not dep_manager.check_dependencies():
            if not dep_manager.install_missing_dependencies():
                logging.error("Failed to install required dependencies")
                return 1
        
        # Check system requirements
        requirements_ok, issues = system_info.check_minimum_requirements()
        if not requirements_ok:
            logging.warning("System requirements check failed:")
            for issue in issues:
                logging.warning(f"  - {issue}")
            if not args.force:
                logging.error("Use --force to bypass system requirements")
                return 1
        
        # If only checking system, exit here
        if args.check_system:
            logging.info("System check completed successfully")
            return 0
        
        # Override node name and IP if specified
        if args.node_name:
            system_info.network_info['hostname'] = args.node_name
        if args.node_ip:
            system_info.network_info['ip_address'] = args.node_ip
        
        logging.info(f"Using hostname: {system_info.network_info['hostname']}")
        logging.info(f"Using IP address: {system_info.network_info['ip_address']}")
        
        # Initialize installer
        installer = WazuhInstaller(system_info)
        
        # Perform installation based on arguments
        success = False
        
        if args.install_all:
            success = installer.install_all()
        else:
            if args.install_indexer:
                success = installer.install_indexer()
            if args.install_manager and success:
                success = installer.install_manager()
            if args.install_dashboard and success:
                success = installer.install_dashboard()
        
        if success:
            logging.info("Installation completed successfully!")
            
            # Print access information
            print("\n" + "="*60)
            print("INSTALLATION COMPLETED SUCCESSFULLY!")
            print("="*60)
            print(f"Wazuh Dashboard: https://{system_info.network_info['ip_address']}")
            print("Default credentials: admin / admin")
            print("="*60)
            
            return 0
        else:
            logging.error("Installation failed!")
            return 1
            
    except KeyboardInterrupt:
        logging.warning("Installation interrupted by user")
        return 1
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())