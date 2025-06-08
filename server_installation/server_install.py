#!/usr/bin/env python3
"""
Wazuh Server Installation Script - Python Implementation
Author: Rodrigo Marins Piaba (Fanaticos4tech)
E-Mail: rodrigomarinsp@gmail.com / fanaticos4tech@gmail.com
GitHub: rodrigomarinsp
Instagram: @fanaticos4tech
License: GPL-3.0

Advanced Python installer with enhanced features, logging, and automation capabilities.
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

# =============================================================================
# CONSTANTS AND CONFIGURATION
# =============================================================================

VERSION = "1.0.0"
AUTHOR = "Rodrigo Marins Piaba (Fanaticos4tech)"
EMAIL = "rodrigomarinsp@gmail.com / fanaticos4tech@gmail.com"

WAZUH_VERSION = "4.7.0"
DEFAULT_LOG_FILE = "/var/log/wazuh-server-install.log"
PASSWORDS_FILE = "/var/log/wazuh-passwords.txt"

# Required ports for Wazuh components
REQUIRED_PORTS = {
    'dashboard': [443, 80],
    'manager': [1514, 1515, 55000],
    'indexer': [9200, 9300]
}

# Minimum system requirements
MIN_REQUIREMENTS = {
    'ram_gb': 4,
    'cpu_cores': 2,
    'disk_gb': 50
}

# =============================================================================
# LOGGING CONFIGURATION
# =============================================================================

class ColoredFormatter(logging.Formatter):
    """Custom formatter with colors for console output."""
    
    COLORS = {
        'DEBUG': '\033[36m',     # Cyan
        'INFO': '\033[34m',      # Blue
        'WARNING': '\033[33m',   # Yellow
        'ERROR': '\033[31m',     # Red
        'CRITICAL': '\033[35m',  # Magenta
    }
    
    RESET = '\033[0m'
    
    def format(self, record):
        color = self.COLORS.get(record.levelname, self.RESET)
        record.levelname = f"{color}{record.levelname}{self.RESET}"
        return super().format(record)

def setup_logging(log_file: str = DEFAULT_LOG_FILE, verbose: bool = False) -> logging.Logger:
    """Setup logging configuration with file and console handlers."""
    
    # Create logger
    logger = logging.getLogger('wazuh_installer')
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    
    # Ensure log directory exists
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    
    # File handler
    file_handler = logging.FileHandler(log_file)
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    file_handler.setFormatter(file_formatter)
    file_handler.setLevel(logging.DEBUG)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_formatter = ColoredFormatter(
        '%(levelname)s: %(message)s'
    )
    console_handler.setFormatter(console_formatter)
    console_handler.setLevel(logging.INFO if not verbose else logging.DEBUG)
    
    # Add handlers
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

# =============================================================================
# SYSTEM UTILITIES
# =============================================================================

class SystemInfo:
    """System information and utilities."""
    
    def __init__(self):
        self.os_info = self._detect_os()
        self.package_manager = self._get_package_manager()
    
    def _detect_os(self) -> Dict[str, str]:
        """Detect operating system information."""
        system = platform.system().lower()
        
        if system == 'linux':
            try:
                with open('/etc/os-release', 'r') as f:
                    os_release = {}
                    for line in f:
                        if '=' in line:
                            key, value = line.strip().split('=', 1)
                            os_release[key] = value.strip('"')
                    
                    return {
                        'name': os_release.get('ID', 'unknown'),
                        'version': os_release.get('VERSION_ID', 'unknown'),
                        'codename': os_release.get('VERSION_CODENAME', ''),
                        'pretty_name': os_release.get('PRETTY_NAME', 'Unknown Linux')
                    }
            except FileNotFoundError:
                pass
        
        return {
            'name': 'unknown',
            'version': 'unknown',
            'codename': '',
            'pretty_name': f'{system.title()} (Unknown)'
        }
    
    def _get_package_manager(self) -> Dict[str, str]:
        """Determine package manager commands based on OS."""
        os_name = self.os_info['name']
        
        if os_name in ['ubuntu', 'debian']:
            return {
                'name': 'apt',
                'update': 'apt update',
                'install': 'apt install -y',
                'remove': 'apt remove -y'
            }
        elif os_name in ['centos', 'rhel', 'rocky', 'almalinux', 'fedora']:
            if shutil.which('dnf'):
                return {
                    'name': 'dnf',
                    'update': 'dnf update -y',
                    'install': 'dnf install -y',
                    'remove': 'dnf remove -y'
                }
            else:
                return {
                    'name': 'yum',
                    'update': 'yum update -y',
                    'install': 'yum install -y',
                    'remove': 'yum remove -y'
                }
        else:
            raise Exception(f"Unsupported operating system: {os_name}")
    
    def get_system_resources(self) -> Dict[str, int]:
        """Get system resource information."""
        try:
            # RAM in GB
            with open('/proc/meminfo', 'r') as f:
                mem_total = 0
                for line in f:
                    if line.startswith('MemTotal:'):
                        mem_total = int(line.split()[1]) * 1024  # Convert KB to bytes
                        break
            ram_gb = mem_total // (1024**3)
            
            # CPU cores
            cpu_cores = os.cpu_count() or 1
            
            # Disk space in GB
            statvfs = os.statvfs('/')
            disk_gb = (statvfs.f_bavail * statvfs.f_frsize) // (1024**3)
            
            return {
                'ram_gb': ram_gb,
                'cpu_cores': cpu_cores,
                'disk_gb': disk_gb
            }
        except Exception as e:
            logger.warning(f"Could not determine system resources: {e}")
            return {'ram_gb': 0, 'cpu_cores': 0, 'disk_gb': 0}

# =============================================================================
# WAZUH INSTALLER CLASS
# =============================================================================

class WazuhInstaller:
    """Main Wazuh installer class."""
    
    def __init__(self, config: Dict, logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.system = SystemInfo()
        self.passwords = {}
        
        # Check if running as root
        if os.getuid() != 0:
            raise PermissionError("This script must be run as root")
    
    def run_command(self, command: str, check: bool = True, shell: bool = True) -> Tuple[int, str, str]:
        """Execute a system command and return result."""
        self.logger.debug(f"Executing command: {command}")
        
        try:
            result = subprocess.run(
                command,
                shell=shell,
                check=check,
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes timeout
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Command failed: {command}")
            self.logger.error(f"Return code: {e.returncode}")
            self.logger.error(f"STDERR: {e.stderr}")
            if check:
                raise
            return e.returncode, e.stdout, e.stderr
        except subprocess.TimeoutExpired:
            self.logger.error(f"Command timed out: {command}")
            raise
    
    def check_system_requirements(self) -> bool:
        """Check if system meets minimum requirements."""
        self.logger.info("Checking system requirements...")
        
        resources = self.system.get_system_resources()
        requirements_met = True
        
        # Check RAM
        if resources['ram_gb'] < MIN_REQUIREMENTS['ram_gb']:
            self.logger.warning(
                f"RAM: {resources['ram_gb']}GB detected. "
                f"Minimum {MIN_REQUIREMENTS['ram_gb']}GB recommended."
            )
            if not self.config.get('force_install', False):
                requirements_met = False
        else:
            self.logger.info(f"RAM: {resources['ram_gb']}GB - Adequate")
        
        # Check CPU cores
        if resources['cpu_cores'] < MIN_REQUIREMENTS['cpu_cores']:
            self.logger.warning(
                f"CPU cores: {resources['cpu_cores']} detected. "
                f"Minimum {MIN_REQUIREMENTS['cpu_cores']} cores recommended."
            )
        else:
            self.logger.info(f"CPU cores: {resources['cpu_cores']} - Adequate")
        
        # Check disk space
        if resources['disk_gb'] < MIN_REQUIREMENTS['disk_gb']:
            self.logger.warning(
                f"Free disk space: {resources['disk_gb']}GB. "
                f"Minimum {MIN_REQUIREMENTS['disk_gb']}GB recommended."
            )
            if not self.config.get('force_install', False):
                requirements_met = False
        else:
            self.logger.info(f"Free disk space: {resources['disk_gb']}GB - Adequate")
        
        return requirements_met
    
    def install_dependencies(self) -> None:
        """Install required system dependencies."""
        self.logger.info("Installing system dependencies...")
        
        # Update package repositories
        self.run_command(self.system.package_manager['update'])
        
        # Common packages
        common_packages = [
            'curl', 'wget', 'gnupg', 'ca-certificates', 'software-properties-common'
        ]
        
        # OS-specific packages
        if self.system.os_info['name'] in ['ubuntu', 'debian']:
            packages = common_packages + ['apt-transport-https', 'lsb-release']
        else:
            packages = ['curl', 'wget', 'gnupg2', 'ca-certificates']
        
        install_cmd = f"{self.system.package_manager['install']} {' '.join(packages)}"
        self.run_command(install_cmd)
        
        self.logger.info("Dependencies installed successfully")
    
    def add_wazuh_repository(self) -> None:
        """Add Wazuh official repository."""
        self.logger.info("Adding Wazuh repository...")
        
        # Download and add GPG key
        gpg_key_url = "https://packages.wazuh.com/key/GPG-KEY-WAZUH"
        
        if self.system.package_manager['name'] == 'apt':
            self.run_command(
                f"curl -s {gpg_key_url} | gpg --dearmor | "
                "tee /usr/share/keyrings/wazuh.gpg > /dev/null"
            )
            
            # Add repository
            repo_line = (
                "deb [signed-by=/usr/share/keyrings/wazuh.gpg] "
                "https://packages.wazuh.com/4.x/apt/ stable main"
            )
            with open('/etc/apt/sources.list.d/wazuh.list', 'w') as f:
                f.write(repo_line + '\n')
            
            self.run_command('apt update')
        
        else:  # YUM/DNF
            repo_content = f"""[wazuh]
gpgcheck=1
gpgkey={gpg_key_url}
enabled=1
name=EL-$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
"""
            with open('/etc/yum.repos.d/wazuh.repo', 'w') as f:
                f.write(repo_content)
        
        self.logger.info("Wazuh repository added successfully")
    
    def generate_passwords(self) -> None:
        """Generate secure passwords for Wazuh components."""
        self.logger.info("Generating secure passwords...")
        
        import secrets
        import string
        
        alphabet = string.ascii_letters + string.digits
        
        self.passwords = {
            'admin': ''.join(secrets.choice(alphabet) for _ in range(32)),
            'wazuh': ''.join(secrets.choice(alphabet) for _ in range(32)),
            'kibanaserver': ''.join(secrets.choice(alphabet) for _ in range(32))
        }
        
        # Save passwords to file
        password_content = f"""# Wazuh Installation Passwords
# Generated: {datetime.now()}
# Author: {AUTHOR}

ADMIN_PASSWORD="{self.passwords['admin']}"
WAZUH_PASSWORD="{self.passwords['wazuh']}"
KIBANASERVER_PASSWORD="{self.passwords['kibanaserver']}"

# Service URLs:
# Dashboard: https://{self._get_server_ip()}
# API: https://{self._get_server_ip()}:55000
# Indexer: https://{self._get_server_ip()}:9200
"""
        
        with open(PASSWORDS_FILE, 'w') as f:
            f.write(password_content)
        
        os.chmod(PASSWORDS_FILE, 0o600)
        self.logger.info(f"Passwords saved to {PASSWORDS_FILE}")
    
    def _get_server_ip(self) -> str:
        """Get server IP address."""
        try:
            result = subprocess.run(
                ["hostname", "-I"], 
                capture_output=True, 
                text=True, 
                check=True
            )
            return result.stdout.strip().split()[0]
        except:
            return "localhost"
    
    def configure_firewall(self) -> None:
        """Configure firewall rules for Wazuh."""
        self.logger.info("Configuring firewall...")
        
        # Get all required ports
        all_ports = []
        for component_ports in REQUIRED_PORTS.values():
            all_ports.extend(component_ports)
        
        # Try UFW first (Ubuntu/Debian)
        if shutil.which('ufw'):
            self.run_command('ufw --force enable', check=False)
            for port in all_ports:
                self.run_command(f'ufw allow {port}/tcp', check=False)
            self.logger.info("UFW firewall configured")
        
        # Try firewalld (RHEL/CentOS)
        elif shutil.which('firewall-cmd'):
            self.run_command('systemctl enable --now firewalld', check=False)
            for port in all_ports:
                self.run_command(f'firewall-cmd --permanent --add-port={port}/tcp', check=False)
            self.run_command('firewall-cmd --reload', check=False)
            self.logger.info("Firewalld configured")
        
        else:
            self.logger.warning("No supported firewall found. Please configure manually.")
    
    def install_component(self, component: str) -> None:
        """Install a specific Wazuh component."""
        self.logger.info(f"Installing Wazuh {component}...")
        
        # Install package
        package_name = f"wazuh-{component}"
        install_cmd = f"{self.system.package_manager['install']} {package_name}"
        self.run_command(install_cmd)
        
        # Enable and start service
        service_name = package_name
        self.run_command('systemctl daemon-reload')
        self.run_command(f'systemctl enable {service_name}')
        self.run_command(f'systemctl start {service_name}')
        
        # Wait for service to be ready
        self._wait_for_service(component)
        
        self.logger.info(f"Wazuh {component} installed and started successfully")
    
    def _wait_for_service(self, component: str) -> None:
        """Wait for a service to be ready."""
        self.logger.info(f"Waiting for {component} to be ready...")
        
        timeout = 120
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                if component == 'indexer':
                    self.run_command('curl -s -k https://localhost:9200', check=True)
                elif component == 'dashboard':
                    self.run_command('curl -s -k https://localhost:443', check=True)
                elif component == 'manager':
                    # Check if manager is listening on API port
                    self.run_command('ss -tulpn | grep :55000', check=True)
                
                self.logger.info(f"{component} is ready")
                return
            
            except subprocess.CalledProcessError:
                time.sleep(2)
        
        raise Exception(f"{component} failed to start within {timeout} seconds")
    
    def run_installation(self) -> None:
        """Run the complete installation process."""
        self.logger.info(f"Starting Wazuh Server installation...")
        self.logger.info(f"Author: {AUTHOR}")
        self.logger.info(f"OS: {self.system.os_info['pretty_name']}")
        
        try:
            # Pre-installation checks
            if not self.check_system_requirements():
                if not self.config.get('force_install', False):
                    raise Exception("System requirements not met. Use --force to override.")
            
            # Pre-installation steps
            self.install_dependencies()
            self.add_wazuh_repository()
            self.configure_firewall()
            self.generate_passwords()
            
            # Install components in order
            components = ['indexer', 'manager', 'dashboard']
            for component in components:
                if self.config.get(f'install_{component}', True):
                    self.install_component(component)
            
            # Post-installation configuration
            self.run_post_installation()
            
            # Validation
            if not self.config.get('skip_validation', False):
                self.validate_installation()
            
            self.show_installation_summary()
            
        except Exception as e:
            self.logger.error(f"Installation failed: {e}")
            raise
    
    def run_post_installation(self) -> None:
        """Run post-installation configuration."""
        self.logger.info("Running post-installation configuration...")
        
        # Configure API credentials
        api_config_file = '/var/ossec/api/configuration/api.yaml'
        if os.path.exists(api_config_file):
            try:
                with open(api_config_file, 'r') as f:
                    content = f.read()
                
                content = content.replace('password: wazuh', f'password: {self.passwords["wazuh"]}')
                
                with open(api_config_file, 'w') as f:
                    f.write(content)
                
                self.run_command('systemctl restart wazuh-manager')
                self.logger.info("API credentials updated")
            except Exception as e:
                self.logger.warning(f"Could not update API credentials: {e}")
    
    def validate_installation(self) -> None:
        """Validate the installation."""
        self.logger.info("Validating installation...")
        
        services = ['wazuh-indexer', 'wazuh-manager', 'wazuh-dashboard']
        all_healthy = True
        
        for service in services:
            try:
                result = self.run_command(f'systemctl is-active {service}', check=False)
                if result[0] == 0 and 'active' in result[1]:
                    self.logger.info(f"✓ {service} is running")
                else:
                    self.logger.error(f"✗ {service} is not running")
                    all_healthy = False
            except Exception as e:
                self.logger.error(f"✗ Could not check {service}: {e}")
                all_healthy = False
        
        if all_healthy:
            self.logger.info("All services are running successfully")
        else:
            self.logger.warning("Some services may have issues")
    
    def show_installation_summary(self) -> None:
        """Show installation completion summary."""
        server_ip = self._get_server_ip()
        
        summary = f"""
======================================================================
🛡️  WAZUH SERVER INSTALLATION SUMMARY
======================================================================
Author: {AUTHOR}
Installation completed: {datetime.now()}

🌐 Access Information:
   Dashboard:  https://{server_ip}
   API:        https://{server_ip}:55000
   Indexer:    https://{server_ip}:9200

🔐 Credentials:
   Check file: {PASSWORDS_FILE}
   Dashboard username: admin

📋 Next Steps:
   1. Access the dashboard using the URL above
   2. Install agents on your endpoints
   3. Configure rules and compliance policies
   4. Review security hardening guide

📚 Documentation:
   Local:  README.md
   Online: https://documentation.wazuh.com/

🆘 Support: {EMAIL}
======================================================================
"""
        
        print(summary)
        self.logger.info("Installation completed successfully!")

# =============================================================================
# MAIN FUNCTION AND CLI
# =============================================================================

def load_config(config_file: Optional[str] = None) -> Dict:
    """Load configuration from file or use defaults."""
    default_config = {
        'install_indexer': True,
        'install_manager': True,
        'install_dashboard': True,
        'force_install': False,
        'skip_validation': False,
        'configure_firewall': True,
        'generate_certificates': True
    }
    
    if config_file and os.path.exists(config_file):
        try:
            with open(config_file, 'r') as f:
                if config_file.endswith('.yml') or config_file.endswith('.yaml'):
                    config = yaml.safe_load(f)
                else:
                    config = json.load(f)
            
            # Merge with defaults
            default_config.update(config)
        except Exception as e:
            print(f"Warning: Could not load config file {config_file}: {e}")
    
    return default_config


def check_and_install_java():
    import subprocess
    import platform
    from shutil import which

    print("🔍 Verificando se o Java 11 está instalado...")

    def run(cmd):
        return subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    java_path = which("java")
    if java_path:
        result = run("java -version")
        version_line = result.stderr.split("\n")[0] if result.stderr else result.stdout.split("\n")[0]
        if 'version' in version_line:
            version = version_line.split('"')[1]
            major = int(version.split(".")[0]) if version.startswith("1.") is False else int(version.split(".")[1])
            if major == 11:
                print("✅ Java 11 já está instalado.")
                return
            else:
                print(f"⚠️ Java detectado: versão {version}. Esperado: 11.")
        else:
            print("⚠️ Java detectado mas versão não identificada.")
    else:
        print("⚠️ Java não encontrado.")

    print("📦 Instalando Java 11...")

    distro = platform.linux_distribution()[0].lower() if hasattr(platform, 'linux_distribution') else platform.system().lower()
    if "ubuntu" in distro or "debian" in distro:
        cmds = [
            "apt update",
            "apt install -y openjdk-11-jdk"
        ]
    elif "centos" in distro or "rhel" in distro or "rocky" in distro or "alma" in distro:
        cmds = [
            "yum install -y java-11-openjdk-devel"
        ]
    else:
        raise RuntimeError(f"Sistema não suportado para instalação automática do Java: {distro}")

    for cmd in cmds:
        res = run(cmd)
        if res.returncode != 0:
            print(f"❌ Erro ao executar: {cmd}\n{res.stderr}")
            raise RuntimeError("Falha na instalação do Java.")
    print("✅ Java 11 instalado com sucesso.\n")


def main():
    """Main function."""
    parser = argparse.ArgumentParser(
        description=f"Wazuh Server Installation Script v{VERSION}",
        epilog=f"Author: {AUTHOR}"
    )
    
    parser.add_argument('--config', '-c', 
                       help='Configuration file (YAML or JSON)')
    parser.add_argument('--log-file', '-l', 
                       default=DEFAULT_LOG_FILE,
                       help='Log file location')
    parser.add_argument('--verbose', '-v', 
                       action='store_true',
                       help='Verbose logging')
    parser.add_argument('--force', '-f', 
                       action='store_true',
                       help='Force installation (skip requirements check)')
    parser.add_argument('--skip-validation', 
                       action='store_true',
                       help='Skip post-installation validation')
    parser.add_argument('--interactive', '-i', 
                       action='store_true',
                       help='Interactive mode with prompts')
    parser.add_argument('--batch', '-b', 
                       action='store_true',
                       help='Batch mode (no prompts)')
    parser.add_argument('--version', 
                       action='version',
                       version=f'%(prog)s {VERSION}')
    
    args = parser.parse_args()
    
    # Setup logging
    global logger
    logger = setup_logging(args.log_file, args.verbose)
    
    try:
        # Load configuration
        config = load_config(args.config)
        
        # Update config with command line arguments
        if args.force:
            config['force_install'] = True
        if args.skip_validation:
            config['skip_validation'] = True
        
        # Create installer and run
        installer = WazuhInstaller(config, logger)
        installer.run_installation()
        
    except KeyboardInterrupt:
        logger.error("Installation cancelled by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Installation failed: {e}")
        if args.verbose:
            import traceback
            logger.error(traceback.format_exc())
        sys.exit(1)

if __name__ == '__main__':
    main()
