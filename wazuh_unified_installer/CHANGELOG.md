# Changelog
# Author: Rodrigo Marins Piaba (Fanaticos4tech)
# E-Mail: rodrigomarinsp@gmail.com / fanaticos4tech@gmail.com
# GitHub: rodrigomarinsp
# Instagram: @fanaticos4tech

All notable changes to the Wazuh Unified Installer project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2023-10-31

### Added
- Initial release of Wazuh Unified Installer
- Comprehensive server installation module
- Ansible deployment module for multi-node installations
- Agent installation module with multi-platform support
- Manual installation guide with step-by-step instructions
- Shared utilities for common functionality
- Unified configuration system via config.yml
- Master installer script with intelligent OS detection
- Automatic error recovery and dependency installation
- Cross-platform support for multiple Linux distributions
- Security hardening features with automatic certificate generation
- Comprehensive logging and validation
- Full documentation with troubleshooting guides

### Security
- Automatic firewall configuration
- TLS/SSL secure communication setup
- Certificate generation and management
- Password generation and management
- SELinux/AppArmor policy handling

## [0.9.0] - 2023-10-15

### Added
- Beta version with core functionality
- Basic server, agent, and ansible installation modules
- Initial configuration system and documentation
- Testing across Ubuntu, CentOS, and RHEL distributions

### Changed
- Improved error handling and logging
- Enhanced cross-platform compatibility

### Fixed
- Certificate generation issues on CentOS
- File permissions for configuration files
- Path handling for different distributions

## [0.5.0] - 2023-09-01

### Added
- Initial project structure
- Proof of concept for unified installation
- Basic server installation script
- Preliminary documentation
