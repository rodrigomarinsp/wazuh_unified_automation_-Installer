<!--
Author: Rodrigo Marins Piaba (Fanaticos4tech)
E-Mail: rodrigomarinsp@gmail.com / fanaticos4tech@gmail.com
GitHub: rodrigomarinsp
Instagram: @fanaticos4tech
-->

# 🛡️ Wazuh Unified Installer

<p align="center">
  <img src="https://wazuh.com/assets/images/wazuh_logo.png" alt="Wazuh Logo" width="300"/>
  <br>
  <em>Enterprise-grade automated deployment for Wazuh SIEM</em>
</p>

<p align="center">
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-features">Features</a> •
  <a href="#-installation-methods">Installation Methods</a> •
  <a href="#-requirements">Requirements</a> •
  <a href="#-documentation">Documentation</a> •
  <a href="#-troubleshooting">Troubleshooting</a> •
  <a href="#-contributing">Contributing</a> •
  <a href="#-license">License</a>
</p>

## 🚀 Quick Start

This project provides a unified installation system for Wazuh components with zero-touch automation and intelligent error handling.

```bash
# Clone the repository
git clone https://github.com/rodrigomarinsp/wazuh-unified-installer.git
cd Wazuh_Unified_Installer

# Run the main installer with default settings (interactive mode)
./main_installer.sh

# Or run with a specific configuration file (non-interactive mode)
./main_installer.sh --config my_config.yml
```

## ✨ Features

- **🔄 Universal Installation System** - Single platform for all deployment methods
- **🧠 Intelligent Detection** - Auto-detects environment and selects optimal installation strategy
- **🛠️ Enterprise-Ready** - Production-grade with zero-touch automation and error recovery
- **🔒 Security First** - Automatic certificate generation and security best practices
- **🌐 Multiple Platforms** - Supports Ubuntu, CentOS, RHEL, Debian, and more
- **📊 Performance Tuning** - Automatic optimization based on available resources
- **📱 Multi-Agent Support** - Automated deployment for Linux, Windows, and macOS agents

## 🔧 Installation Methods

<details>
<summary>🖥️ <b>Server Installation</b> - Complete Wazuh server infrastructure</summary>
<p>

Automated installation of Wazuh Manager, Indexer, and Dashboard on a single server:

```bash
cd server_installation
./server_install.sh
```

Learn more in the [Server Installation Guide](./server_installation/README.md).
</p>
</details>

<details>
<summary>⚙️ <b>Ansible Installation</b> - Enterprise-scale deployment</summary>
<p>

Mass deployment across multiple hosts using Ansible:

```bash
cd ansible_installation
./deploy.sh
```

Learn more in the [Ansible Installation Guide](./ansible_installation/README.md).
</p>
</details>

<details>
<summary>👥 <b>Agent Installation</b> - Connect agents to your Wazuh server</summary>
<p>

Deploy agents on various platforms:

```bash
cd agent_installation
./agent_deploy.sh --manager-ip <WAZUH_MANAGER_IP>
```

Learn more in the [Agent Installation Guide](./agent_installation/README.md).
</p>
</details>

<details>
<summary>📖 <b>Manual Installation</b> - Step-by-step guide</summary>
<p>

Follow our comprehensive step-by-step guide for manual installation and learning:

```bash
cd manual_installation
less README.md
```

Learn more in the [Manual Installation Guide](./manual_installation/README.md).
</p>
</details>

## 📋 Requirements

### System Requirements

- **🖥️ Server Components:**
  - CPU: 4 cores (minimum), 8+ cores (recommended)
  - Memory: 8GB RAM (minimum), 16GB+ RAM (recommended)
  - Disk: 50GB free space (minimum), SSD recommended
  - OS: Ubuntu 20.04+, CentOS 7+, RHEL 7+, Debian 10+

- **💻 Agent Components:**
  - Linux: Any modern distribution with kernel 3.10+
  - Windows: Windows 7+ / Server 2008 R2+
  - macOS: macOS 10.12+

### Software Requirements

- Bash 4.0+
- Python 3.6+ (for Python-based utilities)
- OpenSSL 1.1.1+
- cURL/wget

## 📚 Documentation

Comprehensive documentation is available for all installation methods:

- [Overview & Architecture](./docs/architecture.md)
- [Server Installation Guide](./server_installation/README.md)
- [Ansible Deployment Guide](./ansible_installation/README.md)
- [Agent Installation Guide](./agent_installation/README.md)
- [Manual Installation Guide](./manual_installation/README.md)
- [Configuration Reference](./docs/configuration.md)
- [Performance Tuning](./docs/performance.md)
- [Security Hardening](./docs/security.md)

## 🔍 Troubleshooting

Common issues and their solutions:

<details>
<summary>🔄 <b>Installation Failures</b></summary>
<p>

- Check the logs in `shared/logs/` for detailed error messages
- Ensure your system meets all requirements
- Verify connectivity between components
- Run `./main_installer.sh --validate` to check system compatibility

</p>
</details>

<details>
<summary>🌐 <b>Network Issues</b></summary>
<p>

- Ensure ports 1514, 1515, 55000 are open between agents and manager
- Check firewall rules with `./main_installer.sh --check-firewall`
- Verify DNS resolution for all hosts

</p>
</details>

<details>
<summary>🔐 <b>Certificate Problems</b></summary>
<p>

- Run `./main_installer.sh --fix-certificates` to regenerate certificates
- Check certificate paths and permissions
- Verify CA trust chain is properly configured

</p>
</details>

For more troubleshooting assistance, please refer to our [Troubleshooting Guide](./docs/troubleshooting.md).

## 👥 Contributing

Contributions are welcome and appreciated! Please see our [Contribution Guidelines](./CONTRIBUTING.md) for more details.

- Fork the repository
- Create a feature branch
- Submit a pull request

## 📝 License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](./LICENSE) file for details.

## 🙏 Acknowledgments

- [Wazuh Team](https://wazuh.com/) for their amazing SIEM platform
- All contributors who have helped improve this project
- The open source community for their invaluable tools and libraries

---

<p align="center">
  <sub>Built with ❤️ by <a href="https://github.com/rodrigomarinsp">Rodrigo Marins Piaba</a> and <a href="https://github.com/rodrigomarinsp/wazuh-unified-installer/graphs/contributors">contributors</a></sub>
</p>
