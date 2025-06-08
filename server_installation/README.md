# 🛡️ Wazuh Server Installation Module
# Author: Rodrigo Marins Piaba (Fanaticos4tech)
# E-Mail: rodrigomarinsp@gmail.com / fanaticos4tech@gmail.com
# GitHub: rodrigomarinsp
# Instagram: @fanaticos4tech

## 🚀 Quick Start

Deploy a complete Wazuh server infrastructure with a single command:

```bash
cd server_installation
chmod +x server_install.sh
sudo ./server_install.sh --auto
```

**🎯 One-Line Installation:**
```bash
curl -sSL https://raw.githubusercontent.com/rodrigomarinsp/wazuh-unified-installer/main/server_installation/server_install.sh | sudo bash -s -- --auto
```

## 📋 Prerequisites

### ✅ Automatic System Requirements Checking

The installer automatically validates:

- **Operating System:** Ubuntu 20.04+, CentOS 7+, RHEL 8+, Debian 10+
- **RAM:** Minimum 4GB (8GB+ recommended for production)
- **CPU:** 2+ cores (4+ cores recommended)
- **Disk:** 50GB+ free space
- **Network:** Internet connectivity and open ports

### 🔧 Manual Prerequisites Verification

```bash
# Check system resources
./scripts/pre_install.sh --check-only

# Verify network connectivity
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH
```

## ⚙️ Installation Process

### 🖥️ Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                 WAZUH SERVER STACK                       │
├─────────────────────────────────────────────────────────┤
│  🌐 Wazuh Dashboard (Web UI)                           │
│      ↓ Port 443/80                                     │
│  🧠 Wazuh Manager (SIEM Engine)                        │
│      ↓ Port 1514/1515                                  │
│  🔍 Wazuh Indexer (Data Storage)                       │
│      ↓ Port 9200                                       │
│  🐧 Linux System (Ubuntu/CentOS/RHEL/Debian)          │
└─────────────────────────────────────────────────────────┘
```

### 📦 Component Installation Order

1. **🔧 System Preparation** - Updates, dependencies, firewall
2. **🔍 Wazuh Indexer** - OpenSearch-based data storage
3. **🧠 Wazuh Manager** - Core SIEM processing engine
4. **🌐 Wazuh Dashboard** - Web interface and visualization
5. **✅ Validation** - Health checks and connectivity tests

### 🛠️ Installation Methods

<details>
<summary><b>🤖 Automated Installation (Recommended)</b></summary>

```bash
# Full automation with default settings
sudo ./server_install.sh --auto

# Custom configuration file
sudo ./server_install.sh --config custom-config.yml

# Silent installation with logging
sudo ./server_install.sh --silent --log-file /var/log/wazuh-install.log
```
</details>

<details>
<summary><b>🐍 Python Installation (Advanced)</b></summary>

```bash
# Install Python dependencies
pip3 install -r ../requirements.txt

# Run Python installer
sudo python3 server_install.py --interactive

# Batch installation
sudo python3 server_install.py --batch --config-file custom.yml
```
</details>

<details>
<summary><b>📋 Step-by-Step Manual Installation</b></summary>

```bash
# 1. System preparation
sudo ./scripts/pre_install.sh

# 2. Install Indexer
sudo ./scripts/install_indexer.sh

# 3. Install Manager
sudo ./scripts/install_manager.sh

# 4. Install Dashboard
sudo ./scripts/install_dashboard.sh

# 5. Post-installation configuration
sudo ./scripts/post_install.sh

# 6. Validate installation
sudo ./validate_install.sh
```
</details>

## 🌐 Post-Installation Access

### 🔐 Default Credentials

**After successful installation:**

| Service | URL | Username | Password |
|---------|-----|----------|----------|
| **Wazuh Dashboard** | `https://YOUR-SERVER-IP` | `admin` | *Generated during install* |
| **Wazuh API** | `https://YOUR-SERVER-IP:55000` | `wazuh` | *Generated during install* |
| **Indexer API** | `https://YOUR-SERVER-IP:9200` | `admin` | *Generated during install* |

**🔑 Retrieve Passwords:**
```bash
# Dashboard admin password
sudo cat /var/ossec/api/configuration/api.yaml | grep password

# Check installation summary
sudo cat /var/log/wazuh-passwords.txt
```

### 🌐 Service Status

```bash
# Check all services
sudo systemctl status wazuh-manager wazuh-indexer wazuh-dashboard

# Service URLs validation
curl -k https://localhost:9200
curl -k https://localhost:443
```

## 🔧 Component Details

### 🧠 Wazuh Manager

**Functionality:**
- **Log Analysis** - Real-time security event processing
- **Rule Engine** - Custom detection rules and compliance checks
- **Agent Management** - Centralized agent enrollment and monitoring
- **API Services** - RESTful API for integration and automation

**Key Files:**
- Configuration: `/var/ossec/etc/ossec.conf`
- Rules: `/var/ossec/ruleset/rules/`
- Logs: `/var/ossec/logs/`

### 🔍 Wazuh Indexer

**Functionality:**
- **Data Storage** - Scalable OpenSearch-based backend
- **Index Management** - Automated data lifecycle policies
- **Search API** - High-performance data queries
- **Clustering** - Multi-node deployment support

**Key Files:**
- Configuration: `/etc/wazuh-indexer/opensearch.yml`
- Data: `/var/lib/wazuh-indexer/`
- Logs: `/var/log/wazuh-indexer/`

### 🌐 Wazuh Dashboard

**Functionality:**
- **Web Interface** - Modern responsive dashboard
- **Visualization** - Interactive charts and graphs
- **Compliance** - PCI DSS, GDPR, HIPAA reporting
- **User Management** - Role-based access control

**Key Files:**
- Configuration: `/etc/wazuh-dashboard/opensearch_dashboards.yml`
- Data: `/var/lib/wazuh-dashboard/`

## 🛠️ Troubleshooting

### 🔍 Common Issues & Auto-Solutions

<details>
<summary><b>🚨 Service Start Failures</b></summary>

**Symptoms:**
- Services fail to start
- Port binding errors
- Permission issues

**Auto-Solutions:**
```bash
# Automatic service recovery
sudo ./validate_install.sh --fix-services

# Manual troubleshooting
sudo journalctl -xe -u wazuh-manager
sudo systemctl status wazuh-indexer --no-pager -l
```
</details>

<details>
<summary><b>🌐 Connectivity Issues</b></summary>

**Symptoms:**
- Dashboard inaccessible
- API timeouts
- Certificate errors

**Auto-Solutions:**
```bash
# Automatic connectivity fix
sudo ./validate_install.sh --fix-connectivity

# Manual firewall configuration
sudo ufw allow 443,9200,55000,1514,1515/tcp
sudo firewall-cmd --permanent --add-port={443,9200,55000,1514,1515}/tcp
sudo firewall-cmd --reload
```
</details>

<details>
<summary><b>🔐 Certificate Problems</b></summary>

**Symptoms:**
- SSL/TLS errors
- Browser security warnings
- Component communication failures

**Auto-Solutions:**
```bash
# Regenerate certificates
sudo ./scripts/post_install.sh --regenerate-certs

# Manual certificate validation
sudo openssl x509 -in /etc/wazuh-indexer/certs/node.pem -text -noout
```
</details>

### 📊 Health Check Commands

```bash
# Complete system validation
sudo ./validate_install.sh --comprehensive

# Performance monitoring
sudo ./validate_install.sh --performance

# Security audit
sudo ./validate_install.sh --security-check
```

## 🔒 Security Hardening

### 🛡️ Automatic Security Configuration

The installer automatically implements:

- **🔐 Certificate Generation** - Self-signed SSL/TLS certificates
- **🔑 Password Policy** - Strong random password generation
- **🚪 Firewall Rules** - Restricted port access
- **👤 User Permissions** - Least privilege principle
- **🔒 File Permissions** - Secure configuration file access

### 🔧 Manual Security Enhancements

```bash
# Enable two-factor authentication
sudo ./scripts/post_install.sh --enable-2fa

# Configure external authentication
sudo ./scripts/post_install.sh --setup-ldap

# Security compliance scan
sudo ./validate_install.sh --security-audit
```

## 📊 Performance Tuning

### ⚡ Automatic Optimization

The installer automatically configures:

- **💾 Memory Allocation** - JVM heap sizing based on available RAM
- **🗂️ Index Settings** - Optimal shard and replica configuration
- **🔄 Refresh Intervals** - Balanced real-time vs. performance
- **📁 Log Rotation** - Automated cleanup policies

### 🎛️ Manual Performance Tuning

<details>
<summary><b>🧠 Memory Optimization</b></summary>

```bash
# Adjust JVM heap size (50% of RAM recommended)
sudo nano /etc/wazuh-indexer/jvm.options.d/wazuh-indexer.options
# -Xms4g
# -Xmx4g

# Restart services
sudo systemctl restart wazuh-indexer
```
</details>

<details>
<summary><b>📁 Storage Optimization</b></summary>

```bash
# Configure index lifecycle policies
curl -X PUT "localhost:9200/_ilm/policy/wazuh-policy" -H 'Content-Type: application/json' -d'
{
  "policy": {
    "phases": {
      "hot": {
        "actions": {
          "rollover": {
            "max_size": "50GB",
            "max_age": "30d"
          }
        }
      },
      "delete": {
        "min_age": "90d",
        "actions": {
          "delete": {}
        }
      }
    }
  }
}'
```
</details>

## 📚 Additional Resources

### 📖 Documentation Links

- **[Official Wazuh Documentation](https://documentation.wazuh.com/)**
- **[Installation Guide](https://documentation.wazuh.com/current/installation-guide/)**
- **[Configuration Reference](https://documentation.wazuh.com/current/user-manual/reference/)**
- **[API Documentation](https://documentation.wazuh.com/current/user-manual/api/)**

### 🛠️ Configuration Files

- **📄 Manager Config Template:** `configs/manager_config.yml`
- **📄 Indexer Config Template:** `configs/indexer_config.yml`
- **📄 Dashboard Config Template:** `configs/dashboard_config.yml`

### 🔧 Utility Scripts

- **📋 Pre-installation:** `scripts/pre_install.sh`
- **⚙️ Component Installers:** `scripts/install_*.sh`
- **🔧 Post-installation:** `scripts/post_install.sh`
- **✅ Validation:** `validate_install.sh`

## 🤝 Support & Contribution

### 🆘 Getting Help

1. **📋 Check Logs:** `/var/log/wazuh-installer.log`
2. **🔍 Run Diagnostics:** `./validate_install.sh --debug`
3. **📖 Consult Documentation:** See links above
4. **🐛 Report Issues:** GitHub repository

### 👨‍💻 Contributing

See `../CONTRIBUTING.md` for contribution guidelines.

---

**🛡️ Wazuh Unified Installer - Server Module**  
**Author:** Rodrigo Marins Piaba (Fanaticos4tech)  
**License:** GPL-3.0 | **Support:** fanaticos4tech@gmail.com
