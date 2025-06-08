# 🔧 Wazuh Ansible Installation Module

<!--
Author: Rodrigo Marins Piaba (Fanaticos4tech)
E-Mail: rodrigomarinsp@gmail.com / fanaticos4tech@gmail.com
GitHub: rodrigomarinsp
Instagram: @fanaticos4tech
-->

## 🚀 Quick Start

Deploy Wazuh infrastructure with Ansible in minutes:

```bash
# Install Ansible requirements
ansible-galaxy install -r requirements.yml

# Configure inventory
cp inventory_template.yml inventory.yml
nano inventory.yml

# Deploy complete Wazuh infrastructure
./deploy.sh --environment production --install-all
```

## 📋 Prerequisites

### Ansible Requirements
- **Ansible Core:** 2.12+ (recommended 2.15+)
- **Python:** 3.8+ on control node
- **SSH Access:** Passwordless SSH to all target hosts
- **Privilege Escalation:** sudo/root access on target systems

### Target Systems
| Component | Minimum Resources | Recommended |
|-----------|-------------------|-------------|
| **Manager** | 2 CPU, 4GB RAM, 50GB Disk | 4 CPU, 8GB RAM, 100GB Disk |
| **Indexer** | 2 CPU, 4GB RAM, 50GB Disk | 4 CPU, 8GB RAM, 200GB Disk |
| **Dashboard** | 2 CPU, 2GB RAM, 30GB Disk | 2 CPU, 4GB RAM, 50GB Disk |
| **Agent** | 1 CPU, 512MB RAM, 10GB Disk | 2 CPU, 1GB RAM, 20GB Disk |

### Supported Platforms
- ✅ **Ubuntu:** 18.04, 20.04, 22.04
- ✅ **CentOS:** 7, 8, Stream 8, Stream 9
- ✅ **RHEL:** 7, 8, 9
- ✅ **Debian:** 10, 11, 12
- ✅ **Amazon Linux:** 2, 2023

## ⚙️ Installation Process

### 1. Environment Setup

<details>
<summary><b>🔽 Ansible Installation & Configuration</b></summary>

```bash
# Install Ansible (Ubuntu/Debian)
sudo apt update
sudo apt install -y ansible python3-pip

# Install Ansible (CentOS/RHEL)
sudo yum install -y epel-release
sudo yum install -y ansible python3-pip

# Install additional Python dependencies
pip3 install -r requirements.txt

# Verify installation
ansible --version
```
</details>

### 2. Inventory Configuration

<details>
<summary><b>🔽 Inventory Setup Examples</b></summary>

**Single-Node Deployment:**
```yaml
all:
  children:
    wazuh_cluster:
      children:
        wazuh_manager:
          hosts:
            wazuh-server:
              ansible_host: 192.168.1.100
        wazuh_indexer:
          hosts:
            wazuh-server:
              ansible_host: 192.168.1.100
        wazuh_dashboard:
          hosts:
            wazuh-server:
              ansible_host: 192.168.1.100
```

**Multi-Node Cluster:**
```yaml
all:
  children:
    wazuh_cluster:
      children:
        wazuh_manager:
          hosts:
            manager-01:
              ansible_host: 192.168.1.100
              wazuh_manager_type: master
            manager-02:
              ansible_host: 192.168.1.101
              wazuh_manager_type: worker
        wazuh_indexer:
          hosts:
            indexer-01:
              ansible_host: 192.168.1.110
            indexer-02:
              ansible_host: 192.168.1.111
            indexer-03:
              ansible_host: 192.168.1.112
        wazuh_dashboard:
          hosts:
            dashboard-01:
              ansible_host: 192.168.1.120
    wazuh_agents:
      hosts:
        agent-[01:50]:
          ansible_host: 192.168.1.[150:199]
```
</details>

### 3. Deployment Execution

<details>
<summary><b>🔽 Deployment Options</b></summary>

**Complete Infrastructure:**
```bash
./deploy.sh --environment production --install-all
```

**Individual Components:**
```bash
# Deploy only managers
ansible-playbook -i inventory.yml playbooks/server_deploy.yml --tags wazuh_manager

# Deploy only indexers
ansible-playbook -i inventory.yml playbooks/server_deploy.yml --tags wazuh_indexer

# Deploy only dashboard
ansible-playbook -i inventory.yml playbooks/server_deploy.yml --tags wazuh_dashboard

# Deploy agents
ansible-playbook -i inventory.yml playbooks/agents_deploy.yml
```

**Validation and Testing:**
```bash
# Validate installation
ansible-playbook -i inventory.yml playbooks/validate.yml

# Check service status
ansible all -i inventory.yml -m service -a "name=wazuh-manager state=started"
```
</details>

## 🌍 Multi-Platform Support

### Platform-Specific Features

<details>
<summary><b>🔽 Ubuntu/Debian Optimizations</b></summary>

- APT package management with automatic updates
- UFW firewall configuration
- Systemd service management
- AppArmor profile configuration
- Unattended upgrades setup
</details>

<details>
<summary><b>🔽 CentOS/RHEL Optimizations</b></summary>

- YUM/DNF package management
- FirewallD configuration
- SELinux policy management
- SystemD hardening
- Subscription manager integration (RHEL)
</details>

<details>
<summary><b>🔽 Amazon Linux Optimizations</b></summary>

- YUM package management
- CloudWatch integration ready
- EC2 instance optimization
- AWS SSM agent compatibility
- EBS volume optimization
</details>

## 👥 Agent Management

### Mass Agent Deployment

<details>
<summary><b>🔽 Bulk Agent Operations</b></summary>

**Deploy 100+ Agents:**
```bash
# Configure agent inventory
cat >> inventory.yml << EOF
    production_agents:
      hosts:
        web-server-[01:20]:
          ansible_host: 10.0.1.[10:29]
          wazuh_agent_group: web-servers
        db-server-[01:10]:
          ansible_host: 10.0.2.[10:19]
          wazuh_agent_group: database-servers
EOF

# Deploy with groups
ansible-playbook -i inventory.yml playbooks/agents_deploy.yml --limit production_agents
```

**Agent Group Management:**
```bash
# Create custom agent groups
ansible-playbook -i inventory.yml playbooks/agents_deploy.yml -e "
wazuh_agent_groups:
  - name: web-servers
    rules: web_rules.xml
  - name: database-servers
    rules: db_rules.xml"
```
</details>

### Agent Update Management

<details>
<summary><b>🔽 Rolling Updates</b></summary>

```bash
# Rolling update with 20% batch size
ansible-playbook -i inventory.yml playbooks/agents_deploy.yml   --limit production_agents   --serial 20%   --tags update
```
</details>

## 📈 Scaling Considerations

### High Availability Setup

<details>
<summary><b>🔽 HA Architecture</b></summary>

```yaml
# Load Balancer Configuration
wazuh_dashboard_ha:
  enabled: true
  load_balancer: nginx
  backend_servers:
    - dashboard-01.example.com
    - dashboard-02.example.com

# Manager Cluster
wazuh_manager_cluster:
  enabled: true
  name: wazuh-cluster
  node_name: "{{ ansible_hostname }}"
  node_type: master  # or worker
  key: "{{ wazuh_cluster_key }}"
  bind_addr: "{{ ansible_default_ipv4.address }}"
  nodes:
    - manager-01.example.com
    - manager-02.example.com

# Indexer Cluster
wazuh_indexer_cluster:
  enabled: true
  name: wazuh-indexer-cluster
  master_nodes: 3
  data_nodes: 3
  replica_count: 1
```
</details>

### Performance Tuning

<details>
<summary><b>🔽 Resource Optimization</b></summary>

```yaml
# Manager Performance
wazuh_manager_performance:
  max_agents: 10000
  agent_buffer: 8192
  analysis_threads: 4
  remote_connection_timeout: 60

# Indexer Performance  
wazuh_indexer_performance:
  heap_size: "4g"
  max_open_files: 65536
  thread_pool_search_size: 8
  indices_memory_max_size: "40%"

# Dashboard Performance
wazuh_dashboard_performance:
  max_old_space_size: 4096
  worker_processes: auto
  keepalive_timeout: 65
```
</details>

## 🔄 Maintenance Operations

### Backup & Restore

<details>
<summary><b>🔽 Automated Backup</b></summary>

```bash
# Create backup playbook
ansible-playbook -i inventory.yml playbooks/backup.yml   -e "backup_destination=/backup/wazuh/$(date +%Y%m%d)"

# Restore from backup
ansible-playbook -i inventory.yml playbooks/restore.yml   -e "restore_source=/backup/wazuh/20231201"
```
</details>

### Updates & Upgrades

<details>
<summary><b>🔽 Version Management</b></summary>

```bash
# Update to specific version
ansible-playbook -i inventory.yml playbooks/server_deploy.yml   -e "wazuh_version=4.6.0"   --tags update

# Rolling restart for configuration changes
ansible-playbook -i inventory.yml playbooks/server_deploy.yml   --tags restart   --serial 1
```
</details>

## 🛠️ Troubleshooting

### Common Issues & Solutions

<details>
<summary><b>🔽 Connection Problems</b></summary>

**SSH Key Issues:**
```bash
# Generate and deploy SSH keys
ssh-keygen -t rsa -b 4096 -f ~/.ssh/wazuh_deploy
ssh-copy-id -i ~/.ssh/wazuh_deploy.pub user@target-host

# Test connectivity
ansible all -i inventory.yml -m ping
```

**Privilege Escalation:**
```bash
# Test sudo access
ansible all -i inventory.yml -m command -a "whoami" --become

# Configure passwordless sudo
echo "deploy ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/deploy
```
</details>

<details>
<summary><b>🔽 Installation Failures</b></summary>

**Repository Issues:**
```bash
# Clear package cache
ansible all -i inventory.yml -m command -a "apt clean" --become  # Ubuntu/Debian
ansible all -i inventory.yml -m command -a "yum clean all" --become  # CentOS/RHEL

# Verify repository configuration
ansible-playbook -i inventory.yml playbooks/validate.yml --tags repositories
```

**Service Startup Issues:**
```bash
# Check service status
ansible all -i inventory.yml -m systemd -a "name=wazuh-manager state=started" --become

# View logs
ansible all -i inventory.yml -m command -a "journalctl -u wazuh-manager --no-pager"
```
</details>

<details>
<summary><b>🔽 Performance Issues</b></summary>

**Resource Monitoring:**
```bash
# Check system resources
ansible all -i inventory.yml -m command -a "free -h && df -h && top -bn1"

# Monitor Wazuh processes
ansible all -i inventory.yml -m command -a "ps aux | grep wazuh"
```

**Network Connectivity:**
```bash
# Test network connectivity between components
ansible-playbook -i inventory.yml playbooks/validate.yml --tags connectivity

# Check firewall status
ansible all -i inventory.yml -m command -a "ufw status" --become  # Ubuntu
ansible all -i inventory.yml -m command -a "firewall-cmd --list-all" --become  # CentOS/RHEL
```
</details>

## 🔧 Custom Playbooks

### Creating Custom Deployments

<details>
<summary><b>🔽 Custom Playbook Example</b></summary>

```yaml
---
- name: Custom Wazuh Deployment
  hosts: wazuh_cluster
  become: yes
  vars:
    custom_rules_dir: /var/ossec/etc/rules
    custom_decoders_dir: /var/ossec/etc/decoders
  
  tasks:
    - name: Deploy custom rules
      copy:
        src: "{{ item }}"
        dest: "{{ custom_rules_dir }}/"
        owner: ossec
        group: ossec
        mode: '0640'
      with_fileglob:
        - "../files/rules/*.xml"
      notify: restart wazuh-manager
    
    - name: Deploy custom decoders
      copy:
        src: "{{ item }}"
        dest: "{{ custom_decoders_dir }}/"
        owner: ossec
        group: ossec
        mode: '0640'
      with_fileglob:
        - "../files/decoders/*.xml"
      notify: restart wazuh-manager
```
</details>

## 📊 Monitoring & Alerting

### Integration Examples

<details>
<summary><b>🔽 Prometheus Integration</b></summary>

```yaml
# Enable Prometheus metrics
wazuh_prometheus:
  enabled: true
  port: 9200
  endpoint: /metrics
  scrape_interval: 30s
```
</details>

<details>
<summary><b>🔽 Grafana Dashboards</b></summary>

```bash
# Deploy Grafana dashboards
ansible-playbook -i inventory.yml playbooks/monitoring.yml --tags grafana
```
</details>

## 🤝 Contributing

Found an issue or want to add a feature? Check our [Contributing Guidelines](../CONTRIBUTING.md).

## 📄 License

This project is licensed under the GPL-3.0 License - see the [LICENSE](../LICENSE) file for details.

## 🙏 Acknowledgments

- **Wazuh Team** for the excellent SIEM platform
- **Ansible Community** for automation best practices
- **Contributors** who help improve this project

---

**📞 Support:** For issues and questions, please use our [GitHub Issues](https://github.com/rodrigomarinsp/wazuh-unified-installer/issues)

**🔗 Documentation:** [Complete Wazuh Documentation](https://documentation.wazuh.com/)
