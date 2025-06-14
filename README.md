# RegSeek

> Advanced Windows Registry forensics reference and search engine

## What is RegSeek?

RegSeek is a comprehensive reference tool for Windows Registry forensics artifacts. It provides detailed information about registry locations that are valuable for digital forensics investigations, incident response, and malware analysis including:

- **Forensic limitations** and what artifacts **cannot prove**
- **Correlation requirements** for definitive conclusions  
- **Analysis tools** and investigation techniques
- **Real-world examples** and data structures
- **Windows version compatibility**

## Artifact Categories

| Category | Count | Key Use Cases |
|----------|-------|---------------|
| **Program Execution** | 15+ | Application usage, malware execution tracking |
| **Browser Activity** | 8+ | Web browsing history, security zone configurations |
| **User Behavior** | 20+ | Application usage patterns, cloud storage sync |
| **File Operations** | 12+ | Recent documents, file associations, jump lists |
| **External Storage** | 5+ | USB device history, removable media tracking |
| **Persistence Methods** | 10+ | Autostart locations, service configurations |
| **System Modifications** | 15+ | Windows settings, security configurations |
| **Network Infrastructure** | 12+ | Network connections, DNS configurations |
| **Remote Access** | 8+ | RDP settings, VPN configurations |
| **Security Monitoring** | 10+ | Windows Defender, audit configurations |
| **Communication Apps** | 7+ | Teams, Discord, email client settings |
| **Virtualization** | 6+ | VMware, VirtualBox, container settings |
| **Authentication** | 4+ | Credential providers, account information |

## Key Features

### **Advanced Search & Filtering**
- Full-text search across artifact titles, descriptions, and registry paths
- Filter by category, criticality level, Windows version, and registry hive
- Investigation type filtering (incident response, malware analysis, etc.)

### **Forensic Intelligence**
- **Limitations warnings**: What each artifact CANNOT prove
- **Correlation requirements**: Additional artifacts needed for conclusions
- **Criticality levels**: High/Medium/Low priority classifications
- **Tool recommendations**: Specific analysis tools for each artifact

### **Investigation-Focused**
- Organized by forensic investigation types
- Real-world examples and data structures
- Windows version compatibility information
- Direct links to analysis tools and references


# Quick Start

### Using the Web Interface

Visit the deployed site: [https://regseek.github.io/](https://regseek.github.io/)

### Local Development

1. **Clone the repository**

   ```bash
   git clone https://github.com/regseek/regseek.git
   cd regseek
   ```

2. **Install dependencies**

   ```bash
   pip install -r scripts/requirements.txt
   ```

3. **Validate artifacts**

   ```bash
   python scripts/validate.py
   ```

4. **Build the site**

   ```bash
   python scripts/build.py
   ```

5. **Open the site**
   ```bash
   # Open site/index.html in your browser
   open site/index.html  # macOS
   start site/index.html # Windows
   ```

# Contributing

We welcome contributions from the digital forensics community! See our [Contributing Guidelines](CONTRIBUTING.md) for details on:

- Adding new registry artifacts
- Improving existing documentation
- Suggesting new features or categories
- Reporting bugs or inaccuracies

# License

This project is licensed under GPL-3.0 license - see [LICENSE](LICENSE) file for details.

*RegSeek is a comprehensive Windows Registry forensics reference tool designed to assist digital forensics professionals, incident response teams, and cybersecurity analysts in their investigations.*
