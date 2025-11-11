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

**148 artifacts across 14 categories**

| Category | Count | Key Use Cases |
|----------|-------|---------------|
| **AI Features** | 2 | Windows Copilot, Recall AI configuration |
| **Authentication** | 6 | Credential providers, SAM database, LSA protection |
| **Browser Activity** | 8 | Web browsing history, security zone configurations |
| **Communication Apps** | 8 | Teams, Discord, Slack, Zoom, email clients |
| **External Storage** | 5 | USB device history, removable media tracking |
| **File Operations** | 12 | Recent documents, file associations, jump lists |
| **Network Infrastructure** | 12 | Network connections, DNS, WiFi profiles |
| **Persistence Methods** | 15 | Autostart locations, service configurations |
| **Program Execution** | 13 | Application usage, malware execution tracking |
| **Remote Access** | 6 | RDP settings, VPN configurations, TeamViewer |
| **Security Monitoring** | 15 | Windows Defender, firewall, audit configurations |
| **System Modifications** | 22 | Windows settings, installed programs, updates |
| **User Behaviour** | 17 | Application usage patterns, cloud storage sync |
| **Virtualization** | 7 | VMware, VirtualBox, Docker, WSL, containers |

## Key Features

### **Advanced Search & Filtering**
- Full-text search across artifact titles, descriptions, and registry paths
- Filter by category, criticality level, Windows version, and registry hive
- Investigation type filtering (incident response, malware analysis, etc.)

### **Forensic Intelligence**
- **Limitations warnings**: What each artifact CANNOT prove
- **Correlation requirements**: Additional artifacts needed for conclusions
- **Criticality levels**: High (74) / Medium (58) / Low (16) priority classifications

### **Investigation-Focused**
- Organized by forensic investigation types
- Real-world examples and data structures
- Windows version compatibility information
- Direct links to analysis tools and references


## Quick Start

### Using the Web Interface

Visit the deployed site: **[https://regseek.github.io/](https://regseek.github.io/)**

The site is a static web application that works entirely in your browser - no backend required!

### Local Development

1. **Clone the repository**

   ```bash
   git clone https://github.com/RegSeek/regseek.github.io.git
   cd regseek.github.io
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

## Contributing

We welcome contributions from the digital forensics community! See our [Contributing Guidelines](CONTRIBUTING.md) for details on:

- Adding new registry artifacts
- Improving existing documentation
- Suggesting new features or categories
- Reporting bugs or inaccuracies

## License

This project is licensed under GPL-3.0 license - see [LICENSE](LICENSE) file for details.

---

*RegSeek is a comprehensive Windows Registry forensics reference tool designed to assist digital forensics professionals, incident response teams, and cybersecurity analysts in their investigations.*
