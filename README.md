---

## ⚠️ **Disclaimer**

**For educational and authorized penetration testing purposes only.** Users are responsible for obtaining proper authorization before using this tool on any network. The creator is not responsible for any misuse of this software.

---

## 🌟 **Features**

### 🎯 **Core DNS Spoofing**
- **Advanced Targeting**: Intelligent DNS redirection with customizable rules
- **Real-time Manipulation**: Live DNS response modification
- **Multi-target Support**: Simultaneous spoofing of multiple domains
- **Success Rate Tracking**: Monitor and log successful DNS redirects

### 🌐 **Web Template Management**
- **HTML Template Library**: Pre-built phishing and security testing templates
- **Apache Integration**: Built-in Apache server for HTML serving
- **Live Preview**: Real-time HTML preview functionality
- **Template Customization**: Easy editing and customization of templates

### 🔍 **Network Discovery & Scanning**
- **Interface Detection**: Automatic network interface discovery
- **Network Range Detection**: Automatic gateway and network range configuration
- **Ping Tools**: Comprehensive network testing utilities
- **Network Scanner**: Advanced host and port scanning capabilities

### 📊 **Real-time Monitoring**
- **Live Statistics**: Real-time traffic monitoring and analysis
- **Success Metrics**: Track DNS spoofing success rates
- **Traffic Analysis**: Monitor active DNS requests and responses
- **Target Status**: Visual indication of active redirections

### 💻 **Kali Linux Console**
- **Command Execution**: Integrated terminal for Kali Linux commands
- **Command Library**: Pre-built security testing command collection
- **Favorites System**: Save frequently used commands
- **Real-time Output**: Live command execution feedback

### 🔧 **Security Tools Suite**
- **Port Scanner**: Advanced TCP/UDP/SYN scanning capabilities
- **WHOIS Lookup**: Domain and IP information gathering
- **DNS Lookup**: Comprehensive DNS record analysis
- **MAC Changer**: Network interface MAC address modification
- **BeEF Integration**: Browser Exploitation Framework integration

### 🎨 **Modern Interface**
- **Dark Theme**: Professional dark mode interface
- **Multi-tab Design**: Organized tool layout with intuitive navigation
- **Real-time Updates**: Smooth animations and live feedback

---

## 🛠️ **Installation**

### **Prerequisites**
- Python 3.7 or higher
- Administrative privileges (for network operations)
- Compatible operating system:  Linux,

### **Required Dependencies**
```bash
pip install tkinter scapy
```

### **Download & Setup**
1. **Clone the repository:**
   ```bash
   git clone https://github.com/ScreamsTerror/DNS_ScreamWare.git
   cd ScreamWare
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application:**
   ```bash
   python Screamware.py
   ```

### **Platform-specific Setup**

#### **Windows:**
- Run as Administrator for full network functionality
- Windows Defender may flag the tool (add to exceptions)
- Compatible with Windows 10/11

#### **Linux (Kali/Ubuntu/Debian):**
```bash
sudo apt update
sudo apt install python3-tk python3-pip
sudo pip3 install -r requirements.txt
sudo python3 DNSGUI.py
```

#### **macOS:**
```bash
brew install python-tk
pip3 install -r requirements.txt
python3 DNSGUI.py
```

---

## 🚀 **Usage**

### **Quick Start Guide**

1. **Launch ScreamWare** with administrative privileges
2. **Select Network Interface** from the Main tab
3. **Configure Target Settings** (IP addresses, domains)
4. **Start DNS Spoofing** using the main control panel
5. **Monitor Results** in the Monitor & Stats tab

### **Main Configuration**

#### **DNS Spoofing Setup:**
1. Choose your network interface
2. Set your IP address (auto-detected)
3. Configure target IP and gateway
4. Add domains to spoof in Domain Management
5. Enable DNS spoofing

#### **HTML Template Usage:**
1. Select or create HTML templates
2. Start Apache server for serving
3. Use "Preview via Apache" for testing
4. Monitor template serving statistics

### **Advanced Features**

#### **Network Discovery:**
- Auto-detect network configuration
- Scan for active hosts
- Analyze network topology
- Export scan results

#### **Console Commands:**
- Access pre-built Kali commands
- Execute custom commands
- Save command favorites
- Real-time output monitoring

#### **Security Tools:**
- Port scanning with customizable options
- WHOIS and DNS lookups
- MAC address modification
- BeEF integration for browser testing

---

## 🎯 **Use Cases**

### **Educational Purposes:**
- Learn DNS protocols and security
- Understand network vulnerabilities
- Practice ethical hacking techniques
- Study network traffic analysis

### **Penetration Testing:**
- DNS spoofing security assessments
- Network vulnerability testing
- Social engineering awareness training
- Security tool demonstration

### **Network Administration:**
- Network monitoring and analysis
- DNS configuration testing
- Network troubleshooting
- Security auditing

---

## 🏗️ **Technical Architecture**

### **Core Components:**
- **DNS Engine**: Custom DNS response manipulation
- **Network Scanner**: Multi-protocol network discovery
- **Web Server**: Integrated Apache for HTML serving
- **Command Console**: Cross-platform command execution
- **Monitoring System**: Real-time statistics and logging

### **Supported Protocols:**
- DNS (UDP/TCP)
- HTTP/HTTPS
- ICMP (Ping)
- TCP/UDP (Port scanning)
- ARP (Network discovery)

---

## 🔧 **Configuration**

### **Default Settings:**
- **DNS Server Port**: 53
- **HTTP Server Port**: 80
- **Network Interface**: Auto-detection
- **Log Level**: INFO

### **Customization:**
- Edit configuration files in `/config/`
- Modify HTML templates in `/templates/`
- Customize themes in `/themes/`
- Configure command libraries in `/commands/`

---

## 🐛 **Troubleshooting**

### **Common Issues:**

#### **DNS Spoofing Not Working:**
- Ensure running with administrative privileges
- Check network interface configuration
- Verify firewall settings
- Confirm target IP addresses

#### **Apache Server Issues:**
- Check if port 80 is available
- Verify permissions for HTML directory
- Check for conflicting Apache installations
- Review error logs

#### **Network Discovery Problems:**
- Ensure proper network interface selection
- Check firewall blocking ICMP
- Verify network cable/Wi-Fi connection
- Try different scanning methods

### **Windows-specific:**
- **"Access Denied"**: Run as Administrator
- **"Windows Defender Alert":** Add to exceptions
- **"Port Already in Use":** Change port numbers

### **Linux-specific:**
- **"Permission Denied":** Use `sudo`
- **"Module Not Found":** Install missing dependencies
- **"Interface Not Found":** Check interface names with `ip addr`

---

## 📝 **Changelog**

### **Version 2.0 - Enhanced Edition**
- ✅ Added Credits tab with creator information
- ✅ Enhanced Key Features with interactive design
- ✅ Improved network auto-detection
- ✅ Added BeEF integration
- ✅ Enhanced console with command favorites
- ✅ Improved UI with smoother animations
- ✅ Added comprehensive ping tools
- ✅ Enhanced error handling and logging

### **Version 1.0 - Initial Release**
- ✅ Core DNS spoofing functionality
- ✅ Basic network discovery
- ✅ HTML template management
- ✅ Simple monitoring interface

---

## 🤝 **Contributing**



### **Development Guidelines:**
- Follow PEP 8 Python style guidelines
- Add comments for complex functionality
- Update documentation for new features
- Use meaningful commit messages

### **Bug Reports:**
- Use the GitHub Issues section
- Include operating system and Python version
- Provide detailed error messages
- Include steps to reproduce the issue
- Attach relevant screenshots if applicable

---

## ⚖️ **License & Legal**

### **Educational Use Only**
This tool is provided **for educational and authorized penetration testing purposes only**. Users must:

- ✅ Obtain proper authorization before testing
- ✅ Use only on networks you own or have permission to test
- ✅ Follow all applicable laws and regulations
- ✅ Take responsibility for your actions

### **Prohibited Uses:**
- ❌ Unauthorized network access
- ❌ Illegal hacking activities
- ❌ Identity theft or fraud
- ❌ Any malicious or harmful activities

### **Liability**
The creator of ScreamWare is **not responsible** for any misuse, damage, or illegal activities conducted with this tool. Users assume full responsibility for their actions.

---

## 🙏 **Credits & Acknowledgments**

<div align="center">

### **Created by:**
**🎭 ScreamsTerror**
*Cybersecurity Researcher & Penetration Testing Tools Developer*

### **Special Thanks:**
- The open-source security community
- Python developers worldwide
- Security researchers and ethical hackers
- Beta testers and feedback providers

### **Technologies Used:**
- [Python](https://www.python.org/) - Core development language
- [Tkinter](https://docs.python.org/3/library/tkinter.html) - GUI framework
- [Scapy](https://scapy.net/) - Network packet manipulation
- [Apache](https://httpd.apache.org/) - Web server integration
- [Nmap](https://nmap.org/) - Network scanning (external)
