# SP3CTR
## Spectral Packet Capture & Threat Recognition

[![Version](https://img.shields.io/badge/version-0.5.8-blue.svg)](https://github.com/knifeyspooney/sp3ctr)
[![License](https://img.shields.io/badge/license-GPLv2-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey.svg)](#installation)

> A privacy-respecting packet visualization tool for understanding your system's network behavior

SP3CTR (pronounced "specter") is an ethical network monitoring tool that inspects your machine's outbound traffic, parses key protocols, and renders digestible metadata—all processed locally on your system. It's designed as a transparency tool for your own systems, not for compromising others.

## 🎯 Core Principles

- **🔐 Privacy First**: All processing happens locally. SP3CTR never phones home.
- **👁️ Transparency**: Understand how your systems communicate, not exploit others.
- **🛡️ Zero Exfiltration**: No telemetry, no cloud dependencies, no data collection.
- **✊ Free as in Speech**: Copyleft license ensures the tool remains free forever.

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🌐 **Cross-Platform** | Works on Windows, macOS, and Linux |
| 📡 **Real-Time Monitoring** | Live outbound traffic capture and analysis |
| 📦 **Protocol Parsing** | Deep packet inspection (Ethernet → IP → TCP/UDP) |
| 🎛️ **Visual Interface** | Human-friendly real-time packet events |
| 🧪 **Educational Focus** | Designed for learning and transparency |
| 💾 **PCAP Support** | Save and load packet captures


## 🚀 Quick Start

### Prerequisites

## ⚠️ Legal Note: Npcap Licensing

SP3CTR uses Npcap for packet capture on Windows.

🔒 Npcap is not open source and is only free for non-commercial use

🧾 If you're using SP3CTR in a commercial setting, you must obtain a license from Npcap's developers

📦 SP3CTR does not distribute Npcap—it only interfaces with it if you’ve installed it separately

🔁 You may try using WinPcap instead where functionality allows, but expect instability.

| Requirement | Version | Purpose |
|-------------|---------|---------|
| Python | 3.8+ | Backend runtime |
| pip | Latest | Package management |
| Modern Browser | Chrome/Firefox/Edge | Frontend interface |
| Packet Library | See below | Network capture |

### Platform-Specific Setup

#### Windows
1. Install [Npcap](https://nmap.org/npcap/) (recommended: enable "WinPcap API-compatible Mode")
2. Run Command Prompt as Administrator

#### Linux
```bash
# Debian/Ubuntu
sudo apt-get update && sudo apt-get install libpcap-dev python3-dev

# Fedora
sudo dnf install libpcap-devel python3-devel

# Arch Linux
sudo pacman -S libpcap python
```

#### macOS
```bash
# Install Xcode Command Line Tools (includes libpcap)
xcode-select --install
```

### Installation & Launch

1. **Install Dependencies**
   ```bash
   pip install scapy websockets
   ```

2. **Start Backend Server** (requires admin/root privileges)
   ```bash
   # Windows (as Administrator)
   python Sp3ctrCore.py
   
   # Linux/macOS
   sudo python3 Sp3ctrCore.py
   ```
   
   Expected output: `--- SP3CTR [version] - WebSocket Server Ready --- Listening on ws://localhost:8765`

3. **Launch Frontend**
   ```bash
   # In a new terminal
   python3 -m http.server 8000
   ```
   
   Open browser to: `http://localhost:8000/sp3ctrUI.html`

## 🔧 Troubleshooting

<details>
<summary><strong>Common Issues & Solutions</strong></summary>

### ModuleNotFoundError
- **Cause**: Missing Python packages
- **Solution**: `pip install scapy websockets` (activate virtual environment if using one)

### Permission Errors
- **Cause**: Insufficient privileges for packet capture
- **Solution**: Run backend with admin/root privileges (`sudo` on Unix, "Run as Administrator" on Windows)

### Npcap/libpcap Issues
- **Cause**: Packet capture library not properly installed
- **Solution**: Reinstall packet library, restart system if needed

### Frontend Connection Problems
- **Symptoms**: Cannot connect to backend
- **Checklist**:
  - ✅ Backend server is running
  - ✅ Accessing via `http://localhost:8000` (not `file://`)
  - ✅ Check browser console (F12) for errors
  - ✅ Firewall not blocking port 8765

### Empty Interface List
- **Cause**: Packet library installation issues
- **Solution**: Check backend terminal for errors, reinstall packet library

</details>

## 📋 Project Status

**Current Stage**: Minimum Viable Product (MVP) ✅

**Completed Features:**
- ✅ Core packet sniffing functionality
- ✅ PCAP save/load capabilities
- ✅ Basic filtering system
- ✅ Client-side packet filtering

**In Development:**
- 🔄 UI/UX improvements (active iteration)
- 🔄 Enhanced packet dissection
- 🔄 Threat intelligence integration

## 🛣️ Roadmap

### Short-Term Goals
- [ ] **Enhanced Packet Analysis**: More detailed protocol dissection
- [ ] **Threat Intelligence**: Flag known malicious IPs and domains
- [ ] **Spectral Visualizations**: Network traffic visualization dashboard
- [ ] **Performance Optimization**: Improved handling of high-traffic scenarios

### Future Integration
- **SH4DOW**: Secure Honeypot for Adversary Deception and Operational Warning
- **F0RT**: Fortified Operations & Response Toolkit (a functional GUI combining many tools)

## 🤝 Contributing

We welcome contributions from the community! Here's how you can help:

### Ways to Contribute
- **🐛 Bug Reports**: Found an issue? [Open an issue](https://github.com/knifeyspooney/sp3ctr/issues) with reproduction steps
- **💡 Feature Requests**: Have an idea? Start a discussion in our issues
- **🔧 Code Contributions**: Fork the repo and submit a pull request
- **📚 Documentation**: Help improve our docs and examples

### Development Guidelines
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

**GNU General Public License v2.0 (GPLv2)**

SP3CTR is copyleft software. You're free to use, study, modify, and distribute it, but any derivative works must also be open source under the same license.

**In Plain English**: If you build on SP3CTR, your code must also be open source. No exceptions. This ensures the tool remains free forever.

[Read the full license]

## 📞 Contact & Resources

- **Author**: [KnifeySpooneyy]
- **Documentation**: [PHILOSOPHY.md] | [ROADMAP.md]
- **Issues**: [GitHub Issues](https://github.com/knifeyspooney/sp3ctr/issues)

---

<div align="center">
<strong>Built with ❤️ for network transparency and privacy</strong>
</div>
