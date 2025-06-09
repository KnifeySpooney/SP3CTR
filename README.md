# SP3CTR: Spectral Packet Capture & Threat Recognition V 0.1.2

[![License: GPL v2](https://img.shields.io/badge/license-GPLv2-blue.svg)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)

**SP3CTR** (pronounced *Specter*) is a privacy-respecting packet visualization tool that inspects your own machine's outbound traffic, parses key protocols, and renders digestible, locally-processed metadata. It does *not* exfiltrate data, perform exploits, or rely on external APIs. It is deliberately scoped.

This is not a tool for pen testing, fuzzing, or intrusion  
It’s a transparency tool—for yourself, and your own systems  
It’s minimalist, local, and human-first  

> 🔐 All logic runs locally. SP3CTR never phones home.  
> 🧭 See [PHILOSOPHY.md] for a full ethical breakdown.

# **💭 Philosophy and Intent**

SP3CTR is built on a deliberate rejection of bloat, surveillance, and opacity. It is not a stripped-down Wireshark clone—it is an ethical alternative with strict constraints. It’s designed to help people understand how their own systems communicate outward, not how to compromise others.

    ✊ This project is free as in speech, not just free as in beer.
    ✍️ Copyleft is enforced—see license.

## 🧰 Features

- 🌐 Cross-platform: works on macOS, Windows, and Linux (with caveats)
- 🛡 Zero exfiltration: no telemetry, no cloud dependencies
- 📡 Live traffic capture: outbound packets only
- 📦 Layered protocol parsing: Ethernet → IP → TCP/UDP
- 🎛 Human-friendly visual output: real-time packet events + host summaries
- 🧪 Educational and ethical by design

## 🧪 Project Status

SP3CTR has achieved MVP. Core sniffing, PCAP saves, and basic filters are (finally) functional. UI/UX remains in flux—display logic is undergoing live iteration, and thus user-facing instructions are intentionally deferred until v1.0.

> 🧭 View the [ROADMAP.md] to see what's coming next  
> 💡 Read [PHILOSOPHY.md] to understand why SP3CTR exists at all


---

## 🔧 Features at a Glance

✅ Dark-mode UI for readability  
✅ Detects interfaces automatically  
✅ Live traffic streamed over WebSocket  
✅ Responsive, scrollable packet table  
✅ Human-friendly packet summaries  
✅ Shows:

- 🕒 Timestamps
- 🧭 Source & destination (IP or MAC)
- 🔢 Ports (if applicable)
- 🧬 Protocol (TCP, UDP, ICMP, etc.)
- 📦 Packet size
- ✏️ Protocol summary line
- 🖍️ Color-coded rows by protocol

⚡ Keeps UI smooth using Python threading  
🌐 Works entirely in your browser

---

## 📥 Install & Run

### 📦 Requirements:

- ✅ Python 3.8+
- ✅ pip
- ✅ Chrome, Firefox, or Edge
- ✅ `Npcap` (Windows) or `libpcap` (Linux/macOS)

## 🛠️ Tech Stack

* **Backend:** Python 3
    * Scapy: For packet capture and manipulation.
    * Websockets: For real-time communication with the frontend.
    * Asyncio: For asynchronous operations in the WebSocket server.
    * Threading: To run Scapy sniffing without blocking the server.
* **Frontend:** HTML, CSS (Tailwind CSS), JavaScript
    * Vanilla JS for WebSocket client logic and DOM manipulation.

## ⚙️ Setup and Installation

Follow these steps to get SP3CTR up and running on your local machine.

### Prerequisites

* **Python 3.8+:** Ensure you have a compatible Python version installed.
* **pip:** Python package installer.
* **Web Browser:** A modern web browser (Chrome, Firefox, Edge, etc.).
* **Packet Capture Library (Npcap/libpcap):**
    * **Windows:** **Npcap** is required. Download and install it from the [Npcap website](https://npcap.com/#download). It's recommended to install it with "WinPcap API-compatible Mode" if you use other tools that might rely on WinPcap.
    * **Linux:** **libpcap** is usually required. Install it using your distribution's package manager:
        * Debian/Ubuntu: `sudo apt-get update && sudo apt-get install libpcap-dev python3-dev`
        * Fedora: `sudo dnf install libpcap-devel python3-devel`
        * Arch Linux: `sudo pacman -S libpcap python`
    * **macOS:** libpcap is typically pre-installed with Xcode Command Line Tools. If not, installing Xcode Command Line Tools should provide it: `xcode-select --install`

### Running SP3CTR

1.  **Start the Python Backend (WebSocket Server):**
    Open a terminal, navigate to your project directory, activate your virtual environment (if you created one), and run the Python backend script.
    **Important:** Packet sniffing requires administrator/root privileges.
    * **Windows:** Open your terminal (Command Prompt or PowerShell) **as Administrator**.
        ```bash
        python Sp3ctrCore.py
        ```
    * **Linux/macOS:**
        ```bash
        sudo python3 Sp3ctrCore.py
        ```
    You should see output similar to:
    ```
    --- SP3CTR [version] - WebSocket Server Ready ---
    Listening on ws://localhost:8765
    ```

2.  **Serve and Open the HTML Frontend:**
    The HTML frontend needs to be served via an HTTP server for WebSocket connections to work correctly from the browser.
    * Open a **new terminal window/tab**.
    * Navigate to the directory where your `sp3ctr_frontend.html` (or your HTML file name) is located.
    * Start Python's built-in HTTP server:
        ```bash
        # If you use python3 primarily:
        python3 -m http.server 8000
        # Or if you use python primarily:
        python -m http.server 8000
        ```
        (You can use a different port if 8000 is busy, just not 8765).
    * Open your web browser and navigate to:
        `http://localhost:8000/sp3ctrUI.html`
      

3.  **Using SP3CTR:**
    * The web page should connect to the WebSocket server.
    * The "Network Interface" dropdown should populate.
    * Select an interface and click "Start Capture".
    * Packets should start appearing in the table.
    * Click "Stop Capture" to halt sniffing.

## 🩺 Troubleshooting

* **`ModuleNotFoundError: No module named 'scapy'` (or `websockets`):**
    * Ensure you have activated your virtual environment (if used) before running `pip install`.
    * Make sure you are running the Python script using the same Python interpreter/environment where the packages were installed. Check your IDE's interpreter settings (e.g., in PyCharm or VS Code).
    * Try reinstalling the package: `pip uninstall scapy websockets && pip install scapy websockets`

* **Python Backend: `PermissionError: [Errno 1] Operation not permitted` or `Socket error: [Errno 13] Permission denied` (or similar):**
    * This means Scapy doesn't have the necessary permissions to sniff packets.
    * **Solution:** Run the Python backend script with administrator/root privileges (e.g., `sudo python3 Sp3ctrCore.py` on Linux/macOS, or "Run as administrator" for your terminal on Windows).

* **Python Backend: Errors related to `libpcap` or `Npcap` not found/not working:**
    * **Scapy relies on a packet capture library like Npcap (Windows) or libpcap (Linux/macOS).**
    * **Windows:**
        * Ensure **Npcap** is installed correctly. Download from [Npcap website](https://npcap.com/#download).
        * During Npcap installation, ensure "WinPcap API-compatible Mode" is checked if you have older tools that might need it, though Scapy generally works well with Npcap's native mode.
        * You might need to restart your system after installing/reinstalling Npcap.
    * **Linux:**
        * Ensure `libpcap-dev` (or equivalent like `libpcap-devel`) is installed. For example: `sudo apt-get install libpcap-dev` or `sudo dnf install libpcap-devel`.
        * Sometimes, the issue can be with user permissions to access network devices even with sudo. This is less common for simple Scapy sniffing but can occur in complex setups.
    * **macOS:**
        * libpcap should be included with Xcode Command Line Tools. If you encounter issues, try reinstalling them: `xcode-select --install`.
        * Ensure your user has permissions. Running with `sudo` is generally required.

* **HTML Frontend: "Status: Connecting to WebSocket..." or "Status: Connection Error" and no interfaces load:**
    * **Verify the Python WebSocket server is running** and you see the "Listening on ws://localhost:8765" message in its terminal.
    * **Ensure you are serving the HTML file via an HTTP server** (e.g., `python -m http.server 8000`) and accessing it via `http://localhost:8000/your_file.html`, NOT via `file:///...`. Browsers restrict WebSocket connections from `file:///` origins.
    * **Check the browser's Developer Console (F12)** for WebSocket connection errors or JavaScript errors.
    * **Firewall:** Ensure your local firewall isn't blocking connections on port 8765 or 8000 for `localhost`. This is less common for localhost connections but possible.

* **No Interfaces Listed in Dropdown (but server seems to be running):**
    * Check the Python backend terminal for any errors during interface discovery.
    * Ensure Npcap/libpcap is functioning correctly, as Scapy relies on it to list interfaces.

## 📜 Short-Term Enhancements Roadmap

* More detailed packet dissection and display.
* Client-side filtering of displayed packets. ✅
* Basic threat intelligence integration (e.g., flagging known malicious IPs).
* Saving ✅ and loading packet captures (PCAP format). 
* Visualizations of network traffic ("spectral" display).
* Integration with SH4DOW and F0RT components.

## 🤝 Contributing



## 📝 License

GPL2

---
