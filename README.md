# 🛡️ NetProbe Enterprise Scanner

![Python](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python)
![Security](https://img.shields.io/badge/Focus-Cyber_Security-red?style=for-the-badge&logo=kalilinux)

A multi-threaded network reconnaissance tool designed for efficient vulnerability assessment. Features real-time logging, Geo-Location intelligence, and CVE correlation.

## 🚀 Key Features
* **Auto-Dependency Management:** Bundles the Nmap installer and auto-installs it if missing.
* **Port Scanning:** Quick, Standard, and Full-Port modes with status indicators.
* **Vulnerability Check:** Automates Nmap scripting engine (`--script vuln`) to identify potential exploits.
* **Geo-Intelligence:** Resolves IPs to Physical Location + ISP.
* **HTML Reporting:** Exports comprehensive dark-mode security audits.

## 🛠️ Usage
1.  **Download:** Get the latest `.exe` from the [Releases](https://github.com/YOUR_USERNAME/NetProbe-Scanner/releases) page.
2.  **Run:** Double click `NetProbe_v9_Installer.exe`.
3.  **Scan:** Enter a Target IP or Subnet.

## ⚙️ Development
To run from source:
```bash
git clone [https://github.com/YOUR_USERNAME/NetProbe-Scanner.git](https://github.com/YOUR_USERNAME/NetProbe-Scanner.git)
pip install customtkinter python-nmap requests
python netprobe.py