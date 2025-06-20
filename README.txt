# IoT Security Scanner – Automated Network Discovery and Vulnerability Detection

A Python-based tool with a web interface for scanning local networks to discover IoT devices, identify open ports and services, check for weak SSH credentials, and detect known vulnerabilities (CVEs). Generates both web-based and downloadable PDF reports.

---

## 🔍 Features

* ⚡ Fast ARP and Nmap-based network discovery
* 🔢 Port scanning and service version detection
* ⚡ CVE lookup using Vulners API
* 🔐 Weak SSH credential detection
* 📄 Dynamic PDF report generation
* 🌐 Web-based user interface via Flask
* 🔁 Mitigation recommendations for detected vulnerabilities

---

## 📚 Technologies Used

| Component            | Library / Tool                 |
| -------------------- | ------------------------------ |
| Web Framework        | Flask                          |
| Network Scanning     | Scapy, python-nmap             |
| CVE Lookup           | Vulners API                    |
| SSH Credential Check | Paramiko (or custom SSH logic) |
| PDF Generation       | ReportLab                      |
| Frontend Templating  | Jinja2 (Flask templates)       |

---

## 🛋️ Project Structure

```
project/
├── app.py                    # Main Flask app
├── templates/                # HTML files
│   ├── index.html
│   └── results.html
├── scanner/
│   ├── network_discovery.py  # ARP/Nmap device and port discovery
│   ├── cve_lookup.py         # Vulners CVE API integration
│   ├── weak_credentials.py   # SSH weak credentials checker
│   └── reporting.py          # PDF report generator
```

---

## ⚙️ Installation

### 1. Clone the repository:

```bash
git clone https://github.com/zehra-jm/IOT-vulnerabilities-Scanner cd iot-security-scanner
```

### 2. Install required Python packages:

```bash
pip install flask scapy python-nmap vulners reportlab paramiko
```

### 3. Ensure Nmap is installed:

* Download and install [Nmap](https://nmap.org/download.html)
* Make sure it's in your system PATH (can run `nmap` from terminal)

### 4. Set your Vulners API key:

Edit `scanner/cve_lookup.py`:

```python
API_KEY = "YOUR_VULNERS_API_KEY"
```

---

## 🚀 Usage

### 1. Start the Flask server:

```bash
python app.py
```

### 2. In your browser, go to:

```
http://127.0.0.1:5000
```

### 3. Enter subnet (e.g., `192.168.1.0/24`) to scan your network.

### 4. After scan:

* View open ports, CVEs, weak credentials
* Download full PDF report

---

## 🔢 Sample Output

```json
{
  "ip": "192.168.0.10",
  "mac": "00:1C:B3:AB:CD:EF",
  "device_name": "Apple Device",
  "open_ports": [
    {
      "port": 22,
      "service": "OpenSSH 7.4",
      "cves": ["CVE-2018-15473"]
    }
  ],
  "weak_credentials": true,
  "credentials_used": ["root", "admin"],
  "mitigation_recommendations": ["Change default credentials", "Disable port 23"]
}
```

---

## 📅 Future Improvements

* Add CVSS scores and severity filters
* Include SNMP and UPnP device discovery
* Store scan history in database
* Export reports in JSON or Excel

---

## 🚪 License

MIT License

---

## 🙏 Acknowledgements

* [Nmap](https://nmap.org)
* [Scapy](https://scapy.net)
* [Vulners API](https://vulners.com)
* [ReportLab](https://www.reportlab.com/)
