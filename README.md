# Recon Framework

A modular Python reconnaissance framework that automates asset discovery, service enumeration, and vulnerability assessment for authorized penetration testing and bug bounty engagements.



---

## Features

- Interactive CLI interface
- Multiple scan profiles
- Fast port discovery
- Service and version detection
- NSE script execution
- NetBIOS enumeration
- Web technology fingerprinting
- Vulnerability scanning with Nuclei
- Optional Nikto web server assessment
- Modular architecture for easy extension
- Organized scan results and reporting

---

## Scan Profiles

### 1. Nmap Only

Best for detailed service enumeration.

**Includes:**
- Host discovery
- Open port detection
- Service version detection (`-sV`)
- Default NSE scripts (`-sC`)
- OS detection (optional)
- Service enumeration

**Recommended when**
- Enumerating a known target
- Identifying running services
- Initial penetration testing

---

### 2. Nmap + Masscan

Fast port discovery followed by detailed enumeration.

**Workflow**

Masscan →
Discover open ports quickly

↓

Nmap →
Service detection, version detection, NSE scripts

**Recommended when**
- Large attack surfaces
- External infrastructure
- Bug bounty reconnaissance

---

### 3. Nmap + Nbtscan

Service enumeration with NetBIOS discovery.

**Includes**

- Nmap service detection
- Version detection
- NSE scripts
- NetBIOS hostname discovery
- Windows workgroup/domain information

**Useful for**

- Internal assessments
- Active Directory environments
- Windows networks

---

### 4. Nmap + Nuclei

Service enumeration followed by vulnerability scanning.

**Workflow**

Nmap →
Identify exposed services

↓

Nuclei →
Run community vulnerability templates

**Useful for**

- Bug bounty
- Web applications
- Continuous security assessments

---

### 5. Full Scan

Complete reconnaissance workflow.

**Includes**

- Masscan
- Nmap
- Nbtscan
- WhatWeb
- Nuclei
- Optional Nikto

**Workflow**

Masscan
↓

Nmap
↓

Nbtscan
↓

WhatWeb
↓

Nuclei
↓

(Optional) Nikto

This profile performs comprehensive reconnaissance, technology fingerprinting, service enumeration, and vulnerability assessment.


<img width="717" height="426" alt="Screenshot 2026-06-30 013752" src="https://github.com/user-attachments/assets/855dde2a-18aa-4215-acfc-31b0f923d773" />


---

## Integrated Tools

| Tool | Purpose |
|-------|----------|
| **Masscan** | Ultra-fast TCP port scanner used for rapid port discovery. |
| **Nmap** | Service detection, version identification, operating system detection, and NSE scripting. |
| **Nbtscan** | Enumerates NetBIOS names, Windows hosts, and workgroup/domain information. |
| **WhatWeb** | Identifies web technologies, frameworks, CMS platforms, and server software. |
| **Nuclei** | Template-based vulnerability scanner for detecting known vulnerabilities and security misconfigurations. |
| **Nikto** *(Optional)* | Web server security scanner that identifies outdated software, dangerous files, and common web server issues. |

---

## Installation

```bash
git clone https://github.com/<your-username>/recon-framework.git
cd recon-framework
python main.py
```

On first launch, the framework automatically:

- Detects missing reconnaissance tools
- Installs supported dependencies
- Verifies the environment
- Starts the interactive CLI

> **Note:** Automatic installation of system packages may require `sudo` privileges.

## Usage

```bash
python main.py
```

Select one of the available scan profiles and provide the target host or domain.

---

## Requirements

- Python 3.11+
- Nmap
- Masscan
- Nbtscan
- WhatWeb
- Nuclei
- Nikto (Optional)

---

<img width="717" height="949" alt="Screenshot 2026-06-30 013752" src="https://github.com/user-attachments/assets/ca38eae4-4291-4efa-8093-acd6c47f5ae3" />



## Saved Reports
Reports will be automatically generated and saved in reports directory.



<img width="1269" height="411" alt="Screenshot 2026-06-30 014654" src="https://github.com/user-attachments/assets/07862fa3-19c9-41e8-86e6-07ae2812b9a2" />



## Disclaimer

This framework is intended for **authorized security testing, educational purposes, and bug bounty programs**. Always obtain explicit permission before scanning or testing systems you do not own or administer.

---

## License

This project is licensed under the MIT License. See the  [LICENSE](LICENSE) file for details.
