# Automated Security Triage Playbook (Python & VirusTotal API)

## 📌 Project Overview
As a cybersecurity new graduate, I developed this project to demonstrate the core competencies required for a **SOAR impementation**. 

This project automates the initial **Triage and Enrichment** phase of an incident response workflow. By using Python to bridge a local environment with a global Threat Intelligence source (VirusTotal), I have created a tool that reduces the "Mean Time to Respond" (MTTR) by eliminating the need for manual URL lookups.

---

## 🛠️ Skills & Technologies Demonstrated
* **Programming:** Python 3 (Logic, API requests, Data encoding).
* **Environment:** Linux (Ubuntu/Debian) on Lenovo ThinkPad T480.
* **Integrations:** VirusTotal v3 API (CTI - Cyber Threat Intelligence).
* **DevOps/Ops:** Git version control, .gitignore secret management, and Python Virtual Environments (venv).
* **Security Logic:** Threshold-based alerting to reduce False Positives.

---

## 🚀 How the Playbook Works
The script follows a 4-stage "Playbook" logic common in enterprise SOAR platforms like Chronicle SOAR or Palo Alto XSOAR:

1. **Trigger:** The script accepts a suspicious URL as input (simulating an alert from a SIEM or Email gateway).
2. **Enrichment:** The URL is Base64 encoded and sent to the VirusTotal API to gather intelligence from 70+ security vendors.
3. **Analysis & Thresholds:** * If **>1 engine** flags the URL: Categorized as **DANGER**.
    * If **exactly 1 engine** flags the URL: Categorized as **REVIEW REQUIRED** (Manual Triage).
    * If **0 engines** flag the URL: Categorized as **CLEAN**.
4. **Persistence (Logging):** High-risk events are automatically timestamped and appended to `alerts.log` for audit purposes.

---

## 📋 Implementation Details

### Secret Management
In compliance with security best practices, I implemented a `.gitignore` policy to ensure that sensitive API keys and internal log files are never exposed in the public repository.

### Handling False Positives
During development, I identified that a single detection on reputable domains (like google.com) could lead to "Alert Fatigue." I refined the logic to implement a detection threshold, ensuring that automated actions are only triggered when multiple intelligence sources agree on the threat.

---

## 🔧 Installation & Usage
1. **Clone the repo:** `git clone https://github.com/YOUR_USERNAME/soar-triage-automation.git`
2. **Setup Venv:** `python3 -m venv venv && source venv/bin/activate`
3. **Install Dependencies:** `pip install requests`
4. **Configuration:** Add your VirusTotal API Key to the `API_KEY` variable in `scanner.py`.
5. **Run:** `python3 scanner.py`

---

## 🔗 Connect with me
* **Portfolio:** [farzanehgh.com](https://farzanehgh.com)
* **Objective:** Actively seeking Entry-Level Cybersecurity Analyst / SOAR Specialist roles.
