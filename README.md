# SecBuddy

AI-Assisted SOC Triage & Investigation Assistant

SecBuddy is a lightweight tool designed to help security analysts triage alerts faster by combining alert parsing, threat intelligence enrichment, and guided investigation playbooks.

The goal of SecBuddy is to augment Level 1 SOC analysts by reducing repetitive work, improving investigation consistency, and accelerating incident response.

---

# Overview

Security Operations Centers process a large number of alerts every day. Many alerts require repetitive tasks such as:

- extracting indicators
- performing threat intelligence lookups
- determining investigation steps
- writing case notes

SecBuddy helps streamline this workflow by automatically:

- extracting indicators from alerts
- enriching IP addresses using threat intelligence
- matching alerts to investigation playbooks
- guiding analysts through response steps
- generating closing notes

---

# Features

## Alert Parsing

Paste raw alert data from SIEM or EDR tools and SecBuddy will extract:

- IP addresses
- domains
- URLs
- email addresses
- hostnames

---

## Threat Intelligence Enrichment

Currently supports:

- AbuseIPDB IP reputation lookup

Future integrations may include:

- VirusTotal
- GreyNoise
- Shodan
- IPinfo

---

## Use Case Library

SecBuddy contains a customizable investigation playbook system.

Each use case includes:

- Use case title
- Playbook ID
- Keywords
- Investigation steps

Example:

**Suspicious SSH Brute Force**

Steps:

1. Check IP reputation
2. Review authentication logs
3. Verify exposed services
4. Determine if attack succeeded

---

## Admin Portal

The admin interface allows administrators to:

- add new use cases
- modify investigation playbooks
- delete outdated use cases

This allows SOC teams to maintain their own investigation knowledge base.

---

## Closing Note Generator

Analysts can quickly generate case closing notes using preset options:

- False Positive
- Expected Activity
- Blocked by Security Controls
- Confirmed Malicious
- Other

These notes can be copied directly into ticketing or incident systems.

---

# Installation

Clone the repository:

```bash
git clone https://github.com/YOURUSERNAME/secbuddy.git
cd secbuddy
```

Create a virtual environment:

```bash
python -m venv .venv
```

Activate it.

Mac / Linux:

```bash
source .venv/bin/activate
```

Windows:

```bash
.venv\Scripts\activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

# Configuration

Copy the environment template:

```bash
cp .env.example .env
```

Add your AbuseIPDB API key:

```
ABUSEIPDB_API_KEY=your_api_key_here
```

You can obtain a free API key from:

https://abuseipdb.com

---

# Running SecBuddy

Start the application with:

```bash
streamlit run app.py
```

Your browser will open the application automatically.

---

# Example Alert

Paste the following alert into the triage console:

```
Alert Name: Suspicious SSH Brute Force

Source IP: 185.220.101.45
Destination Host: prod-linux-web01
Port: 22

Description:
Multiple failed SSH authentication attempts detected.

Log:
Mar 16 14:21:01 sshd: Failed password for root from 185.220.101.45
```

SecBuddy will:

- extract the IP address
- query AbuseIPDB
- display investigation guidance

---

# Project Structure

```
secbuddy/
│
├── app.py
├── requirements.txt
├── .env.example
│
├── data/
│   └── usecases.json
│
├── modules/
│   ├── alert_parser.py
│   ├── enrichment.py
│   ├── playbook_engine.py
│
└── admin/
    └── admin_portal.py
```

---

# Roadmap

Planned improvements:

- VirusTotal integration
- GreyNoise enrichment
- AI alert summarization
- automatic indicator extraction improvements
- automated playbook execution
- case history database
- multi-user authentication
- SOC analytics dashboard
- SIEM integrations (Splunk, Sentinel)

---

# Disclaimer

This project is a prototype intended for educational and research purposes. It is not intended to replace enterprise SOAR platforms.

---

# Author

Sean Duchstein  
Security Analyst  
Automation + AI in Cybersecurity
