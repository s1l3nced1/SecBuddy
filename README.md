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
