from __future__ import annotations

import re


def _unique(values: list[str]) -> list[str]:
    seen = set()
    out = []
    for value in values:
        if value not in seen:
            seen.add(value)
            out.append(value)
    return out


def extract_iocs(text: str) -> dict:
    ip_pattern = r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
    email_pattern = r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
    domain_pattern = r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"
    host_pattern = r"\b(?:WS|PC|LAPTOP|DESKTOP|SRV|HOST)-?[A-Za-z0-9]{2,}\b"
    url_pattern = r'https?://[^\s\]\[\)>\'"]+'

    ips = re.findall(ip_pattern, text)
    users = re.findall(email_pattern, text)
    urls = re.findall(url_pattern, text)
    hosts = re.findall(host_pattern, text, flags=re.IGNORECASE)
    domains = [d for d in re.findall(domain_pattern, text) if d not in users and not re.fullmatch(ip_pattern, d)]

    return {
        "ips": _unique(ips),
        "users": _unique(users),
        "domains": _unique(domains),
        "urls": _unique(urls),
        "hosts": _unique(hosts),
    }


def derive_findings(alert_text: str, iocs: dict) -> list[str]:
    text = alert_text.lower()
    findings = []
    if "encodedcommand" in text or "frombase64string" in text or " -enc " in text:
        findings.append("Possible encoded PowerShell execution detected.")
    if "failed login" in text or "password spray" in text or "lockout" in text:
        findings.append("Authentication attack pattern language present.")
    if "impossible travel" in text or "geo anomaly" in text or "new country" in text:
        findings.append("Risky sign-in / geolocation anomaly wording present.")
    if "phishing" in text or "clicked" in text or "credential" in text:
        findings.append("Potential user-targeted phishing workflow indicated.")
    if len(iocs.get("ips", [])) >= 3:
        findings.append("Multiple IP indicators extracted, suggesting broader correlation scope.")
    if iocs.get("domains"):
        findings.append("Domain indicators were extracted and should be checked in email, proxy, and DNS logs.")
    if iocs.get("hosts"):
        findings.append("Named endpoints were extracted for host-centric pivoting.")
    return findings[:6]


def summarize_alert(alert_text: str, iocs: dict, use_case: dict | None, findings: list[str]) -> str:
    lines = ["Alert summary:"]
    if use_case:
        lines.append(f"Likely use case: {use_case['title']} ({use_case['playbook_id']}).")
    else:
        lines.append("No direct use case match found from the local library.")
    for label in ("users", "hosts", "ips", "domains", "urls"):
        values = iocs.get(label, [])
        if values:
            lines.append(f"{label.title()}: {', '.join(values)}")
    if findings:
        lines.append("Quick findings: " + " | ".join(findings[:4]))
    snippet = " ".join(alert_text.strip().split())
    if len(snippet) > 280:
        snippet = snippet[:280] + "..."
    lines.append("Original context: " + snippet)
    return "\n".join(lines)
