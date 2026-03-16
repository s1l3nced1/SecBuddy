from __future__ import annotations

import json
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
USE_CASES_FILE = DATA_DIR / "use_cases.json"
SETTINGS_FILE = DATA_DIR / "settings.json"
CASE_HISTORY_FILE = DATA_DIR / "case_history.json"

DEFAULT_USE_CASES = [
    {
        "title": "Suspicious PowerShell Execution",
        "playbook_id": "UC-001",
        "keywords": ["powershell", "encodedcommand", "base64", "iex", "frombase64string"],
        "steps": [
            "Identify the host, user, and exact process tree.",
            "Review the full command line for encoded payloads or download cradles.",
            "Check parent process, script block logs, and EDR ancestry.",
            "Determine whether the activity maps to approved admin tooling.",
            "Escalate and isolate if malicious or unapproved execution is confirmed."
        ]
    },
    {
        "title": "Impossible Travel / Suspicious Login",
        "playbook_id": "UC-002",
        "keywords": ["impossible travel", "geo anomaly", "new country", "mfa", "sign-in risk", "vpn"],
        "steps": [
            "Review source IP, user, user agent, and sign-in timestamps.",
            "Validate MFA challenge results and known device history.",
            "Compare the login path to recent normal user behavior.",
            "Confirm whether travel, VPN, or remote work explains the event.",
            "Reset sessions and escalate if account compromise is suspected."
        ]
    },
    {
        "title": "Brute Force / Password Spray",
        "playbook_id": "UC-003",
        "keywords": ["password spray", "brute force", "failed login", "authentication failure", "lockout"],
        "steps": [
            "Count failed attempts and identify targeted accounts and sources.",
            "Determine whether the pattern is horizontal spray or single-account brute force.",
            "Check for any successful sign-ins following the failed activity.",
            "Review controls triggered such as MFA, lockout, or conditional access.",
            "Contain, block, or escalate if compromise is plausible."
        ]
    },
    {
        "title": "Phishing / Suspicious URL Click",
        "playbook_id": "UC-004",
        "keywords": ["phishing", "url click", "credential harvest", "defender for office", "attachment"],
        "steps": [
            "Identify the user, message, sender, and original delivery path.",
            "Review the URL reputation and redirection chain.",
            "Determine whether credentials were entered or malware launched.",
            "Search for other recipients exposed to the same lure.",
            "Contain affected users and escalate as needed."
        ]
    },
    {
        "title": "Suspicious External IP Communication",
        "playbook_id": "UC-005",
        "keywords": ["ip", "abuseipdb", "scanner", "c2", "external connection", "threat intel"],
        "steps": [
            "Confirm the destination or source IP is external and not approved.",
            "Review reputation, abuse confidence, ASN, and country.",
            "Correlate with proxy, firewall, DNS, and EDR telemetry.",
            "Check whether multiple assets communicated with the same indicator.",
            "Escalate if malicious infrastructure is likely involved."
        ]
    }
]

DEFAULT_SETTINGS = {
    "app_name": "SecBuddy",
    "allowed_skip_reasons": [
        "False positive",
        "Expected activity",
        "User confirmed legitimate",
        "No malicious evidence found",
        "Benign admin activity"
    ]
}


def ensure_data_files() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not USE_CASES_FILE.exists():
        save_json(USE_CASES_FILE, DEFAULT_USE_CASES)
    if not SETTINGS_FILE.exists():
        save_json(SETTINGS_FILE, DEFAULT_SETTINGS)
    if not CASE_HISTORY_FILE.exists():
        save_json(CASE_HISTORY_FILE, [])


def load_json(path: Path, fallback):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return fallback


def save_json(path: Path, payload) -> None:
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def score_use_case(alert_text: str, use_case: dict) -> int:
    text = alert_text.lower()
    score = 0
    for keyword in use_case.get("keywords", []):
        if keyword.lower() in text:
            score += 1
    return score


def match_use_case(alert_text: str, use_cases: list[dict]) -> dict | None:
    ranked = sorted(use_cases, key=lambda uc: score_use_case(alert_text, uc), reverse=True)
    best = ranked[0] if ranked else None
    if best and score_use_case(alert_text, best) > 0:
        return best
    return None


def save_case_record(record: dict) -> None:
    history = load_json(CASE_HISTORY_FILE, [])
    history.append(record)
    save_json(CASE_HISTORY_FILE, history)


def generate_closing_note(reason: str, notes: str, use_case: dict | None, iocs: dict, findings: list[str]) -> str:
    subject = use_case["title"] if use_case else "alert review"
    ioc_bits = []
    for key in ("users", "ips", "domains", "hosts"):
        if iocs.get(key):
            ioc_bits.append(f"{key}: {', '.join(iocs[key])}")
    ioc_text = "; ".join(ioc_bits) if ioc_bits else "No clear indicators were extracted."
    findings_text = " | ".join(findings[:4]) if findings else "No high-confidence quick findings generated."
    return (
        f"Reviewed {subject}.\n"
        f"Disposition: {reason}.\n"
        f"Indicators reviewed: {ioc_text}\n"
        f"Quick findings: {findings_text}\n"
        f"Analyst notes: {notes.strip() if notes.strip() else 'None provided.'}\n"
        f"Recommended status: Closed unless new evidence is identified."
    )
