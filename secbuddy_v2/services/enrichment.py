"""Live enrichment helpers for SecBuddy v2.

AbuseIPDB is queried when `ABUSEIPDB_API_KEY` is present. Otherwise the
module gracefully falls back to an offline/local-only result.
"""

from __future__ import annotations

import ipaddress
import os
from typing import Any

import requests

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
TIMEOUT_SECONDS = 12


def _is_private_ip(ip: str) -> bool:
    try:
        obj = ipaddress.ip_address(ip)
        return obj.is_private or obj.is_loopback
    except ValueError:
        return False


def _classify_abuse_confidence(score: int | None) -> str:
    if score is None:
        return "Unknown"
    if score >= 80:
        return "High"
    if score >= 30:
        return "Medium"
    return "Low"


def enrich_ip(ip: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ip": ip,
        "type": "Internal / private" if _is_private_ip(ip) else "External / public",
        "source": "local",
    }
    if _is_private_ip(ip):
        result.update({
            "status": "private",
            "message": "Private or loopback address. External reputation lookup skipped.",
        })
        return result
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        result.update({
            "status": "offline",
            "message": "ABUSEIPDB_API_KEY not set. Add it to .env for live lookups.",
        })
        return result
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""}
    try:
        response = requests.get(ABUSEIPDB_URL, headers=headers, params=params, timeout=TIMEOUT_SECONDS)
        response.raise_for_status()
        payload = response.json().get("data", {})
        abuse_score = payload.get("abuseConfidenceScore")
        result.update({
            "status": "ok",
            "source": "AbuseIPDB",
            "abuseConfidenceScore": abuse_score,
            "severity": _classify_abuse_confidence(abuse_score),
            "countryCode": payload.get("countryCode"),
            "usageType": payload.get("usageType"),
            "isp": payload.get("isp"),
            "domain": payload.get("domain"),
            "totalReports": payload.get("totalReports"),
            "lastReportedAt": payload.get("lastReportedAt"),
            "isWhitelisted": payload.get("isWhitelisted"),
        })
        return result
    except Exception as exc:
        result.update({
            "status": "error",
            "message": f"Lookup failed: {exc}",
        })
        return result
