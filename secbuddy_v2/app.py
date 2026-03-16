from __future__ import annotations

from datetime import datetime
from pathlib import Path

import streamlit as st
from dotenv import load_dotenv

from services.alert_parser import extract_iocs, summarize_alert, derive_findings
from services.enrichment import enrich_ip
from services.storage import (
    CASE_HISTORY_FILE,
    DEFAULT_SETTINGS,
    DEFAULT_USE_CASES,
    ensure_data_files,
    load_json,
    save_json,
    save_case_record,
    match_use_case,
    generate_closing_note,
)

load_dotenv()

DATA_DIR = Path(__file__).parent / "data"
USE_CASES_FILE = DATA_DIR / "use_cases.json"
SETTINGS_FILE = DATA_DIR / "settings.json"

st.set_page_config(page_title="SecBuddy v2", page_icon="🛡️", layout="wide")

CUSTOM_CSS = """
<style>
.main .block-container {
    padding-top: 1.5rem;
    padding-bottom: 2rem;
    max-width: 1350px;
}
[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #0d1326 0%, #131d38 100%);
}
.sb-card {
    background: linear-gradient(180deg, rgba(20,30,54,.96), rgba(14,20,38,.96));
    border: 1px solid rgba(145, 158, 171, 0.22);
    border-radius: 18px;
    padding: 1rem 1.1rem;
    box-shadow: 0 8px 24px rgba(0,0,0,.18);
}
.sb-pill {
    display: inline-block;
    margin: 0 .4rem .4rem 0;
    padding: .25rem .6rem;
    border-radius: 999px;
    border: 1px solid rgba(125,125,255,.28);
    background: rgba(109, 122, 255, .1);
    font-size: .85rem;
}
.sb-muted {opacity: .8; font-size: .92rem;}
</style>
"""


def render_header(settings: dict) -> None:
    st.markdown(CUSTOM_CSS, unsafe_allow_html=True)
    left, right = st.columns([3, 1])
    with left:
        st.title(settings.get("app_name", "SecBuddy") + " v2")
        st.caption("SOC triage assistant with real AbuseIPDB enrichment, alert parsing, case history, and a cleaner interface.")
    with right:
        st.markdown(
            f"""
            <div class="sb-card">
                <div><strong>Session</strong></div>
                <div class="sb-muted">{datetime.now().strftime('%Y-%m-%d %H:%M')}</div>
                <div class="sb-muted">Local JSON persistence enabled</div>
            </div>
            """,
            unsafe_allow_html=True,
        )


def render_summary_panel(summary: str, findings: list[str], matched: dict | None) -> None:
    st.markdown('<div class="sb-card">', unsafe_allow_html=True)
    st.subheader("Analyst Summary")
    st.code(summary, language="text")
    if matched:
        st.markdown(f"**Matched Use Case:** {matched['title']} (`{matched['playbook_id']}`)")
    if findings:
        st.markdown("**Fast Findings**")
        for finding in findings:
            st.write(f"- {finding}")
    st.markdown('</div>', unsafe_allow_html=True)


def render_iocs(iocs: dict) -> None:
    st.markdown('<div class="sb-card">', unsafe_allow_html=True)
    st.subheader("Extracted Indicators")
    any_ioc = False
    for key, values in iocs.items():
        if values:
            any_ioc = True
            st.write(f"**{key.title()}**")
            st.markdown("".join([f'<span class="sb-pill">{v}</span>' for v in values]), unsafe_allow_html=True)
    if not any_ioc:
        st.info("No obvious indicators were extracted from the alert body.")
    st.markdown('</div>', unsafe_allow_html=True)


def triage_page(use_cases: list[dict], settings: dict) -> None:
    render_header(settings)

    left, right = st.columns([1.25, 1])
    with left:
        st.markdown('<div class="sb-card">', unsafe_allow_html=True)
        st.subheader("Triage Console")
        sample = "User john.smith@corp.local triggered suspicious PowerShell with EncodedCommand on host WS-445. Source IP 45.155.205.233 also had 220 failed logins and geo anomaly from RU. Domain update-office365-security.com seen in email click telemetry."
        alert_text = st.text_area("Paste alert body / case notes", height=240, placeholder=sample)
        analyst_name = st.text_input("Analyst name", placeholder="Sean")
        case_id = st.text_input("Case ID", placeholder="INC-2026-001")
        analyze = st.button("Analyze Alert", type="primary", use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

        if analyze:
            if not alert_text.strip():
                st.warning("Paste an alert first.")
                return
            iocs = extract_iocs(alert_text)
            matched = match_use_case(alert_text, use_cases)
            findings = derive_findings(alert_text, iocs)
            summary = summarize_alert(alert_text, iocs, matched, findings)
            st.session_state["last_analysis"] = {
                "alert_text": alert_text,
                "analyst_name": analyst_name,
                "case_id": case_id,
                "iocs": iocs,
                "matched": matched,
                "findings": findings,
                "summary": summary,
            }

    with right:
        st.markdown('<div class="sb-card">', unsafe_allow_html=True)
        st.subheader("What changed in v2")
        st.write("- Live AbuseIPDB lookups when `ABUSEIPDB_API_KEY` is set")
        st.write("- Better IOC extraction and quick pattern findings")
        st.write("- Persistent case history saved to `data/case_history.json`")
        st.write("- Refreshed SOC-style UI")
        st.write("- Closing note and copy-ready case output")
        st.markdown('</div>', unsafe_allow_html=True)

    analysis = st.session_state.get("last_analysis")
    if not analysis:
        return

    iocs = analysis["iocs"]
    matched = analysis["matched"]
    findings = analysis["findings"]
    summary = analysis["summary"]
    alert_text = analysis["alert_text"]
    analyst_name = analysis["analyst_name"]
    case_id = analysis["case_id"]

    a, b = st.columns([1.1, 0.9])
    with a:
        render_summary_panel(summary, findings, matched)
        st.write("")
        render_iocs(iocs)
        if matched:
            st.markdown('<div class="sb-card">', unsafe_allow_html=True)
            st.subheader("Recommended Playbook")
            for idx, step in enumerate(matched.get("steps", []), start=1):
                st.write(f"{idx}. {step}")
            st.markdown('</div>', unsafe_allow_html=True)

    with b:
        st.markdown('<div class="sb-card">', unsafe_allow_html=True)
        st.subheader("IP Enrichment")
        if iocs["ips"]:
            for ip in iocs["ips"]:
                result = enrich_ip(ip)
                with st.expander(ip, expanded=False):
                    st.json(result)
        else:
            st.info("No IPs found to enrich.")
        st.markdown('</div>', unsafe_allow_html=True)

        st.write("")
        st.markdown('<div class="sb-card">', unsafe_allow_html=True)
        st.subheader("Skip Playbook → Closing Note")
        reason = st.selectbox("Disposition reason", settings.get("allowed_skip_reasons", []))
        notes = st.text_area("Optional analyst notes", height=120)
        closing_note = generate_closing_note(reason, notes, matched, iocs, findings)
        st.code(closing_note, language="text")
        if st.button("Save Case Record", use_container_width=True):
            record = {
                "saved_at": datetime.now().isoformat(timespec="seconds"),
                "case_id": case_id or f"CASE-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                "analyst": analyst_name or "Unknown",
                "matched_use_case": matched["title"] if matched else "None",
                "playbook_id": matched.get("playbook_id") if matched else "N/A",
                "summary": summary,
                "closing_note": closing_note,
                "iocs": iocs,
                "findings": findings,
                "source_alert": alert_text,
            }
            save_case_record(record)
            st.success("Case history saved locally.")
        st.markdown('</div>', unsafe_allow_html=True)


def admin_page(use_cases: list[dict]) -> None:
    render_header({"app_name": "SecBuddy"})
    st.subheader("Admin Portal")
    st.caption("Manage use cases without touching code.")
    for idx, use_case in enumerate(use_cases):
        with st.expander(f"{use_case['playbook_id']} — {use_case['title']}", expanded=False):
            st.write("**Keywords:** " + ", ".join(use_case.get("keywords", [])))
            st.write("**Steps:**")
            for step_idx, step in enumerate(use_case.get("steps", []), start=1):
                st.write(f"{step_idx}. {step}")
            if st.button(f"Delete {use_case['playbook_id']}", key=f"del_{idx}"):
                updated = [uc for i, uc in enumerate(use_cases) if i != idx]
                save_json(USE_CASES_FILE, updated)
                st.success("Use case removed. Reload the page.")
    st.divider()
    with st.expander("Add New Use Case", expanded=False):
        title = st.text_input("Use case title")
        playbook_id = st.text_input("Playbook ID", placeholder="UC-999")
        keywords = st.text_input("Keywords (comma-separated)")
        steps = st.text_area("Playbook steps (one per line)", height=160)
        if st.button("Save Use Case"):
            if not title.strip() or not playbook_id.strip():
                st.error("Title and playbook ID are required.")
            else:
                use_cases.append({
                    "title": title.strip(),
                    "playbook_id": playbook_id.strip(),
                    "keywords": [k.strip() for k in keywords.split(",") if k.strip()],
                    "steps": [s.strip() for s in steps.splitlines() if s.strip()],
                })
                save_json(USE_CASES_FILE, use_cases)
                st.success("Use case saved. Reload the page.")


def history_page() -> None:
    render_header({"app_name": "SecBuddy"})
    st.subheader("Case History")
    history = load_json(CASE_HISTORY_FILE, [])
    if not history:
        st.info("No saved cases yet.")
        return
    for entry in reversed(history[-25:]):
        with st.expander(f"{entry['case_id']} — {entry['matched_use_case']} — {entry['saved_at']}", expanded=False):
            st.write(f"**Analyst:** {entry['analyst']}")
            st.write(f"**Playbook ID:** {entry['playbook_id']}")
            st.write("**Summary**")
            st.code(entry["summary"], language="text")
            st.write("**Closing Note**")
            st.code(entry["closing_note"], language="text")
            st.write("**IOCs**")
            st.json(entry["iocs"])


def main() -> None:
    ensure_data_files()
    use_cases = load_json(USE_CASES_FILE, DEFAULT_USE_CASES)
    settings = load_json(SETTINGS_FILE, DEFAULT_SETTINGS)
    st.sidebar.title("SecBuddy")
    page = st.sidebar.radio("Go to", ["Triage Console", "Admin Portal", "Case History"])
    st.sidebar.caption("Set `ABUSEIPDB_API_KEY` in `.env` for live reputation checks.")
    if page == "Triage Console":
        triage_page(use_cases, settings)
    elif page == "Admin Portal":
        admin_page(use_cases)
    else:
        history_page()


if __name__ == "__main__":
    main()
