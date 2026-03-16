# SecBuddy v2

A more complete local build of your SecBuddy idea.

## What's included
- SOC-style Streamlit UI
- Better IOC extraction for IPs, emails, domains, URLs, and hostnames
- Local use case matching and admin management
- Real AbuseIPDB enrichment when `ABUSEIPDB_API_KEY` is set
- Persistent case history stored in `data/case_history.json`
- Closing note generation for copy/paste into tickets

## Run it

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scriptsctivate
pip install -r requirements.txt
cp .env.example .env
# add your AbuseIPDB key to .env if you want live lookups
streamlit run app.py
```

## Notes
- The app runs without API keys.
- If no API key is present, enrichment falls back to local/offline behavior.
- This is still a local prototype. No auth, RBAC, or multi-user support yet.
