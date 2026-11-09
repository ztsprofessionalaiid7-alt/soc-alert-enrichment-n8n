# SOC Alert Enrichment & Triage (n8n)

An n8n workflow that takes security alerts, enriches the indicator (IP or file hash) with VirusTotal and AbuseIPDB, lets Gemini score the severity, then routes it to Slack, GitHub Issues and Postgres.

▶ **Demo video:** https://drive.google.com/file/d/1X8wJeVbRCYpMX5CkU68EriE0UWC0b-Wl/view

## How it works

1. Mock alerts arrive (bad IP, safe IP, EICAR test file hash)
2. The indicator (IOC) and its type are extracted
3. VirusTotal and AbuseIPDB are queried for reputation
4. Context is built and Gemini returns severity (low, medium, high), a score, a summary and a recommended action
5. A Switch routes by severity:

| Severity | Destination |
|---|---|
| low | Postgres only |
| medium | Slack + Postgres |
| high | Slack + GitHub Issue + Postgres |

```
Manual Trigger -> Mock Alerts -> Extract IOC -> VT Lookup -> AbuseIPDB Lookup
-> Build Context -> Analyze Alert (Gemini + Output Parser) -> Parse Result -> Switch
Switch -> Slack Alert | Create GitHub Issue | Upsert Alert (Postgres)
```

## Tech stack

n8n Cloud, Google Gemini, VirusTotal API, AbuseIPDB API, Slack, GitHub Issues, Supabase (Postgres)

## Setup

1. Import `soc-alert-enrichment-cloud.json` into n8n
2. Create credentials (free tiers):
   - VirusTotal (Header Auth: name `x-apikey`)
   - AbuseIPDB (Header Auth: name `Key`)
   - Google Gemini (API key)
   - Slack (Bot token and signing secret)
   - GitHub (classic token with `repo` scope)
   - Postgres (Supabase Session pooler, SSL: Require)
3. Slack node: channel `soc-alerts`, invite the bot to it
4. GitHub node: set your repository owner and repo name (for example `soc-alerts`)
5. Create the database table (below)
6. Click **Execute workflow**

## Database

```sql
create table if not exists public.soc_alerts (
  alert_id text primary key,
  ioc text,
  ioc_type text,
  source text,
  severity text,
  score numeric,
  summary text,
  action text,
  created_at timestamptz default now()
);
```

`alert_id` is the match key, so re-running the workflow updates existing rows instead of duplicating them.

## Notes

- The GitHub node only runs on the **high** branch. "Node was not executed" on other runs is expected
- Gemini decides the severity, so results can vary between runs
- Never commit API keys. Use n8n credentials only

## Author

Zarin Tasnim Shaily, AI Automation Engineer
[LinkedIn](https://linkedin.com/in/5ha1l72) | [GitHub](https://github.com/ztsprofessionalaiid7-alt)
