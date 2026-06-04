# ATIP API — Python Analysis Backend

FastAPI backend for the Agentic Threat Intelligence Platform.

## Endpoints

### POST /scan
Full scan with explicit type.
```json
{
  "input": "https://suspicious-site.xyz",
  "scan_type": "url",
  "deep_scan": false
}
```

### POST /scan/quick
Auto-detect type and scan immediately.
```json
{"input": "suspicious-domain.top"}
```

### Scan Types
- `url` — Scrape + content analysis + domain intel
- `domain` — WHOIS, DNS, IP reputation, age
- `text` — AI detection, manipulation patterns, linguistic analysis
- `username` — Cross-platform presence (coming soon)
- `ip` — Geolocation, VPN/proxy detection (coming soon)

## Deploy on Render
1. Connect GitHub repo
2. Set `DATABASE_URL` env var (Neon connection string)
3. Deploy

## Local Development
```bash
pip install -r requirements.txt
uvicorn main:app --reload
```
