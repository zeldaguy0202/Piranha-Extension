# Piranha Extension

Piranha is a Tennessee State University senior project: a browser extension and Python API for checking links against threat intelligence, explaining suspicious URL characteristics, blocking sites, and collecting community reports.

> A scanner cannot prove that a URL is safe. Piranha returns **malicious**, **suspicious**, or **unknown** and includes the evidence and provider status behind the result.

## What is implemented

- FastAPI backend with interactive OpenAPI documentation
- URL validation and canonical normalization
- Explainable URL heuristics (IP hosts, punycode, shorteners, deep subdomains, phishing terms, and excessive length)
- Local URL/domain threat-indicator database
- Optional URLhaus malware-URL lookup
- Live PhishTank, ThreatFox, and Google Safe Browsing lookups when enabled or configured
- VirusTotal URL-report and IP-address reputation lookups
- Positive-only provider cache; clean and unknown browsing URLs are not stored
- Persistent community reports, counted by distinct reporter and reused during scans
- Reporter email fingerprinting; report email addresses are not stored directly
- Optional Have I Been Pwned account-breach lookup
- Automatic new-password screening through the free HIBP Pwned Passwords k-anonymity API
- SQLite locally and PostgreSQL/Supabase through `DATABASE_URL`
- Protected indicator-administration endpoint
- Automated API tests

## Run the backend

Python 3.11 or newer is recommended.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r Backend/requirements-dev.txt
cp Backend/.env.example Backend/.env
uvicorn app.main:app --app-dir Backend --reload
```

Open <http://127.0.0.1:8000/docs>. The default local database is `piranha.db`. Set `DATABASE_URL` in `Backend/.env` to use PostgreSQL.

The Piranha Security Portal is available at <http://127.0.0.1:8000/>. It provides URL and IP scanning, password and email breach tools, community reporting, aggregate statistics, and recent confirmed threat matches without exposing reporter emails.

Run tests with `cd Backend && ../.venv/bin/python -m pytest -q`.

## Main API routes

- `POST /api/scan` with `{"url":"https://example.com"}` checks and explains a URL.
- `POST /api/report` records a community report.
- `GET /api/ip/{address}` checks an IPv4 or IPv6 address with VirusTotal.
- `POST /api/indicators` adds a trusted URL/domain indicator and requires `X-Admin-Key`.
- `GET /api/breaches/{email}` checks HIBP when `HIBP_API_KEY` is configured.
- `GET /api/password/range/{prefix}` proxies the free padded HIBP password hash-range response. Chrome hashes passwords locally; plaintext passwords and complete hashes are never sent or stored.
- `GET /health` supports service health checks.

The scan response's `providers` field tells the client which sources were checked, unavailable, or not configured. `unknown` means no strong evidence was found with the available sources; it does not mean safe.

To import a downloaded PhishTank JSON or CSV feed, run:

```bash
cd Backend
../.venv/bin/python -m scripts.import_phishtank /path/to/phishtank-feed.json
```

## Configuration

Copy `Backend/.env.example` to `Backend/.env`. Never commit real secrets.

- `DATABASE_URL`: SQLite or PostgreSQL SQLAlchemy URL
- `ADMIN_API_KEY`: protects threat-indicator writes
- `REPORT_IDENTITY_SECRET`: fingerprints reporter emails before database storage
- `URLHAUS_AUTH_KEY`: enables URLhaus malware URL checks
- `PHISHTANK_ENABLED`: enables limited unauthenticated PhishTank live checks
- `PHISHTANK_API_KEY`: optional free application key for higher PhishTank limits
- `THREATFOX_AUTH_KEY`: enables ThreatFox domain and IOC checks
- `GOOGLE_SAFE_BROWSING_API_KEY`: enables Google Safe Browsing URL checks
- `VIRUSTOTAL_API_KEY`: enables existing VirusTotal URL-report checks; unknown URLs are not automatically submitted
- `HIBP_API_KEY`: enables breached-account checks
- `CORS_ORIGINS`: comma-separated web development origins
- `REQUEST_TIMEOUT_SECONDS`: outbound provider timeout
- `POSITIVE_CACHE_HOURS`: maximum lifetime for confirmed provider matches; provider limits take precedence

The Supabase credential previously committed in this repository has been removed from current source. The database owner must rotate that password because it remains exposed in Git history.

## Browser extension

Visit `chrome://extensions`, enable Developer mode, select **Load unpacked**, and choose the `Frontend` directory. Keep the backend running. The popup has two tabs: **URL Check** for URLs, IP reputation, reports, and personal blocking; and **Password Check** for HIBP password and email breach checks. Piranha also scans each ordinary HTTP or HTTPS page automatically at document start. Malicious and suspicious results display a full-page warning. If the API is unavailable, navigation fails open so the extension does not break normal browsing.

See [Open_Source_Threat_Tools.md](Open_Source_Threat_Tools.md) for the recommended detection stack, limitations, and phased integration plan.

## License and attribution

See [LICENSE](LICENSE). The extension began from ideas/code credited to [IAmTomShaw's Website Blocker Chrome Extension](https://github.com/IAmTomShaw/Website-Blocker-Chrome-Extension). External feeds and APIs have separate licenses, terms, rate limits, and attribution requirements.
