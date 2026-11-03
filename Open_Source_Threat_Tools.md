# Open-source and community threat tools for Piranha

## Recommended first stack

1. **URLhaus (abuse.ch)** — malware-distribution URLs. It provides an authenticated community API, downloadable indicators, MISP events, RPZ data, and Suricata/ClamAV material. It intentionally does not cover ordinary phishing pages, so it cannot be the only source. Piranha already has an optional URLhaus lookup adapter.
2. **PhishTank** — verified phishing URLs through downloadable feeds and an API. Add it as the phishing counterpart to URLhaus. Cache a feed locally instead of sending every user's browsing URL to another service.
3. **MISP** — open-source threat-intelligence sharing and indicator management. Use it to combine URLhaus, PhishTank, institutional reports, and analyst decisions into one curated source.
4. **OpenCTI** — open-source knowledge platform for observables, campaigns, malware, vulnerabilities, and relationships. It is useful for a research dashboard and richer context, but heavier than the first release needs.
5. **Suricata** — open-source network IDS/IPS. It can support a lab demonstration correlating browser detections with network alerts; URLhaus publishes a compatible ruleset.
6. **ClamAV** — open-source antivirus for scanning files downloaded from suspect links. It scans file content, not URL reputation; keep file scanning isolated from the API host.
7. **YARA** — open-source rules for classifying downloaded files or captured artifacts. It complements ClamAV and does not replace a URL feed.

## Where Have I Been Pwned fits

HIBP answers account-security questions: whether an email appears in known breaches and whether a password appeared in exposed password data. It is not a malicious-link database. Email searches require an API subscription key and descriptive user agent; Pwned Passwords uses a separate k-anonymity design.

Use HIBP as an optional, consent-based post-warning feature. Do not automatically submit addresses discovered on web pages. Explain the privacy impact and visibly attribute HIBP results.

## Suggested phases

### Phase 1 — reliable local API

- Connect the extension UI to `POST /api/scan`.
- Use URLhaus for malware and a cached PhishTank feed for phishing.
- Keep verdicts explainable and surface provider outages.
- Rate-limit reporting and verify accounts before reports influence blocking.

### Phase 2 — stronger signals

- Add domain age and DNS signals without fetching the target page.
- Expand redirects only in an isolated worker with strict SSRF controls.
- Add analyst review plus allow/block overrides.
- Import feeds on a schedule and retain source timestamps.

### Phase 3 — research platform

- Feed indicators into MISP or OpenCTI.
- Evaluate a lexical ML model against a dated, deduplicated dataset.
- Measure precision, recall, false-positive rate, and time-to-detection by source.
- Scan downloads with ClamAV/YARA in a disposable sandbox.

## Important constraints

- Never fetch an arbitrary submitted URL from the main API process; this creates SSRF and malware-exposure risk.
- Never label absence from a blocklist as safe.
- Treat community reports as unverified until corroborated.
- Keep API keys server-side and rotate exposed credentials.
- Minimize stored browsing data, define retention, and obtain consent for email checks.
- Defend reporting against spam, duplicate accounts, and reputation manipulation.
- Follow every feed's license, attribution, and commercial-use rules.

## Primary documentation

- URLhaus Community API: https://urlhaus.abuse.ch/api/
- PhishTank developer information: https://phishtank.org/developer_info.php
- HIBP API v3: https://haveibeenpwned.com/API/v3
- MISP: https://www.misp-project.org/
- OpenCTI: https://docs.opencti.io/
- Suricata: https://suricata.io/
- ClamAV: https://docs.clamav.net/
- YARA: https://virustotal.github.io/yara/
