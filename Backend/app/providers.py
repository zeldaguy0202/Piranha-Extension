from urllib.parse import quote
import base64

import httpx

from .config import Settings


async def check_urlhaus(url: str, settings: Settings) -> tuple[dict | None, dict]:
    if not settings.urlhaus_auth_key:
        return None, {"provider": "URLhaus", "status": "not_configured", "detail": "Set URLHAUS_AUTH_KEY to enable lookups."}
    try:
        async with httpx.AsyncClient(timeout=settings.request_timeout_seconds) as client:
            response = await client.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": url}, headers={"Auth-Key": settings.urlhaus_auth_key})
            response.raise_for_status()
            data = response.json()
        if data.get("query_status") == "ok":
            detail = f"URLhaus lists this URL with status {data.get('url_status', 'unknown')}."
            return {"source": "URLhaus", "category": "known_malware_url", "detail": detail, "score": 100}, {"provider": "URLhaus", "status": "checked"}
        return None, {"provider": "URLhaus", "status": "checked"}
    except (httpx.HTTPError, ValueError) as exc:
        return None, {"provider": "URLhaus", "status": "unavailable", "detail": type(exc).__name__}


async def check_phishtank(url: str, settings: Settings) -> tuple[dict | None, dict]:
    if not settings.phishtank_enabled:
        return None, {"provider": "PhishTank", "status": "not_configured", "detail": "Live checks are disabled."}
    payload = {"url": url, "format": "json"}
    if settings.phishtank_api_key:
        payload["app_key"] = settings.phishtank_api_key
    try:
        async with httpx.AsyncClient(timeout=settings.request_timeout_seconds) as client:
            response = await client.post(
                "https://checkurl.phishtank.com/checkurl/",
                data=payload,
                headers={"user-agent": "Piranha-Senior-Project/0.1"},
            )
            response.raise_for_status()
            data = response.json().get("results", {})
        if data.get("valid") and data.get("verified") and data.get("in_database"):
            return {"source": "PhishTank", "category": "phishing", "detail": "PhishTank lists this URL as a verified phishing page.", "score": 100}, {"provider": "PhishTank", "status": "checked"}
        return None, {"provider": "PhishTank", "status": "checked"}
    except (httpx.HTTPError, ValueError, AttributeError) as exc:
        return None, {"provider": "PhishTank", "status": "unavailable", "detail": type(exc).__name__}


async def check_threatfox(hostname: str, settings: Settings) -> tuple[dict | None, dict]:
    if not settings.threatfox_auth_key:
        return None, {"provider": "ThreatFox", "status": "not_configured", "detail": "Set THREATFOX_AUTH_KEY to enable lookups."}
    try:
        async with httpx.AsyncClient(timeout=settings.request_timeout_seconds) as client:
            response = await client.post(
                "https://threatfox-api.abuse.ch/api/v1/",
                json={"query": "search_ioc", "search_term": hostname, "exact_match": True},
                headers={"Auth-Key": settings.threatfox_auth_key},
            )
            response.raise_for_status()
            data = response.json()
        matches = data.get("data") if data.get("query_status") == "ok" else []
        if matches:
            confidence = max(int(item.get("confidence_level") or 0) for item in matches)
            threat = matches[0].get("threat_type_desc") or matches[0].get("threat_type") or "malware infrastructure"
            score = max(80, min(100, confidence))
            return {"source": "ThreatFox", "category": "malware", "detail": f"ThreatFox lists this domain as {threat}.", "score": score}, {"provider": "ThreatFox", "status": "checked"}
        return None, {"provider": "ThreatFox", "status": "checked"}
    except (httpx.HTTPError, ValueError, TypeError, AttributeError) as exc:
        return None, {"provider": "ThreatFox", "status": "unavailable", "detail": type(exc).__name__}


async def check_google_safe_browsing(url: str, settings: Settings) -> tuple[dict | None, dict]:
    if not settings.google_safe_browsing_api_key:
        return None, {"provider": "Google Safe Browsing", "status": "not_configured", "detail": "Set GOOGLE_SAFE_BROWSING_API_KEY to enable lookups."}
    body = {
        "client": {"clientId": "piranha-senior-project", "clientVersion": "0.1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        async with httpx.AsyncClient(timeout=settings.request_timeout_seconds) as client:
            response = await client.post(
                "https://safebrowsing.googleapis.com/v4/threatMatches:find",
                params={"key": settings.google_safe_browsing_api_key},
                json=body,
            )
            response.raise_for_status()
            matches = response.json().get("matches", [])
        if matches:
            types = sorted({item.get("threatType", "unsafe") for item in matches})
            durations = []
            for item in matches:
                raw = str(item.get("cacheDuration", "")).rstrip("s")
                try:
                    durations.append(max(1, int(float(raw))))
                except ValueError:
                    pass
            evidence = {"source": "Google Safe Browsing", "category": "malware", "detail": f"Google Safe Browsing matched: {', '.join(types)}.", "score": 100}
            if durations:
                evidence["cache_seconds"] = min(durations)
            return evidence, {"provider": "Google Safe Browsing", "status": "checked"}
        return None, {"provider": "Google Safe Browsing", "status": "checked"}
    except (httpx.HTTPError, ValueError, AttributeError) as exc:
        return None, {"provider": "Google Safe Browsing", "status": "unavailable", "detail": type(exc).__name__}


async def check_virustotal(url: str, settings: Settings) -> tuple[dict | None, dict]:
    if not settings.virustotal_api_key:
        return None, {"provider": "VirusTotal", "status": "not_configured", "detail": "Set VIRUSTOTAL_API_KEY to enable lookups."}
    url_id = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")
    try:
        async with httpx.AsyncClient(timeout=settings.request_timeout_seconds) as client:
            response = await client.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers={"x-apikey": settings.virustotal_api_key, "accept": "application/json"},
            )
        if response.status_code == 404:
            return None, {"provider": "VirusTotal", "status": "checked", "detail": "No existing VirusTotal report; the URL was not submitted."}
        if response.status_code == 429:
            return None, {"provider": "VirusTotal", "status": "unavailable", "detail": "Public API rate limit reached."}
        response.raise_for_status()
        attributes = response.json().get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        malicious = int(stats.get("malicious") or 0)
        suspicious = int(stats.get("suspicious") or 0)
        if malicious >= 2:
            return {
                "source": "VirusTotal",
                "category": "malware",
                "detail": f"VirusTotal reports {malicious} malicious and {suspicious} suspicious engine detections.",
                "score": 100,
            }, {"provider": "VirusTotal", "status": "checked"}
        if malicious == 1 or suspicious > 0:
            return {
                "source": "VirusTotal",
                "category": "suspicious_url",
                "detail": f"VirusTotal reports {malicious} malicious and {suspicious} suspicious engine detections; this is not strong consensus.",
                "score": 50,
            }, {"provider": "VirusTotal", "status": "checked"}
        return None, {"provider": "VirusTotal", "status": "checked"}
    except (httpx.HTTPError, ValueError, TypeError, AttributeError) as exc:
        return None, {"provider": "VirusTotal", "status": "unavailable", "detail": type(exc).__name__}


async def check_virustotal_ip(ip_address: str, settings: Settings) -> dict:
    if not settings.virustotal_api_key:
        raise RuntimeError("VirusTotal API access is unavailable")
    async with httpx.AsyncClient(timeout=settings.request_timeout_seconds) as client:
        response = await client.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}",
            headers={"x-apikey": settings.virustotal_api_key, "accept": "application/json"},
        )
    if response.status_code == 404:
        return {"malicious": 0, "suspicious": 0}
    if response.status_code == 429:
        raise RuntimeError("VirusTotal request limit reached; try again shortly")
    response.raise_for_status()
    attributes = response.json().get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})
    return {
        "malicious": int(stats.get("malicious") or 0),
        "suspicious": int(stats.get("suspicious") or 0),
        "country": attributes.get("country"),
        "network": attributes.get("network"),
        "owner": attributes.get("as_owner"),
    }


async def check_hibp(email: str, settings: Settings) -> list[dict]:
    if not settings.hibp_api_key:
        raise RuntimeError("HIBP_API_KEY is not configured")
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email, safe='')}"
    async with httpx.AsyncClient(timeout=settings.request_timeout_seconds) as client:
        response = await client.get(url, params={"truncateResponse": "false"}, headers={"hibp-api-key": settings.hibp_api_key, "user-agent": "Piranha-Senior-Project"})
    if response.status_code == 404:
        return []
    response.raise_for_status()
    return response.json()


async def get_pwned_password_range(prefix: str, settings: Settings) -> dict[str, int]:
    """Return HIBP SHA-1 suffix counts. The complete hash and password never leave Chrome."""
    async with httpx.AsyncClient(timeout=settings.request_timeout_seconds) as client:
        response = await client.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={
                "user-agent": "Piranha-Senior-Project/0.1",
                "Add-Padding": "true",
            },
        )
    response.raise_for_status()
    matches: dict[str, int] = {}
    for line in response.text.splitlines():
        try:
            suffix, raw_count = line.strip().split(":", 1)
            count = int(raw_count)
        except (ValueError, TypeError):
            continue
        if count > 0:
            matches[suffix.upper()] = count
    return matches
