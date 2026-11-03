import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import quote, unquote, urlsplit, urlunsplit


class InvalidURL(ValueError):
    pass


@dataclass(frozen=True)
class NormalizedURL:
    url: str
    hostname: str


SUSPICIOUS_WORDS = {"account", "auth", "confirm", "credential", "login", "password", "recover", "secure", "signin", "support", "update", "verify", "wallet"}
SHORTENERS = {"bit.ly", "cutt.ly", "is.gd", "rb.gy", "rebrand.ly", "shorturl.at", "t.co", "tinyurl.com", "tiny.one", "ow.ly"}


def normalize_url(raw_url: str) -> NormalizedURL:
    raw_url = raw_url.strip()
    if not raw_url:
        raise InvalidURL("URL cannot be empty")
    if "://" not in raw_url:
        raw_url = "https://" + raw_url
    try:
        parts = urlsplit(raw_url)
        if parts.scheme.lower() not in {"http", "https"}:
            raise InvalidURL("Only http and https URLs are supported")
        if parts.username is not None or parts.password is not None:
            raise InvalidURL("URLs containing embedded credentials are not accepted")
        if not parts.hostname:
            raise InvalidURL("URL must contain a hostname")
        hostname = parts.hostname.rstrip(".").encode("idna").decode("ascii").lower()
        port = parts.port
    except (UnicodeError, ValueError) as exc:
        if isinstance(exc, InvalidURL):
            raise
        raise InvalidURL("URL is malformed") from exc
    if len(hostname) > 253 or any(not label or len(label) > 63 for label in hostname.split(".")):
        raise InvalidURL("Hostname is invalid")
    scheme = parts.scheme.lower()
    default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    netloc = hostname if port is None or default_port else f"{hostname}:{port}"
    path = quote(unquote(parts.path or "/"), safe="/%:@!$&'()*+,;=-._~")
    query = quote(unquote(parts.query), safe="=&?/:@!$'()*+,;%-._~")
    return NormalizedURL(url=urlunsplit((scheme, netloc, path, query, "")), hostname=hostname)


def heuristic_evidence(value: NormalizedURL) -> list[dict]:
    evidence: list[dict] = []
    try:
        ipaddress.ip_address(value.hostname.strip("[]"))
        evidence.append({"source": "heuristics", "category": "ip_hostname", "detail": "The link uses an IP address instead of a domain name.", "score": 20})
    except ValueError:
        pass
    if "xn--" in value.hostname:
        evidence.append({"source": "heuristics", "category": "idn", "detail": "The hostname contains internationalized (punycode) labels.", "score": 15})
    if value.hostname in SHORTENERS:
        evidence.append({"source": "heuristics", "category": "shortener", "detail": "The destination is hidden behind a URL shortener.", "score": 15})
    if len(value.hostname.split(".")) >= 5:
        evidence.append({"source": "heuristics", "category": "subdomains", "detail": "The hostname has an unusually deep subdomain chain.", "score": 10})
    matches = sorted(set(re.findall(r"[a-z0-9]+", value.url.lower())) & SUSPICIOUS_WORDS)
    if len(matches) >= 2:
        evidence.append({"source": "heuristics", "category": "social_engineering_words", "detail": f"Multiple urgency/account terms appear in the URL: {', '.join(matches[:5])}.", "score": min(20, len(matches) * 5)})
    if len(value.url) > 200:
        evidence.append({"source": "heuristics", "category": "length", "detail": "The URL is unusually long.", "score": 10})
    return evidence
