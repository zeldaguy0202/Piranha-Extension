import json

from sqlalchemy import func, select

from app.database import SessionLocal, ThreatIndicator
from scripts.import_phishtank import import_feed


def test_imports_only_verified_online_urls(tmp_path):
    feed = tmp_path / "feed.json"
    feed.write_text(json.dumps([
        {"url": "https://phishing.example/login", "verified": "yes", "online": "yes"},
        {"url": "https://unverified.example/", "verified": "no", "online": "yes"},
    ]))
    assert import_feed(feed) == (1, 1)
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(ThreatIndicator)) == 1
