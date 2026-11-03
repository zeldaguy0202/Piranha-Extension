"""Import a downloaded PhishTank JSON or CSV feed into Piranha.

Run from Backend: python -m scripts.import_phishtank path/to/feed.json
"""

import argparse
import csv
import json
from pathlib import Path

from app.database import SessionLocal, ThreatIndicator, create_tables
from app.url_analysis import InvalidURL, normalize_url
from sqlalchemy.dialects.sqlite import insert as sqlite_insert


def rows_from(path: Path):
    if path.suffix.lower() == ".json":
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, list):
            raise ValueError("PhishTank JSON feed must contain a list")
        yield from data
    else:
        with path.open(newline="", encoding="utf-8-sig") as handle:
            yield from csv.DictReader(handle)


def truthy(value) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


def import_feed(path: Path) -> tuple[int, int]:
    create_tables()
    imported = skipped = 0
    with SessionLocal() as db:
        for row in rows_from(path):
            if "verified" in row and not truthy(row["verified"]):
                skipped += 1
                continue
            if "online" in row and not truthy(row["online"]):
                skipped += 1
                continue
            try:
                normalized = normalize_url(row["url"]).url
            except (KeyError, InvalidURL):
                skipped += 1
                continue
            values = {"value": normalized, "indicator_type": "url", "source": "PhishTank", "threat_type": "phishing", "confidence": 90}
            if db.bind.dialect.name == "sqlite":
                result = db.execute(sqlite_insert(ThreatIndicator).values(**values).on_conflict_do_nothing(index_elements=["value"]))
                imported += max(result.rowcount, 0)
            elif db.query(ThreatIndicator).filter_by(value=normalized).first() is None:
                db.add(ThreatIndicator(**values))
                imported += 1
        db.commit()
    return imported, skipped


def main() -> None:
    parser = argparse.ArgumentParser(description="Import a downloaded PhishTank JSON/CSV feed")
    parser.add_argument("feed", type=Path)
    args = parser.parse_args()
    imported, skipped = import_feed(args.feed)
    print(f"Imported {imported} verified online URLs; skipped {skipped} rows.")


if __name__ == "__main__":
    main()
