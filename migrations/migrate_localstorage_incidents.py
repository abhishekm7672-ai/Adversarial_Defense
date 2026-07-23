"""
migrations/migrate_localstorage_incidents.py
============================================
One-time migration script.

The frontend previously stored incidents in browser localStorage.
This script reads a JSON export from localStorage and imports all
incidents into the PostgreSQL incidents table.

HOW TO USE:
-----------
1. Open the Navigo dashboard in Chrome/Firefox while the OLD version
   is still running.

2. Open DevTools → Console and run:
       copy(localStorage.getItem('navigo_incidents'))

   This copies the JSON to your clipboard.

3. Paste it into a file: migrations/incidents_export.json

4. Run this script (with venv active and DB running):
       python migrations/migrate_localstorage_incidents.py

5. Verify:
       psql -U navigo -d navigo_db -c "SELECT COUNT(*) FROM incidents;"
"""

import asyncio
import json
import pathlib
import sys
import uuid
from datetime import datetime, timezone

# Make sure project root is importable
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

from db.database import db
from db.repositories import IncidentRepository


EXPORT_FILE = pathlib.Path(__file__).parent / "incidents_export.json"

SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    # Legacy field names
    "Critical": "critical",
    "High": "high",
    "Medium": "medium",
    "Low": "low",
}

STATUS_MAP = {
    "open": "open",
    "investigating": "investigating",
    "resolved": "resolved",
    "false_positive": "false_positive",
    # Legacy
    "Open": "open",
    "Investigating": "investigating",
    "Resolved": "resolved",
    "False Positive": "false_positive",
}


async def migrate():
    if not EXPORT_FILE.exists():
        print(f"ERROR: {EXPORT_FILE} not found.")
        print("Follow the instructions at the top of this script.")
        sys.exit(1)

    raw = json.loads(EXPORT_FILE.read_text())
    if isinstance(raw, str):
        # Double-encoded JSON
        raw = json.loads(raw)

    incidents_data = raw if isinstance(raw, list) else raw.get("incidents", [])

    print(f"Found {len(incidents_data)} incidents to migrate.")

    await db.connect()
    repo = IncidentRepository(db)

    success = 0
    skipped = 0

    for item in incidents_data:
        try:
            severity = SEVERITY_MAP.get(item.get("severity", "medium"), "medium")
            status   = STATUS_MAP.get(item.get("status", "open"), "open")
            title    = item.get("title") or item.get("name") or "Untitled"
            description = item.get("description") or item.get("details") or None
            tags = item.get("tags") or []

            # Parse timestamp if present
            created_at_raw = item.get("created_at") or item.get("timestamp") or None

            await db.execute(
                """
                INSERT INTO incidents (
                    id, title, description, severity, status, tags, created_at, updated_at
                ) VALUES (
                    $1, $2, $3, $4, $5, $6, $7, $7
                )
                ON CONFLICT (id) DO NOTHING
                """,
                uuid.uuid4(),
                title[:256],
                description,
                severity,
                status,
                tags,
                _parse_ts(created_at_raw),
            )
            success += 1
        except Exception as exc:
            print(f"  SKIP: {item.get('title', '?')} — {exc}")
            skipped += 1

    await db.disconnect()

    print(f"\nMigration complete.")
    print(f"  Imported : {success}")
    print(f"  Skipped  : {skipped}")


def _parse_ts(raw) -> datetime:
    if not raw:
        return datetime.now(timezone.utc)
    if isinstance(raw, (int, float)):
        # Unix epoch ms (common in localStorage)
        ts = raw / 1000 if raw > 1e10 else raw
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    try:
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except Exception:
        return datetime.now(timezone.utc)


if __name__ == "__main__":
    asyncio.run(migrate())