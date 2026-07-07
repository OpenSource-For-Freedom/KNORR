"""SQLite registry for image findings + run audit (PRD section 14.1).

Single-file, version-controllable store. One row per image (dedup on the
``image`` namespace/repo key); the audit ``runs`` table records each hunt.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from .models import FindingStatus, ImageFinding

_SCHEMA = """
CREATE TABLE IF NOT EXISTS image_findings (
    image            TEXT PRIMARY KEY,
    reference        TEXT,
    digest           TEXT,
    detection_method TEXT,
    status           TEXT,
    score            INTEGER,
    signals          TEXT,     -- json array
    reasoning        TEXT,
    publisher        TEXT,
    pull_count       INTEGER,
    osm_severity     TEXT,
    osm_tags         TEXT,     -- json array
    attribution      TEXT,
    tier             TEXT,
    confirming       TEXT,     -- json array of {category,rule,evidence}
    evidence         TEXT,     -- json object
    first_seen_run   TEXT,
    last_seen_run    TEXT
);
CREATE TABLE IF NOT EXISTS runs (
    run_id       TEXT PRIMARY KEY,
    started_at   TEXT,
    finished_at  TEXT,
    status       TEXT,
    counts       TEXT          -- json object
);
CREATE INDEX IF NOT EXISTS idx_findings_status ON image_findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_publisher ON image_findings(publisher);
"""


class Database:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn
        self.conn.row_factory = sqlite3.Row

    @classmethod
    def open(cls, path: Path | str) -> Database:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(path))
        conn.executescript(_SCHEMA)
        conn.commit()
        return cls(conn)

    def close(self) -> None:
        self.conn.close()

    # --- findings -----------------------------------------------------------
    def known_images(self) -> set[str]:
        return {r["image"] for r in self.conn.execute("SELECT image FROM image_findings")}

    def upsert_finding(self, f: ImageFinding, run_id: str) -> None:
        existing = self.conn.execute(
            "SELECT first_seen_run FROM image_findings WHERE image = ?", (f.image,)
        ).fetchone()
        first_seen = existing["first_seen_run"] if existing else run_id
        self.conn.execute(
            """INSERT INTO image_findings
               (image, reference, digest, detection_method, status, score, signals,
                reasoning, publisher, pull_count, osm_severity, osm_tags, attribution,
                tier, confirming, evidence, first_seen_run, last_seen_run)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(image) DO UPDATE SET
                 reference=excluded.reference, digest=excluded.digest,
                 detection_method=excluded.detection_method, status=excluded.status,
                 score=excluded.score, signals=excluded.signals, reasoning=excluded.reasoning,
                 publisher=excluded.publisher, pull_count=excluded.pull_count,
                 osm_severity=excluded.osm_severity, osm_tags=excluded.osm_tags,
                 attribution=excluded.attribution, tier=excluded.tier,
                 confirming=excluded.confirming, evidence=excluded.evidence,
                 last_seen_run=excluded.last_seen_run""",
            (
                f.image, f.reference, f.digest, str(f.detection_method), str(f.status),
                f.score, json.dumps(f.signals), f.reasoning, f.publisher, f.pull_count,
                f.osm_severity, json.dumps(f.osm_tags), f.attribution, f.tier,
                json.dumps(f.confirming), json.dumps(f.evidence), first_seen, run_id,
            ),
        )
        self.conn.commit()

    def confirmed(self) -> list[sqlite3.Row]:
        return list(self.conn.execute(
            "SELECT * FROM image_findings WHERE status = ? ORDER BY score DESC",
            (str(FindingStatus.CONFIRMED),)))

    def confirmed_publishers(self) -> set[str]:
        """Publishers of confirmed findings, for the compounding owner pivot: a
        publisher we proved malicious once is enumerated for siblings next run."""
        rows = self.conn.execute(
            "SELECT DISTINCT publisher FROM image_findings WHERE status = ? "
            "AND publisher IS NOT NULL", (str(FindingStatus.CONFIRMED),))
        return {r["publisher"] for r in rows if r["publisher"]}

    def all_findings(self) -> list[sqlite3.Row]:
        return list(self.conn.execute(
            "SELECT * FROM image_findings ORDER BY status, score DESC"))

    # --- runs ---------------------------------------------------------------
    def start_run(self, run_id: str, started_at: str) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO runs (run_id, started_at, status) VALUES (?,?,?)",
            (run_id, started_at, "running"))
        self.conn.commit()

    def finish_run(self, run_id: str, finished_at: str, counts: dict) -> None:
        self.conn.execute(
            "UPDATE runs SET finished_at=?, status=?, counts=? WHERE run_id=?",
            (finished_at, "completed", json.dumps(counts), run_id))
        self.conn.commit()
