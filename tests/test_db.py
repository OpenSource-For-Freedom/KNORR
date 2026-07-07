"""Tests for the SQLite registry (Database)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from knorr.db import Database
from knorr.models import DetectionMethod, FindingStatus, ImageFinding


@pytest.fixture
def db(tmp_path):
    d = Database.open(tmp_path / "test.sqlite")
    yield d
    d.close()


def _finding(image: str, status: FindingStatus = FindingStatus.CANDIDATE,
              publisher: str = "evil", score: int = 0) -> ImageFinding:
    return ImageFinding(
        image=image,
        status=status,
        publisher=publisher,
        score=score,
        detection_method=DetectionMethod.HUB_SEARCH,
    )


# ---------------------------------------------------------------------------
# upsert + query
# ---------------------------------------------------------------------------

def test_upsert_and_known_images(db):
    f = _finding("evil/miner")
    db.upsert_finding(f, "run-1")
    assert "evil/miner" in db.known_images()


def test_upsert_preserves_first_seen(db):
    f = _finding("evil/miner")
    db.upsert_finding(f, "run-1")
    db.upsert_finding(f, "run-2")
    row = db.conn.execute(
        "SELECT first_seen_run, last_seen_run FROM image_findings WHERE image = ?",
        ("evil/miner",),
    ).fetchone()
    assert row["first_seen_run"] == "run-1"
    assert row["last_seen_run"] == "run-2"


def test_upsert_updates_status(db):
    f = _finding("evil/miner", status=FindingStatus.CANDIDATE)
    db.upsert_finding(f, "run-1")
    f.status = FindingStatus.CONFIRMED
    f.tier = "A:cryptojacking"
    f.score = 14
    db.upsert_finding(f, "run-2")
    row = db.conn.execute(
        "SELECT status, tier, score FROM image_findings WHERE image = ?",
        ("evil/miner",),
    ).fetchone()
    assert row["status"] == "confirmed"
    assert row["tier"] == "A:cryptojacking"
    assert row["score"] == 14


def test_confirmed_returns_only_confirmed(db):
    db.upsert_finding(_finding("evil/a", FindingStatus.CONFIRMED), "r1")
    db.upsert_finding(_finding("evil/b", FindingStatus.CANDIDATE), "r1")
    db.upsert_finding(_finding("evil/c", FindingStatus.REMOVED), "r1")
    confirmed = db.confirmed()
    images = [r["image"] for r in confirmed]
    assert "evil/a" in images
    assert "evil/b" not in images
    assert "evil/c" not in images


def test_confirmed_ordered_by_score_desc(db):
    db.upsert_finding(_finding("evil/low", FindingStatus.CONFIRMED, score=3), "r1")
    db.upsert_finding(_finding("evil/high", FindingStatus.CONFIRMED, score=15), "r1")
    db.upsert_finding(_finding("evil/mid", FindingStatus.CONFIRMED, score=8), "r1")
    scores = [r["score"] for r in db.confirmed()]
    assert scores == sorted(scores, reverse=True)


def test_confirmed_publishers(db):
    db.upsert_finding(_finding("evil/a", FindingStatus.CONFIRMED, publisher="evil"), "r1")
    db.upsert_finding(_finding("nice/x", FindingStatus.CANDIDATE, publisher="nice"), "r1")
    pubs = db.confirmed_publishers()
    assert "evil" in pubs
    assert "nice" not in pubs


def test_confirmed_publishers_no_null(db):
    f = _finding("evil/a", FindingStatus.CONFIRMED)
    f.publisher = None
    db.upsert_finding(f, "r1")
    pubs = db.confirmed_publishers()
    assert None not in pubs


def test_all_findings(db):
    db.upsert_finding(_finding("a/b"), "r1")
    db.upsert_finding(_finding("c/d"), "r1")
    rows = db.all_findings()
    images = [r["image"] for r in rows]
    assert "a/b" in images
    assert "c/d" in images


def test_signals_json_roundtrip(db):
    f = _finding("evil/x")
    f.signals = ["cryptomining/miner-binary", "c2/bash-tcp"]
    db.upsert_finding(f, "r1")
    row = db.conn.execute("SELECT signals FROM image_findings WHERE image='evil/x'").fetchone()
    assert json.loads(row["signals"]) == ["cryptomining/miner-binary", "c2/bash-tcp"]


def test_evidence_json_roundtrip(db):
    f = _finding("evil/x")
    f.evidence = {"iocs": {"pools": ["pool.supportxmr.com"], "wallets": []}, "tier2_layers_pulled": 3}
    db.upsert_finding(f, "r1")
    row = db.conn.execute("SELECT evidence FROM image_findings WHERE image='evil/x'").fetchone()
    ev = json.loads(row["evidence"])
    assert ev["iocs"]["pools"] == ["pool.supportxmr.com"]
    assert ev["tier2_layers_pulled"] == 3


# ---------------------------------------------------------------------------
# runs table
# ---------------------------------------------------------------------------

def test_start_and_finish_run(db):
    db.start_run("run-42", "2026-07-01T00:00:00Z")
    row = db.conn.execute("SELECT status FROM runs WHERE run_id='run-42'").fetchone()
    assert row["status"] == "running"

    db.finish_run("run-42", "2026-07-01T01:00:00Z", {"confirmed_total": 3})
    row = db.conn.execute("SELECT status, counts FROM runs WHERE run_id='run-42'").fetchone()
    assert row["status"] == "completed"
    assert json.loads(row["counts"])["confirmed_total"] == 3


def test_schema_idempotent(tmp_path):
    """Opening the same DB twice must not raise (schema CREATE IF NOT EXISTS)."""
    path = tmp_path / "idem.sqlite"
    d1 = Database.open(path)
    d1.close()
    d2 = Database.open(path)
    d2.close()
