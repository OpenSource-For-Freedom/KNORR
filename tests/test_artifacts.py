"""Tests for the run artifacts module (write_findings_csv, write_summary)."""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from knorr.artifacts import write_findings_csv, write_summary
from knorr.db import Database
from knorr.models import DetectionMethod, FindingStatus, ImageFinding


@pytest.fixture
def db(tmp_path, monkeypatch):
    """An in-memory DB with the ARTIFACTS_DIR redirected to tmp_path."""
    import knorr.config as cfg
    monkeypatch.setattr(cfg, "ARTIFACTS_DIR", tmp_path)
    d = Database.open(tmp_path / "test.sqlite")
    yield d
    d.close()


def _add(db, image, status=FindingStatus.CONFIRMED, score=10,
         tier="A:cryptojacking", detection_method=DetectionMethod.HUB_SEARCH,
         pull_count=5000, signals=None, evidence=None, reasoning="ok"):
    f = ImageFinding(
        image=image,
        status=status,
        score=score,
        tier=tier,
        detection_method=detection_method,
        publisher=image.split("/", 1)[0],
        pull_count=pull_count,
        signals=signals or ["cryptomining/miner-binary"],
        reasoning=reasoning,
    )
    f.evidence = evidence or {"iocs": {"pools": ["pool.supportxmr.com"], "wallets": [], "miners": ["xmrig"]}}
    db.upsert_finding(f, "run-test")
    return f


# ---------------------------------------------------------------------------
# write_findings_csv
# ---------------------------------------------------------------------------

def test_write_findings_csv_creates_file(db, tmp_path):
    _add(db, "evil/miner")
    path = write_findings_csv(db, "run-test")
    assert path.exists()
    assert path.suffix == ".csv"


def test_write_findings_csv_header(db, tmp_path):
    _add(db, "evil/miner")
    path = write_findings_csv(db, "run-test")
    with path.open(encoding="utf-8") as fh:
        reader = csv.reader(fh)
        header = next(reader)
    assert "image" in header
    assert "status" in header
    assert "tier" in header
    assert "score" in header
    assert "pool" in header
    assert "signals" in header


def test_write_findings_csv_data_row(db, tmp_path):
    _add(db, "evil/miner", tier="A:cryptojacking", score=14)
    path = write_findings_csv(db, "run-test")
    with path.open(encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    assert len(rows) == 1
    assert rows[0]["image"] == "evil/miner"
    assert rows[0]["tier"] == "A:cryptojacking"
    assert rows[0]["score"] == "14"
    assert "pool.supportxmr.com" in rows[0]["pool"]


def test_write_findings_csv_multiple_rows(db, tmp_path):
    _add(db, "evil/a")
    _add(db, "evil/b", status=FindingStatus.CANDIDATE, score=3)
    path = write_findings_csv(db, "run-test")
    with path.open(encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    images = [r["image"] for r in rows]
    assert "evil/a" in images
    assert "evil/b" in images


def test_write_findings_csv_empty_db(db, tmp_path):
    path = write_findings_csv(db, "run-empty")
    assert path.exists()
    with path.open(encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    assert rows == []


def test_write_findings_csv_likely_tool_flag(db, tmp_path):
    _add(db, "tool/miner", evidence={"likely_tool": True, "iocs": {"pools": [], "wallets": [], "miners": []}})
    path = write_findings_csv(db, "run-test")
    with path.open(encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    assert rows[0]["likely_tool"] == "yes"


def test_write_findings_csv_reasoning_truncated(db, tmp_path):
    long_reasoning = "x" * 500
    _add(db, "evil/miner", reasoning=long_reasoning)
    path = write_findings_csv(db, "run-test")
    with path.open(encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    assert len(rows[0]["reasoning"]) <= 300


def test_write_findings_csv_run_id_in_filename(db, tmp_path):
    _add(db, "evil/miner")
    path = write_findings_csv(db, "hunt-20260707T123456Z")
    assert "hunt-20260707T123456Z" in path.name


# ---------------------------------------------------------------------------
# write_summary
# ---------------------------------------------------------------------------

def test_write_summary_creates_json(tmp_path, monkeypatch):
    import knorr.config as cfg
    monkeypatch.setattr(cfg, "ARTIFACTS_DIR", tmp_path)
    summary = {"run_id": "run-1", "counts": {"confirmed_total": 3}, "confirmed": []}
    path = write_summary("run-1", summary)
    assert path.exists()
    assert path.suffix == ".json"


def test_write_summary_json_content(tmp_path, monkeypatch):
    import knorr.config as cfg
    monkeypatch.setattr(cfg, "ARTIFACTS_DIR", tmp_path)
    summary = {
        "run_id": "run-42",
        "counts": {"confirmed_total": 2, "removed": 1},
        "confirmed": [{"image": "evil/x", "tier": "A:cryptojacking"}],
    }
    path = write_summary("run-42", summary)
    loaded = json.loads(path.read_text(encoding="utf-8"))
    assert loaded["run_id"] == "run-42"
    assert loaded["counts"]["confirmed_total"] == 2
    assert loaded["confirmed"][0]["image"] == "evil/x"


def test_write_summary_run_id_in_filename(tmp_path, monkeypatch):
    import knorr.config as cfg
    monkeypatch.setattr(cfg, "ARTIFACTS_DIR", tmp_path)
    path = write_summary("hunt-20260707T000000Z", {})
    assert "hunt-20260707T000000Z" in path.name
