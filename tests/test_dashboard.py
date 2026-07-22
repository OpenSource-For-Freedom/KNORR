"""Tests for the dashboard's data-shaping functions (dashboard/app.py).

The HTML/CSS/JS is exercised by hand in a browser; this pins the one piece
of real logic behind the telemetry graphs: which runs qualify, in what
order, and what each data point carries.
"""

from __future__ import annotations

import pytest

from knorr.dashboard.app import _telemetry
from knorr.db import Database


@pytest.fixture
def db(tmp_path):
    d = Database.open(tmp_path / "test.sqlite")
    yield d
    d.close()


def _run(db_, run_id, started_at, *, finished=True, counts=None):
    db_.start_run(run_id, started_at)
    if finished:
        db_.finish_run(run_id, started_at, counts or {})


def test_telemetry_empty_db_returns_empty(db):
    assert _telemetry(db) == []


def test_telemetry_excludes_running_rows(db):
    _run(db, "r1", "2026-07-01T00:00:00Z", finished=False)
    assert _telemetry(db) == []


def test_telemetry_orders_chronologically_oldest_first(db):
    _run(db, "r2", "2026-07-02T00:00:00Z", counts={"candidates": 2, "confirmed_total": 20})
    _run(db, "r1", "2026-07-01T00:00:00Z", counts={"candidates": 1, "confirmed_total": 10})
    _run(db, "r3", "2026-07-03T00:00:00Z", counts={"candidates": 3, "confirmed_total": 30})
    tel = _telemetry(db)
    assert [t["run_id"] for t in tel] == ["r1", "r2", "r3"]


def test_telemetry_extracts_candidates_and_confirmed_total(db):
    _run(db, "r1", "2026-07-01T00:00:00Z",
         counts={"candidates": 7, "confirmed_total": 42, "removed": 1})
    tel = _telemetry(db)
    assert tel[0]["candidates"] == 7
    assert tel[0]["confirmed_total"] == 42


def test_telemetry_defaults_missing_counts_keys_to_zero(db):
    _run(db, "r1", "2026-07-01T00:00:00Z", counts={"removed": 3})
    tel = _telemetry(db)
    assert tel[0]["candidates"] == 0
    assert tel[0]["confirmed_total"] == 0


def test_telemetry_respects_limit(db):
    for i in range(5):
        _run(db, f"r{i}", f"2026-07-0{i + 1}T00:00:00Z", counts={"confirmed_total": i})
    tel = _telemetry(db, limit=2)
    assert len(tel) == 2
    # still chronological among the most-recent `limit` runs
    assert [t["run_id"] for t in tel] == ["r3", "r4"]


def test_telemetry_confirmed_total_can_dip(db):
    """Confirmed count is not purely monotonic: a precision fix rejecting
    false positives can drop it between runs, and the graph must show that
    honestly rather than assume growth-only."""
    _run(db, "r1", "2026-07-01T00:00:00Z", counts={"confirmed_total": 50})
    _run(db, "r2", "2026-07-02T00:00:00Z", counts={"confirmed_total": 43})
    tel = _telemetry(db)
    assert [t["confirmed_total"] for t in tel] == [50, 43]
