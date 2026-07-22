"""Tests for the dashboard's data-shaping functions (dashboard/app.py).

The HTML/CSS/JS is exercised by hand in a browser; this pins the one piece
of real logic behind the telemetry graphs: which runs qualify, in what
order, and what each data point carries.
"""

from __future__ import annotations

import pytest

from knorr.dashboard.app import _packages, _summary, _telemetry
from knorr.db import Database
from knorr.models import DetectionMethod, FindingStatus, ImageFinding


@pytest.fixture
def db(tmp_path):
    d = Database.open(tmp_path / "test.sqlite")
    yield d
    d.close()


def _run(db_, run_id, started_at, *, finished=True, counts=None):
    db_.start_run(run_id, started_at)
    if finished:
        db_.finish_run(run_id, started_at, counts or {})


def _confirmed(db_, image, *, tier="A:cryptojacking", publisher=None, evidence=None):
    f = ImageFinding(
        image=image, status=FindingStatus.CONFIRMED, tier=tier,
        detection_method=DetectionMethod.HUB_SEARCH,
        publisher=publisher or image.split("/", 1)[0],
        evidence=evidence or {},
    )
    db_.upsert_finding(f, "run-1")


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


# ---------------------------------------------------------------------------
# _summary: by_publisher / by_severity (the fill-the-screen additions)
# ---------------------------------------------------------------------------

def test_summary_by_publisher_counts_confirmed_only(db):
    _confirmed(db, "evil/a", publisher="evil")
    _confirmed(db, "evil/b", publisher="evil")
    _confirmed(db, "nice/x", publisher="nice")
    s = _summary(db)
    assert dict(s["by_publisher"])["evil"] == 2
    assert dict(s["by_publisher"])["nice"] == 1


def test_summary_by_publisher_top_10_only(db):
    for i in range(15):
        _confirmed(db, f"pub{i}/img", publisher=f"pub{i}")
    s = _summary(db)
    assert len(s["by_publisher"]) == 10


def test_summary_by_severity_tier_a_is_critical(db):
    _confirmed(db, "evil/a", tier="A:reverse_shell")
    s = _summary(db)
    assert dict(s["by_severity"])["critical"] == 1


def test_summary_by_severity_tier_b_is_high(db):
    _confirmed(db, "evil/a", tier="B:steal-and-send")
    s = _summary(db)
    assert dict(s["by_severity"])["high"] == 1


# ---------------------------------------------------------------------------
# _packages: the searchable Dependency/Package Report (DPR)
# ---------------------------------------------------------------------------

def test_packages_empty_when_no_sbom_hits(db):
    _confirmed(db, "evil/a")
    assert _packages(db) == []


def test_packages_aggregates_a_single_hit(db):
    _confirmed(db, "evil/a", evidence={"sbom_hits": [
        {"ecosystem": "npm", "name": "evil-pkg", "version": "1.0.0"}]})
    pkgs = _packages(db)
    assert len(pkgs) == 1
    assert pkgs[0]["ecosystem"] == "npm"
    assert pkgs[0]["name"] == "evil-pkg"
    assert pkgs[0]["version"] == "1.0.0"
    assert pkgs[0]["images"][0]["image"] == "evil/a"


def test_packages_groups_same_package_across_images(db):
    hit = {"ecosystem": "pypi", "name": "bad-lib", "version": "2.0"}
    _confirmed(db, "evil/a", evidence={"sbom_hits": [hit]})
    _confirmed(db, "evil/b", evidence={"sbom_hits": [hit]})
    pkgs = _packages(db)
    assert len(pkgs) == 1
    assert {im["image"] for im in pkgs[0]["images"]} == {"evil/a", "evil/b"}


def test_packages_different_versions_are_distinct_entries(db):
    _confirmed(db, "evil/a", evidence={"sbom_hits": [
        {"ecosystem": "npm", "name": "evil-pkg", "version": "1.0.0"}]})
    _confirmed(db, "evil/b", evidence={"sbom_hits": [
        {"ecosystem": "npm", "name": "evil-pkg", "version": "2.0.0"}]})
    pkgs = _packages(db)
    assert len(pkgs) == 2


def test_packages_sorted_by_image_count_descending(db):
    hit_a = {"ecosystem": "npm", "name": "popular-bad", "version": "1.0"}
    hit_b = {"ecosystem": "npm", "name": "rare-bad", "version": "1.0"}
    _confirmed(db, "evil/a", evidence={"sbom_hits": [hit_a]})
    _confirmed(db, "evil/b", evidence={"sbom_hits": [hit_a]})
    _confirmed(db, "evil/c", evidence={"sbom_hits": [hit_b]})
    pkgs = _packages(db)
    assert pkgs[0]["name"] == "popular-bad"
    assert pkgs[1]["name"] == "rare-bad"


def test_packages_includes_non_confirmed_findings_too(db):
    """A package's malicious dependency is real evidence regardless of the
    carrying image's own status (screened/rejected images still carry proof
    an operator may want to see)."""
    f = ImageFinding(
        image="evil/screened", status=FindingStatus.SCREENED,
        detection_method=DetectionMethod.HUB_SEARCH, publisher="evil",
        evidence={"sbom_hits": [{"ecosystem": "npm", "name": "x", "version": "1"}]})
    db.upsert_finding(f, "run-1")
    pkgs = _packages(db)
    assert len(pkgs) == 1
    assert pkgs[0]["images"][0]["status"] == "screened"
