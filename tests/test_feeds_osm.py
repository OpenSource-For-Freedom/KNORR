"""Tests for OsmClient's read-only novelty/status helpers (all HTTP mocked)."""

from __future__ import annotations

from unittest.mock import MagicMock

from knorr.feeds.osm import OsmClient


def _make_session(payload) -> MagicMock:
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = payload
    session = MagicMock()
    session.get.return_value = resp
    session.headers = {}
    return session


# ---------------------------------------------------------------------------
# current_reports
# ---------------------------------------------------------------------------

def test_current_reports_maps_by_casefolded_resource():
    session = _make_session({"threats": [
        {"resource_identifier": "Evil/Miner", "id": "abc123", "status": "verified"},
        {"resource_identifier": "other/img", "id": "def456", "status": "pending"},
    ]})
    client = OsmClient(token="tok", session=session)
    out = client.current_reports()
    assert out["evil/miner"] == {
        "id": "abc123", "status": "verified", "verified_by": None, "resource": "Evil/Miner"}
    assert out["other/img"]["status"] == "pending"


def test_current_reports_skips_entries_without_a_resource_identifier():
    session = _make_session({"threats": [{"id": "x", "status": "verified"}]})
    client = OsmClient(token="tok", session=session)
    assert client.current_reports() == {}


def test_current_reports_no_token_returns_empty_without_a_request():
    client = OsmClient(token=None, session=MagicMock())
    assert client.current_reports() == {}


# ---------------------------------------------------------------------------
# existing_resource
# ---------------------------------------------------------------------------

def test_existing_resource_finds_exact_casefolded_match():
    session = _make_session(
        {"data": [{"resource_identifier": "Some/Image", "id": "z9", "status": "verified"}]})
    client = OsmClient(token="tok", session=session)
    hit = client.existing_resource("some/image")
    assert hit["id"] == "z9"


def test_existing_resource_none_when_no_exact_match():
    session = _make_session(
        {"data": [{"resource_identifier": "some/image-other", "id": "z9"}]})
    client = OsmClient(token="tok", session=session)
    assert client.existing_resource("some/image") is None


def test_existing_resource_matches_by_package_name_fallback():
    session = _make_session({"data": [{"package_name": "pool.evil.example", "id": "d1"}]})
    client = OsmClient(token="tok", session=session)
    hit = client.existing_resource("pool.evil.example")
    assert hit["id"] == "d1"


def test_existing_resource_handles_non_200():
    resp = MagicMock()
    resp.status_code = 500
    session = MagicMock()
    session.get.return_value = resp
    session.headers = {}
    client = OsmClient(token="tok", session=session)
    assert client.existing_resource("anything") is None
