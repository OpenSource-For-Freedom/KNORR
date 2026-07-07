"""Tests for Docker Hub + Quay discovery functions (all HTTP mocked)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from knorr.scanning.discovery import (
    DEFAULT_SEARCH_TERMS,
    TYPOSQUAT_TARGETS,
    _QUAY_HREF,
    _one_edit,
    hub_search,
    publisher_images,
    quay_publisher_images,
    quay_search,
    typosquat_candidates,
)


# ---------------------------------------------------------------------------
# _one_edit
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("a,b,expected", [
    ("alpin",  "alpine", False),   # different length
    ("alpine", "alpine", False),   # identical
    ("a1pine", "alpine", True),    # one substitution
    ("a1p1ne", "alpine", False),   # two substitutions
    ("alpone", "alpine", True),    # one substitution
    ("nginx",  "nginx",  False),
    ("ngiix",  "nginx",  True),
])
def test_one_edit(a, b, expected):
    assert _one_edit(a, b) == expected


# ---------------------------------------------------------------------------
# _QUAY_HREF regex
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("href,ns,name", [
    ("/repository/kinsing/malware",      "kinsing", "malware"),
    ("/repository/ns/deep/path",         "ns",      "deep/path"),
    ("/repository/a-b_c/img.name-1",     "a-b_c",   "img.name-1"),
])
def test_quay_href_regex_matches(href, ns, name):
    m = _QUAY_HREF.match(href)
    assert m is not None
    assert m.group(1) == ns
    assert m.group(2) == name


@pytest.mark.parametrize("href", [
    "/search/kinsing",
    "/api/v1/repository",
    "repository/kinsing/malware",  # missing leading slash
    "",
])
def test_quay_href_regex_no_match(href):
    assert _QUAY_HREF.match(href) is None


# ---------------------------------------------------------------------------
# hub_search
# ---------------------------------------------------------------------------

def _make_hub_session(results: list[dict]) -> MagicMock:
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {"results": results}
    session = MagicMock()
    session.get.return_value = resp
    session.headers = {}
    return session


def test_hub_search_returns_candidates():
    results = [
        {"repo_name": "evil/xmrigminer", "is_official": False, "pull_count": 5000, "star_count": 1},
    ]
    session = _make_hub_session(results)
    out = hub_search(("xmrig",), session=session)
    assert len(out) == 1
    assert out[0]["image"] == "evil/xmrigminer"
    assert out[0]["publisher"] == "evil"
    assert out[0]["pull_count"] == 5000


def test_hub_search_skips_official():
    results = [
        {"repo_name": "alpine", "is_official": True, "pull_count": 9999},
        {"repo_name": "evil/miner", "is_official": False, "pull_count": 1},
    ]
    session = _make_hub_session(results)
    out = hub_search(("xmrig",), session=session)
    names = [r["image"] for r in out]
    assert "alpine" not in names
    assert "evil/miner" in names


def test_hub_search_skips_bare_name_no_slash():
    # A result with no '/' is an Official/library image slug — skip it.
    results = [
        {"repo_name": "python", "is_official": False, "pull_count": 1},
    ]
    session = _make_hub_session(results)
    out = hub_search(("python",), session=session)
    assert out == []


def test_hub_search_deduplicates_across_terms():
    results = [
        {"repo_name": "evil/xmrigminer", "is_official": False, "pull_count": 1},
    ]
    session = _make_hub_session(results)
    # Two terms both return the same image; should appear once.
    out = hub_search(("xmrig", "monero"), session=session)
    images = [r["image"] for r in out]
    assert images.count("evil/xmrigminer") == 1


def test_hub_search_http_error_returns_empty():
    resp = MagicMock()
    resp.status_code = 500
    session = MagicMock()
    session.get.return_value = resp
    session.headers = {}
    out = hub_search(("xmrig",), session=session)
    assert out == []


def test_hub_search_network_error_returns_empty():
    import requests
    session = MagicMock()
    session.get.side_effect = requests.RequestException("timeout")
    session.headers = {}
    out = hub_search(("xmrig",), session=session)
    assert out == []


# ---------------------------------------------------------------------------
# publisher_images
# ---------------------------------------------------------------------------

def test_publisher_images():
    results = [
        {"name": "payload", "pull_count": 100},
        {"name": "backdoor", "pull_count": 50},
    ]
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {"results": results}
    session = MagicMock()
    session.get.return_value = resp
    session.headers = {}

    out = publisher_images("teamtnt", session=session)
    images = [r["image"] for r in out]
    assert "teamtnt/payload" in images
    assert "teamtnt/backdoor" in images
    assert all(r["publisher"] == "teamtnt" for r in out)


def test_publisher_images_http_error():
    resp = MagicMock()
    resp.status_code = 404
    session = MagicMock()
    session.get.return_value = resp
    session.headers = {}
    out = publisher_images("gone", session=session)
    assert out == []


# ---------------------------------------------------------------------------
# typosquat_candidates
# ---------------------------------------------------------------------------

def test_typosquat_detects_exact_repo_name():
    results = [
        {"repo_name": "evil/alpine", "is_official": False, "pull_count": 20},
    ]
    session = _make_hub_session(results)
    out = typosquat_candidates(("alpine",), session=session)
    assert any(r["image"] == "evil/alpine" for r in out)


def test_typosquat_detects_one_edit():
    results = [
        {"repo_name": "evil/a1pine", "is_official": False, "pull_count": 30},
    ]
    session = _make_hub_session(results)
    out = typosquat_candidates(("alpine",), session=session)
    assert any(r["image"] == "evil/a1pine" for r in out)


def test_typosquat_ignores_unrelated():
    results = [
        {"repo_name": "legit/myapp", "is_official": False, "pull_count": 5},
    ]
    session = _make_hub_session(results)
    out = typosquat_candidates(("alpine",), session=session)
    assert out == []


def test_typosquat_skips_official():
    results = [
        {"repo_name": "alpine", "is_official": True, "pull_count": 9999},
    ]
    session = _make_hub_session(results)
    out = typosquat_candidates(("alpine",), session=session)
    assert out == []


# ---------------------------------------------------------------------------
# quay_search
# ---------------------------------------------------------------------------

def _make_quay_session(results: list[dict]) -> MagicMock:
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {"results": results}
    session = MagicMock()
    session.get.return_value = resp
    session.headers = {}
    return session


def test_quay_search_returns_candidates():
    results = [
        {"kind": "repository", "is_public": True, "href": "/repository/kinsing/miner"},
    ]
    session = _make_quay_session(results)
    out = quay_search(("xmrig",), session=session)
    assert len(out) == 1
    assert out[0]["image"] == "kinsing/miner"
    assert out[0]["publisher"] == "kinsing"


def test_quay_search_skips_non_repository_kind():
    results = [
        {"kind": "user", "is_public": True, "href": "/repository/kinsing/miner"},
    ]
    session = _make_quay_session(results)
    out = quay_search(("xmrig",), session=session)
    assert out == []


def test_quay_search_skips_bad_href():
    results = [
        {"kind": "repository", "is_public": True, "href": "/search/something"},
    ]
    session = _make_quay_session(results)
    out = quay_search(("xmrig",), session=session)
    assert out == []


def test_quay_search_lowercases():
    results = [
        {"kind": "repository", "is_public": True, "href": "/repository/TeamTNT/Miner"},
    ]
    session = _make_quay_session(results)
    out = quay_search(("xmrig",), session=session)
    assert out[0]["image"] == "teamtnt/miner"


def test_quay_search_deduplicates():
    results = [
        {"kind": "repository", "is_public": True, "href": "/repository/ns/img"},
    ]
    session = _make_quay_session(results)
    out = quay_search(("xmrig", "monero"), session=session)
    images = [r["image"] for r in out]
    assert images.count("ns/img") == 1


def test_quay_search_http_error():
    resp = MagicMock()
    resp.status_code = 503
    session = MagicMock()
    session.get.return_value = resp
    session.headers = {}
    out = quay_search(("xmrig",), session=session)
    assert out == []


def test_quay_search_network_error():
    import requests
    session = MagicMock()
    session.get.side_effect = requests.RequestException("timeout")
    session.headers = {}
    out = quay_search(("xmrig",), session=session)
    assert out == []


# ---------------------------------------------------------------------------
# quay_publisher_images
# ---------------------------------------------------------------------------

def test_quay_publisher_images():
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {
        "repositories": [
            {"name": "miner1"},
            {"name": "backdoor"},
        ]
    }
    session = MagicMock()
    session.get.return_value = resp
    session.headers = {}

    out = quay_publisher_images("kinsing", session=session)
    images = [r["image"] for r in out]
    assert "kinsing/miner1" in images
    assert "kinsing/backdoor" in images
    assert all(r["publisher"] == "kinsing" for r in out)


def test_quay_publisher_images_http_error():
    resp = MagicMock()
    resp.status_code = 404
    session = MagicMock()
    session.get.return_value = resp
    session.headers = {}
    out = quay_publisher_images("gone", session=session)
    assert out == []


def test_quay_publisher_images_lowercases():
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {"repositories": [{"name": "MyMiner"}]}
    session = MagicMock()
    session.get.return_value = resp
    session.headers = {}
    out = quay_publisher_images("EvilNS", session=session)
    assert out[0]["image"] == "evilns/myminer"


def test_quay_publisher_images_skips_nameless():
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {"repositories": [{"name": "ok"}, {"name": ""}]}
    session = MagicMock()
    session.get.return_value = resp
    session.headers = {}
    out = quay_publisher_images("ns", session=session)
    images = [r["image"] for r in out]
    assert "ns/ok" in images
    assert "ns/" not in images


def test_quay_publisher_images_source_term():
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {"repositories": [{"name": "img"}]}
    session = MagicMock()
    session.get.return_value = resp
    session.headers = {}
    out = quay_publisher_images("badns", session=session)
    assert out[0]["source_term"] == "publisher:badns"
