"""Tests for Docker Hub discovery functions (all HTTP mocked)."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from knorr.scanning.discovery import (
    _one_edit,
    hub_search,
    publisher_images,
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
# hub_search pagination (the coverage-starvation fix: page 1 alone samples only
# ~25 of what is often 500-1000+ matches for a common term like "xmrig")
# ---------------------------------------------------------------------------

def _make_paged_session(pages: list[list[dict]]) -> MagicMock:
    """A session whose .get() returns successive pages in order, one per call."""
    responses = []
    for page_results in pages:
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"results": page_results}
        responses.append(resp)
    session = MagicMock()
    session.get.side_effect = responses
    session.headers = {}
    return session


def test_hub_search_requests_multiple_pages():
    """pages=3 must issue 3 requests for a single term when each page is full."""
    def _page(n: int) -> list[dict]:
        return [{"repo_name": f"evil/p{n}-miner{i}", "is_official": False, "pull_count": 1}
                for i in range(25)]
    session = _make_paged_session([_page(1), _page(2), _page(3)])
    out = hub_search(("xmrig",), per_term=25, pages=3, session=session)
    assert session.get.call_count == 3
    # 3 distinct pages of 25 unique names each -> 75 unique candidates
    assert len({r["image"] for r in out}) == 75


def test_hub_search_stops_early_when_page_short():
    """A page returning fewer than page_size results means the term is exhausted;
    no further pages should be requested even if ``pages`` allows more."""
    full_page = [{"repo_name": f"evil/miner{i}", "is_official": False, "pull_count": 1}
                 for i in range(25)]
    short_page = [{"repo_name": "evil/last", "is_official": False, "pull_count": 1}]
    session = _make_paged_session([full_page, short_page])
    out = hub_search(("xmrig",), per_term=25, pages=5, session=session)
    assert session.get.call_count == 2  # stopped after the short page, not 5
    assert "evil/last" in {r["image"] for r in out}


def test_hub_search_default_pages_is_one():
    """Backward-compatible default: pages=1 issues exactly one request per term."""
    session = _make_hub_session([
        {"repo_name": "evil/miner", "is_official": False, "pull_count": 1},
    ])
    hub_search(("xmrig",), session=session)
    assert session.get.call_count == 1


def test_hub_search_pagination_requests_page_param():
    """Each page request must carry the correct 'page' query parameter."""
    full_page = [{"repo_name": f"evil/m{i}", "is_official": False, "pull_count": 1}
                 for i in range(25)]
    session = _make_paged_session([full_page, [{"repo_name": "evil/z", "is_official": False}]])
    hub_search(("xmrig",), per_term=25, pages=2, session=session)
    calls = session.get.call_args_list
    assert calls[0].kwargs["params"]["page"] == 1
    assert calls[1].kwargs["params"]["page"] == 2


# ---------------------------------------------------------------------------
# publisher_images pagination (the owner pivot must enumerate a large publisher
# fully, not just its first 100 repos)
# ---------------------------------------------------------------------------

def test_publisher_images_paginates_with_next():
    page1 = {"results": [{"name": "a", "pull_count": 1}], "next": "http://next"}
    page2 = {"results": [{"name": "b", "pull_count": 1}], "next": None}
    resp1, resp2 = MagicMock(), MagicMock()
    resp1.status_code, resp1.json.return_value = 200, page1
    resp2.status_code, resp2.json.return_value = 200, page2
    session = MagicMock()
    session.get.side_effect = [resp1, resp2]
    session.headers = {}
    out = publisher_images("teamtnt", page_size=1, session=session)
    images = [r["image"] for r in out]
    assert images == ["teamtnt/a", "teamtnt/b"]


def test_publisher_images_stops_at_max_pages():
    page = {"results": [{"name": "x", "pull_count": 1}], "next": "http://next"}
    resp = MagicMock()
    resp.status_code, resp.json.return_value = 200, page
    session = MagicMock()
    session.get.return_value = resp  # always has a "next", would loop forever
    session.headers = {}
    out = publisher_images("teamtnt", page_size=1, max_pages=3, session=session)
    assert session.get.call_count == 3
    assert len(out) == 3  # one repo per page, capped at max_pages

