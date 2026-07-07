"""Integration-level tests for the hunt pipeline (Quay and Docker Hub paths).

All registry HTTP calls are mocked; nothing touches the network.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from knorr.hunt import _discover_quay, _pull_ref
from knorr.models import DetectionMethod, FindingStatus, ImageFinding


# ---------------------------------------------------------------------------
# _pull_ref  (registry-prefix stripping)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("image,reference,expected_repo", [
    ("evil/miner",             "latest",       "evil/miner"),
    ("quay.io/evil/miner",     "latest",       "evil/miner"),
    ("ghcr.io/evil/miner",     "sha256:abc",   "evil/miner"),
    ("some.registry/ns/img",   "1.0",          "some.registry/ns/img"),
])
def test_pull_ref_strips_prefix(image, reference, expected_repo):
    from knorr.registry import ImageRef
    ref = _pull_ref(image, reference)
    assert ref.repository == expected_repo
    assert ref.reference == reference


# ---------------------------------------------------------------------------
# _discover_quay (mocked quay_search + quay_publisher_images + db)
# ---------------------------------------------------------------------------

def _make_db(confirmed_quay_publishers=None):
    """Minimal db mock for _discover_quay."""
    db = MagicMock()
    rows = [{"publisher": p} for p in (confirmed_quay_publishers or [])]
    db.conn.execute.return_value.__iter__ = lambda self: iter(rows)
    db.conn.execute.return_value = iter(rows)
    return db


def test_discover_quay_search_source():
    """quay_search hits are picked up and keyed under quay.io/."""
    with patch("knorr.hunt.quay_search", return_value=[
        {"image": "ns/img", "publisher": "ns", "source_term": "xmrig"},
    ]) as mock_search, \
    patch("knorr.hunt.quay_publisher_images", return_value=[]) as mock_pub:
        db = _make_db()
        candidates = _discover_quay({"search"}, db)

    assert "quay.io/ns/img" in candidates
    f = candidates["quay.io/ns/img"]
    assert f.detection_method == DetectionMethod.HUB_SEARCH
    assert f.publisher == "ns"
    assert "quay" in f.reasoning.lower()


def test_discover_quay_publisher_pivot():
    """If there are confirmed quay publishers in db, publisher_images are enumerated."""
    with patch("knorr.hunt.quay_search", return_value=[]) as mock_search, \
    patch("knorr.hunt.quay_publisher_images", return_value=[
        {"image": "evil/tool", "publisher": "evil", "source_term": "publisher:evil"},
    ]) as mock_pub:
        db = MagicMock()
        rows = [{"publisher": "evil"}]
        db.conn.execute.return_value = iter(rows)
        candidates = _discover_quay({"publisher"}, db)

    assert "quay.io/evil/tool" in candidates
    f = candidates["quay.io/evil/tool"]
    assert f.detection_method == DetectionMethod.PUBLISHER_PIVOT


def test_discover_quay_no_publisher_pivot_when_no_confirmed():
    """With no confirmed Quay publishers, publisher pivot produces nothing."""
    with patch("knorr.hunt.quay_search", return_value=[]) as mock_search, \
    patch("knorr.hunt.quay_publisher_images", return_value=[]) as mock_pub:
        db = MagicMock()
        db.conn.execute.return_value = iter([])  # empty confirmed publishers
        candidates = _discover_quay({"search", "publisher"}, db)

    mock_pub.assert_not_called()
    assert candidates == {}


def test_discover_quay_deduplicates():
    """Same image from two terms appears only once."""
    with patch("knorr.hunt.quay_search", return_value=[
        {"image": "ns/img", "publisher": "ns", "source_term": "xmrig"},
        {"image": "ns/img", "publisher": "ns", "source_term": "monero"},
    ]):
        db = _make_db()
        candidates = _discover_quay({"search"}, db)

    assert list(candidates.keys()).count("quay.io/ns/img") == 1


def test_discover_quay_empty_sources():
    db = _make_db()
    candidates = _discover_quay(set(), db)
    assert candidates == {}


# ---------------------------------------------------------------------------
# run_hunt CLI integration (smoke test, all external calls mocked)
# ---------------------------------------------------------------------------

def _make_args(registry="docker", sources="search", scan=False, tier1_limit=5,
               limit=2, pace=0.0, run_id="test-run", db=None):
    import argparse
    from pathlib import Path
    args = argparse.Namespace(
        registry=registry,
        sources=sources,
        scan=scan,
        tier1_limit=tier1_limit,
        limit=limit,
        pace=pace,
        run_id=run_id,
        db=db,
    )
    return args


def test_run_hunt_quay_smoke(tmp_path):
    """Full pipeline smoke test on Quay path: no network calls, no exceptions."""
    from knorr.hunt import run_hunt

    manifest_resp = {
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {"digest": "sha256:cfg"},
        "layers": [],
    }

    def mock_resolve_manifest(self, ref, **kwargs):
        from knorr.registry import ManifestResult
        return ManifestResult(manifest_resp, "sha256:fake", {})

    def mock_get_config(self, ref, manifest):
        return {
            "config": {
                "Entrypoint": ["/usr/bin/xmrig"],
                "Cmd": None,
                "Env": ["XMR_WALLET=43ZR6AzgXtE2B9HzNAFqTQE7ZdBCsTVWyTtQdHoPhQ6N3SPfJVzTkLrYgXaiqsS8jZ1jEkN3BCRVeJNqV6D3H5DmBb5HAxy",
                        "POOL=stratum+tcp://pool.supportxmr.com:3333"],
                "Labels": {},
                "User": "",
            },
            "history": [],
        }

    with patch("knorr.hunt.quay_search", return_value=[
            {"image": "evil/xmrig", "publisher": "evil", "source_term": "xmrig"},
        ]), \
        patch("knorr.hunt.quay_publisher_images", return_value=[]), \
        patch("knorr.hunt.DockerHubClient.resolve_manifest", mock_resolve_manifest), \
        patch("knorr.hunt.DockerHubClient.get_config", mock_get_config), \
        patch("knorr.hunt.write_findings_csv", return_value=MagicMock(name="out.csv")), \
        patch("knorr.hunt.write_summary", return_value=MagicMock(name="summary.json")):

        args = _make_args(
            registry="quay",
            sources="search",
            scan=False,
            db=tmp_path / "hunt.sqlite",
        )
        ret = run_hunt(args)

    assert ret == 0


def test_run_hunt_docker_smoke(tmp_path):
    """Full pipeline smoke test on Docker Hub path (clean image, no confirms)."""
    from knorr.hunt import run_hunt

    manifest_resp = {
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {"digest": "sha256:cfg"},
        "layers": [],
    }

    def mock_resolve_manifest(self, ref, **kwargs):
        from knorr.registry import ManifestResult
        return ManifestResult(manifest_resp, "sha256:fake", {})

    def mock_get_config(self, ref, manifest):
        return {"config": {"Entrypoint": ["nginx", "-g", "daemon off;"], "Cmd": None,
                            "Env": [], "Labels": {}, "User": ""}, "history": []}

    with patch("knorr.hunt.hub_search", return_value=[
            {"image": "ns/cleanapp", "publisher": "ns",
             "pull_count": 100, "source_term": "xmrig"},
        ]), \
        patch("knorr.hunt.DockerHubClient.resolve_manifest", mock_resolve_manifest), \
        patch("knorr.hunt.DockerHubClient.get_config", mock_get_config), \
        patch("knorr.hunt.OsmClient.container_targets", return_value=[]), \
        patch("knorr.hunt.write_findings_csv", return_value=MagicMock(name="out.csv")), \
        patch("knorr.hunt.write_summary", return_value=MagicMock(name="summary.json")):

        args = _make_args(
            registry="docker",
            sources="search",
            scan=False,
            db=tmp_path / "hunt.sqlite",
        )
        ret = run_hunt(args)

    assert ret == 0
