"""Integration-level tests for the hunt pipeline (Docker Hub + GHCR paths).

All registry HTTP calls are mocked; nothing touches the network.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from knorr.hunt import _discover, _is_known_good_publisher, _pull_ref
from knorr.models import DetectionMethod, ImageFinding

# ---------------------------------------------------------------------------
# _pull_ref  (registry-prefix stripping)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("image,reference,expected_repo", [
    ("evil/miner",             "latest",       "evil/miner"),
    ("ghcr.io/evil/miner",     "sha256:abc",   "evil/miner"),
    ("some.registry/ns/img",   "1.0",          "some.registry/ns/img"),
])
def test_pull_ref_strips_prefix(image, reference, expected_repo):
    ref = _pull_ref(image, reference)
    assert ref.repository == expected_repo
    assert ref.reference == reference


# ---------------------------------------------------------------------------
# run_hunt CLI integration (smoke test, all external calls mocked)
# ---------------------------------------------------------------------------

def _make_args(registry="docker", sources="search", scan=False, tier1_limit=5,
               limit=2, pace=0.0, run_id="test-run", db=None):
    import argparse
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


# ---------------------------------------------------------------------------
# _discover: known-image exclusion (the starvation-fix regression guard).
#
# Without this, every round rediscovers the same ~1000+ candidates and, since
# Tier-1 always screens items[:tier1_limit] from the FRONT of a fixed-order
# list, a budget-constrained round never reaches sources appended later. These
# tests pin both halves of the fix: (1) already-known images are dropped from
# rediscovery, and (2) the publisher pivot is ordered before hub_search/
# typosquat so it is never crowded out.
# ---------------------------------------------------------------------------

def _mock_osm(targets=None):
    osm = MagicMock()
    osm.container_targets.return_value = targets or []
    return osm


def test_discover_excludes_known_images():
    """An image already in `known` must not reappear as a fresh candidate."""
    with patch("knorr.hunt.hub_search", return_value=[
            {"image": "evil/miner", "publisher": "evil", "pull_count": 1,
             "source_term": "xmrig"},
        ]), \
        patch("knorr.hunt.typosquat_candidates", return_value=[]):
        candidates = _discover({"search"}, _mock_osm(), 100, known={"evil/miner"})
    assert candidates == {}


def test_discover_keeps_unknown_images():
    """A genuinely new image (not in `known`) must still surface."""
    with patch("knorr.hunt.hub_search", return_value=[
            {"image": "evil/miner", "publisher": "evil", "pull_count": 1,
             "source_term": "xmrig"},
        ]), \
        patch("knorr.hunt.typosquat_candidates", return_value=[]):
        candidates = _discover({"search"}, _mock_osm(), 100, known={"someone/else"})
    assert "evil/miner" in candidates


def test_discover_publisher_pivot_ordered_before_hub_search():
    """The publisher pivot must be discoverable ahead of hub_search in the
    returned dict's iteration order, so a low tier1_limit slice still reaches
    it (dict insertion order == first-N screening order in run_hunt)."""
    with patch("knorr.hunt.publisher_images", return_value=[
            {"image": "badpub/sibling", "publisher": "badpub", "pull_count": 1,
             "source_term": "publisher:badpub"},
        ]), \
        patch("knorr.hunt.hub_search", return_value=[
            {"image": "unrelated/miner", "publisher": "unrelated", "pull_count": 1,
             "source_term": "xmrig"},
        ]), \
        patch("knorr.hunt.typosquat_candidates", return_value=[]):
        candidates = _discover(
            {"search", "publisher"}, _mock_osm(), 100,
            confirmed_publishers={"badpub"})
    order = list(candidates.keys())
    assert order.index("badpub/sibling") < order.index("unrelated/miner")


def test_discover_publisher_pivot_reports_only_new_candidates():
    """The publisher-pivot count logged/returned reflects NEW candidates only,
    not re-additions of images the OSM seed already contributed."""
    with patch("knorr.hunt.publisher_images", return_value=[
            {"image": "badpub/a", "publisher": "badpub", "pull_count": 1},
            {"image": "badpub/b", "publisher": "badpub", "pull_count": 1},
        ]), \
        patch("knorr.hunt.hub_search", return_value=[]), \
        patch("knorr.hunt.typosquat_candidates", return_value=[]):
        candidates = _discover(
            {"publisher"}, _mock_osm(), 100, confirmed_publishers={"badpub"})
    assert set(candidates) == {"badpub/a", "badpub/b"}


# ---------------------------------------------------------------------------
# _is_known_good_publisher (the systemic FP-prevention gate). Born from two
# live incidents in one night: aquasec (a security vendor's own AppSec-ruleset
# fixtures) and xmrig (the upstream miner project itself, a BYO tool).
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("image,publisher,expected", [
    ("xmrig/xmrig", "xmrig", True),
    ("aquasec/codesec-remediation", "aquasec", True),
    ("isukim/xmrig", "isukim", False),          # similar image name, different publisher
    ("shahzaadt/xmrig", None, False),           # publisher unset, namespace not allowlisted
    ("XMRig/XMRig", "XMRig", True),             # case-insensitive
])
def test_is_known_good_publisher(image, publisher, expected):
    f = ImageFinding(image=image, publisher=publisher,
                     detection_method=DetectionMethod.HUB_SEARCH)
    assert _is_known_good_publisher(f) is expected
