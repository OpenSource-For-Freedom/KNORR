"""Tests for parse_image, parse_ratelimit, and DockerHubClient (incl. Quay factory)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from knorr.registry import (
    DockerHubClient,
    ImageRef,
    ManifestResult,
    RateLimited,
    RegistryError,
    parse_image,
    parse_ratelimit,
)


# ---------------------------------------------------------------------------
# parse_image
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("raw,repo,ref", [
    ("alpine",                      "library/alpine",          "latest"),
    ("ubuntu:22.04",                "library/ubuntu",          "22.04"),
    ("teamtnt/foo",                 "teamtnt/foo",             "latest"),
    ("teamtnt/foo:evil",            "teamtnt/foo",             "evil"),
    ("docker.io/library/nginx",     "library/nginx",           "latest"),
    ("index.docker.io/user/img",    "user/img",                "latest"),
    ("registry-1.docker.io/a/b",   "a/b",                     "latest"),
    ("user/img@sha256:deadbeef",    "user/img",                "sha256:deadbeef"),
    ("  alpine  ",                  "library/alpine",          "latest"),
])
def test_parse_image(raw, repo, ref):
    r = parse_image(raw)
    assert r.repository == repo
    assert r.reference == ref


def test_image_ref_is_digest():
    r = ImageRef("ns/repo", "sha256:abc")
    assert r.is_digest is True
    r2 = ImageRef("ns/repo", "latest")
    assert r2.is_digest is False


def test_image_ref_str_tag():
    assert str(ImageRef("ns/repo", "1.0")) == "ns/repo:1.0"


def test_image_ref_str_digest():
    assert str(ImageRef("ns/repo", "sha256:ab")) == "ns/repo@sha256:ab"


def test_image_ref_namespace():
    assert ImageRef("teamtnt/payload", "latest").namespace == "teamtnt"


# ---------------------------------------------------------------------------
# parse_ratelimit
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("headers,limit,remaining", [
    ({"ratelimit-limit": "100;w=21600", "ratelimit-remaining": "73;w=21600"}, 100, 73),
    ({"RateLimit-Limit": "200;w=21600", "RateLimit-Remaining": "199;w=21600"}, 200, 199),
    ({}, None, None),
    ({"ratelimit-limit": "100;w=21600"}, 100, None),
    ({"ratelimit-remaining": "badvalue"}, None, None),
])
def test_parse_ratelimit(headers, limit, remaining):
    lim, rem = parse_ratelimit(headers)
    assert lim == limit
    assert rem == remaining


# ---------------------------------------------------------------------------
# DockerHubClient construction and auth
# ---------------------------------------------------------------------------

def test_client_authenticated():
    c = DockerHubClient(user="bob", token="secret")
    assert c.authenticated is True


def test_client_anonymous():
    c = DockerHubClient(user="", token="")
    assert c.authenticated is False


def test_client_normalize_user_extra_text(caplog):
    import logging
    with caplog.at_level(logging.WARNING, logger="knorr.registry.dockerhub"):
        c = DockerHubClient(user="docker login myuser", token="")
    assert c.user == "myuser"


# ---------------------------------------------------------------------------
# DockerHubClient.for_quay factory
# ---------------------------------------------------------------------------

def test_for_quay_profile():
    q = DockerHubClient.for_quay()
    assert q.registry == "quay.io"
    assert "quay.io" in q.auth_url
    assert q.user == "" or q.user is None or not q.authenticated
    assert not q.authenticated


# ---------------------------------------------------------------------------
# DockerHubClient.resolve_manifest (mocked HTTP)
# ---------------------------------------------------------------------------

def _make_session(status: int, json_body: dict, headers: dict | None = None):
    """Build a fake requests.Session whose .get() returns a canned response."""
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = json_body
    resp.headers = headers or {}
    session = MagicMock()
    session.get.return_value = resp
    session.headers = {}
    return session


def test_resolve_manifest_single_arch():
    manifest = {
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {"digest": "sha256:cfg"},
        "layers": [{"digest": "sha256:layer1", "size": 1000}],
    }
    headers = {"Docker-Content-Digest": "sha256:mfst", "ratelimit-remaining": "90;w=21600"}

    def get_side_effect(url, *args, **kwargs):
        resp = MagicMock()
        # token endpoint
        if "auth" in url or "token" in url:
            resp.status_code = 200
            resp.json.return_value = {"token": "fake-token"}
            resp.headers = {}
        else:
            resp.status_code = 200
            resp.json.return_value = manifest
            resp.headers = headers
        return resp

    session = MagicMock()
    session.get.side_effect = get_side_effect
    session.headers = {}

    client = DockerHubClient(user="", token="", session=session)
    ref = ImageRef("library/alpine", "latest")
    result = client.resolve_manifest(ref)
    assert result.digest == "sha256:mfst"
    assert result.manifest["config"]["digest"] == "sha256:cfg"


def test_resolve_manifest_404_raises():
    def get_side_effect(url, *args, **kwargs):
        resp = MagicMock()
        if "auth" in url or "token" in url:
            resp.status_code = 200
            resp.json.return_value = {"token": "t"}
            resp.headers = {}
        else:
            resp.status_code = 404
            resp.json.return_value = {}
            resp.headers = {}
        return resp

    session = MagicMock()
    session.get.side_effect = get_side_effect
    session.headers = {}
    client = DockerHubClient(user="", token="", session=session)
    with pytest.raises(RegistryError):
        client.resolve_manifest(ImageRef("ns/gone", "latest"))


def test_resolve_manifest_429_raises_rate_limited():
    def get_side_effect(url, *args, **kwargs):
        resp = MagicMock()
        if "auth" in url or "token" in url:
            resp.status_code = 200
            resp.json.return_value = {"token": "t"}
            resp.headers = {}
        else:
            resp.status_code = 429
            resp.json.return_value = {}
            resp.headers = {}
        return resp

    session = MagicMock()
    session.get.side_effect = get_side_effect
    session.headers = {}
    client = DockerHubClient(user="", token="", session=session)
    with pytest.raises(RateLimited):
        client.resolve_manifest(ImageRef("ns/img", "latest"))


def test_resolve_manifest_multiarch_selects_amd64():
    index = {
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [
            {"digest": "sha256:arm", "platform": {"os": "linux", "architecture": "arm64"}},
            {"digest": "sha256:x86", "platform": {"os": "linux", "architecture": "amd64"}},
        ],
    }
    arch_manifest = {
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"digest": "sha256:cfg"},
        "layers": [],
    }

    call_count = {"n": 0}

    def get_side_effect(url, *args, **kwargs):
        resp = MagicMock()
        if "auth" in url or "token" in url:
            resp.status_code = 200
            resp.json.return_value = {"token": "t"}
            resp.headers = {}
        elif call_count["n"] == 0:
            call_count["n"] += 1
            resp.status_code = 200
            resp.json.return_value = index
            resp.headers = {}
        else:
            resp.status_code = 200
            resp.json.return_value = arch_manifest
            resp.headers = {"Docker-Content-Digest": "sha256:x86"}
        return resp

    session = MagicMock()
    session.get.side_effect = get_side_effect
    session.headers = {}
    client = DockerHubClient(user="", token="", session=session)
    result = client.resolve_manifest(ImageRef("ns/img", "latest"))
    assert result.digest == "sha256:x86"


# ---------------------------------------------------------------------------
# DockerHubClient.for_quay bearer flow (different auth URL)
# ---------------------------------------------------------------------------

def test_quay_client_uses_correct_endpoints():
    client = DockerHubClient.for_quay()
    assert client.registry == "quay.io"
    assert client.auth_url == "https://quay.io/v2/auth"
    assert client.auth_service == "quay.io"
    assert client.api_url == "https://quay.io/api/v1"


def test_quay_manifest_url():
    client = DockerHubClient.for_quay()
    ref = ImageRef("ns/repo", "latest")
    url = client._manifest_url(ref)
    assert url == "https://quay.io/v2/ns/repo/manifests/latest"
