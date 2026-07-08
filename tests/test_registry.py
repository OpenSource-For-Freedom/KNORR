"""Tests for parse_image, parse_ratelimit, and DockerHubClient."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
import requests

from knorr.registry import (
    DockerHubClient,
    ImageRef,
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
# _get_retry: transient-failure resilience (overnight-run hardening). Retries
# 5xx and network errors with backoff; never retries a 4xx (a real answer,
# including 429, which the caller handles via RateLimited instead).
# ---------------------------------------------------------------------------

def _resp(status: int, body: dict | None = None) -> MagicMock:
    r = MagicMock()
    r.status_code = status
    r.json.return_value = body or {}
    r.headers = {}
    return r


def test_get_retry_succeeds_after_transient_5xx(monkeypatch):
    import knorr.registry.dockerhub as dh_module
    monkeypatch.setattr(dh_module.time, "sleep", lambda _s: None)  # no real delay in tests

    session = MagicMock()
    session.get.side_effect = [_resp(503), _resp(200, {"ok": True})]
    client = DockerHubClient(user="", token="", session=session)
    resp = client._get_retry("https://example/x")
    assert resp.status_code == 200
    assert session.get.call_count == 2


def test_get_retry_exhausts_attempts_and_returns_last_5xx(monkeypatch):
    import knorr.registry.dockerhub as dh_module
    monkeypatch.setattr(dh_module.time, "sleep", lambda _s: None)

    session = MagicMock()
    session.get.side_effect = [_resp(503), _resp(503), _resp(503)]
    client = DockerHubClient(user="", token="", session=session)
    resp = client._get_retry("https://example/x", max_attempts=3)
    assert resp.status_code == 503
    assert session.get.call_count == 3  # gives up after max_attempts, does not loop forever


def test_get_retry_never_retries_404():
    session = MagicMock()
    session.get.return_value = _resp(404)
    client = DockerHubClient(user="", token="", session=session)
    resp = client._get_retry("https://example/x")
    assert resp.status_code == 404
    assert session.get.call_count == 1  # a real answer, not retried


def test_get_retry_never_retries_429():
    session = MagicMock()
    session.get.return_value = _resp(429)
    client = DockerHubClient(user="", token="", session=session)
    resp = client._get_retry("https://example/x")
    assert resp.status_code == 429
    assert session.get.call_count == 1  # handled by the caller via RateLimited, not blind retry


def test_get_retry_recovers_from_network_exception(monkeypatch):
    import knorr.registry.dockerhub as dh_module
    monkeypatch.setattr(dh_module.time, "sleep", lambda _s: None)

    session = MagicMock()
    session.get.side_effect = [requests.RequestException("timeout"), _resp(200)]
    client = DockerHubClient(user="", token="", session=session)
    resp = client._get_retry("https://example/x")
    assert resp.status_code == 200
    assert session.get.call_count == 2


def test_get_retry_raises_after_repeated_network_exceptions(monkeypatch):
    import knorr.registry.dockerhub as dh_module
    monkeypatch.setattr(dh_module.time, "sleep", lambda _s: None)

    session = MagicMock()
    session.get.side_effect = requests.RequestException("down")
    client = DockerHubClient(user="", token="", session=session)
    with pytest.raises(requests.RequestException):
        client._get_retry("https://example/x", max_attempts=3)
    assert session.get.call_count == 3

