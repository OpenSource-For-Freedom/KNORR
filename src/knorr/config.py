"""Runtime configuration and well-known paths.

Kept deliberately small for the MVP. Secrets (registry token, OSM key) come from
the environment / a local .env so nothing sensitive is version-controlled.

Credential names are read *forgivingly*: Knörr's own ``KN_*`` names take
precedence, but the raw names from the shared root .env (``DOCKER_LOGIN`` /
``DOCKER_API_KEY``) and git_warden's ``GW_OSM_API_KEY`` are accepted as
fallbacks, so an existing .env Just Works without renaming.
"""

from __future__ import annotations

import os
from pathlib import Path

from .env import load_env_file

# Repository root = two levels up from this file (src/knorr/config.py).
PROJECT_ROOT = Path(__file__).resolve().parents[2]

# Load .env before reading any variable below (real env vars always win). We walk
# from the project dir up to the drive root loading a .env at each level, plus
# the git_warden sibling, so the shared Docker + OSM credentials are found
# wherever they live (knorr/.env, dev/.env, or the F:\ root .env the operator
# keeps). load_env_file never overwrites an already-set var, so precedence is:
# real env > most-specific .env (knorr) > ... > drive-root .env > git_warden.
for _dir in (PROJECT_ROOT, *PROJECT_ROOT.parents):
    load_env_file(_dir / ".env")
load_env_file(PROJECT_ROOT.parent / "git_warden" / ".env")

DATA_DIR = PROJECT_ROOT / "data"
ARTIFACTS_DIR = PROJECT_ROOT / "artifacts"
CACHE_DIR = DATA_DIR / "cache"

# Tier-2 layer-unpack scratch. Set KN_WORK_DIR to keep large, ephemeral layer
# extractions off a near-full system drive. None => system temp (right for CI).
_work = os.environ.get("KN_WORK_DIR")
WORK_DIR = Path(_work) if _work else None

# Single-file, version-controllable store.
DB_PATH = Path(os.environ.get("KNORR_DB", DATA_DIR / "knorr.sqlite"))


def _first_env(*names: str, default: str | None = None) -> str | None:
    """First non-empty value among ``names`` in the environment, else default."""
    for name in names:
        value = os.environ.get(name)
        if value:
            return value
    return default


# --- Credentials (from environment / .env; never hard-coded) ----------------
# Docker Hub: username + access token (dckr_pat_...). The token authenticates
# both `docker login` and the registry Bearer-token flow, and lifts the pull
# budget from 100 to 200 per 6h (PRD section 13).
DOCKERHUB_USER = _first_env("KN_DOCKERHUB_USER", "DOCKER_LOGIN", "DOCKERHUB_USERNAME")
DOCKERHUB_TOKEN = _first_env("KN_DOCKERHUB_TOKEN", "DOCKER_API_KEY", "DOCKERHUB_TOKEN")
# GitHub: read-only public token, for code-searching malicious Dockerfiles in
# source repos (the pre-publish supply-chain surface). Lifts search to 30/min.
GITHUB_TOKEN = _first_env("KN_GITHUB_TOKEN", "GW_GITHUB_TOKEN")
GITHUB_API_URL = os.environ.get("KN_GITHUB_API_URL", "https://api.github.com")
# OSM: RESTful API, Bearer auth. Shared with git_warden / git_paca.
OSM_API_KEY = _first_env("KN_OSM_API_KEY", "GW_OSM_API_KEY")
OSM_BASE_URL = os.environ.get(
    "KN_OSM_BASE_URL", "https://api.opensourcemalware.com/functions/v1/"
)
# Gold/alert channel (confirmed findings only).
ALERT_WEBHOOK = _first_env("KN_ALERT_WEBHOOK", "GW_DISCORD_WEBHOOK")

# --- Docker Hub / OCI Distribution endpoints --------------------------------
# The registry (blob/manifest) host, its token-auth service, and the Hub API
# (search, stars, pull counts, publisher metadata). Overridable so a later phase
# can re-point at GHCR / ECR Public with the same client shape.
DOCKERHUB_REGISTRY = os.environ.get("KN_DOCKERHUB_REGISTRY", "registry-1.docker.io")
DOCKERHUB_AUTH_URL = os.environ.get("KN_DOCKERHUB_AUTH_URL", "https://auth.docker.io/token")
DOCKERHUB_AUTH_SERVICE = os.environ.get("KN_DOCKERHUB_AUTH_SERVICE", "registry.docker.io")
DOCKERHUB_API_URL = os.environ.get("KN_DOCKERHUB_API_URL", "https://hub.docker.com/v2")

# Default platform to resolve out of a multi-arch image index.
DEFAULT_PLATFORM_OS = os.environ.get("KN_PLATFORM_OS", "linux")
DEFAULT_PLATFORM_ARCH = os.environ.get("KN_PLATFORM_ARCH", "amd64")

# Known-good publishers: legitimate vendors/projects whose own tooling or
# instrumentation can trip a signature (a security vendor's demo/test fixture,
# a miner project's own upstream repo, a well-known devops image). Confirmed
# findings under these publishers are held for manual review instead of
# auto-confirming, mirroring git_warden's KNOWN_GOOD_OWNERS precision sweep.
# Born from two live incidents in one night: aquasec (a security vendor's own
# OpenSSL/AppSec-ruleset fixtures) and xmrig (the upstream miner project itself,
# a BYO tool, not a cryptojacking distribution). Comma-separated via
# KN_KNOWN_GOOD_PUBLISHERS to extend without a code change.
KNOWN_GOOD_PUBLISHERS = frozenset(
    p.strip().casefold() for p in os.environ.get(
        "KN_KNOWN_GOOD_PUBLISHERS",
        "xmrig,aquasec,minervaproject,docker,library,bitnami,linuxserver,"
        "grafana,prometheus,hashicorp,datadog,newrelic,elastic,sentry",
    ).split(",") if p.strip()
)

# --- HTTP politeness ---------------------------------------------------------
HTTP_TIMEOUT = int(os.environ.get("KN_HTTP_TIMEOUT", "20"))
USER_AGENT = os.environ.get(
    "KN_USER_AGENT", "knorr/0.1 (+defensive-container-threat-intelligence)"
)


def osm_endpoint(path: str) -> str:
    """Join an endpoint path onto the OSM base URL."""
    return OSM_BASE_URL.rstrip("/") + "/" + path.lstrip("/")


def ensure_dirs() -> None:
    """Create the runtime directories if they do not yet exist."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    if WORK_DIR:
        WORK_DIR.mkdir(parents=True, exist_ok=True)
