"""Daemonless Docker Hub / OCI registry client (Tier-1: no layer pull).

A pure-``requests`` implementation of the OCI Distribution API. It fetches the
image **manifest** and the small image **config blob** only -- never a layer
blob -- so Tier-1 screening costs almost nothing against the pull-rate budget
(PRD section 13). No Docker daemon and no skopeo dependency, which also keeps
Knörr far from executing a target image (the static-only invariant, PRD 4/11).

The config blob is high-signal on its own: it carries ``Entrypoint``, ``Cmd``,
``Env``, ``Labels``, ``User``, exposed ports, and the build ``history`` -- enough
to score miners, reverse shells, fetch-and-run build steps, and cloud-metadata
theft before a single layer is downloaded.

Auth is the standard Docker registry token flow: an anonymous or Basic-auth
request to the auth service returns a short-lived Bearer token scoped to
``repository:<repo>:pull``. An authenticated token also lifts the pull budget
from 100 to 200 per 6h.
"""

from __future__ import annotations

import base64
import logging
import time
from dataclasses import dataclass

import requests

from .. import config

log = logging.getLogger(__name__)

# 5xx is the registry's own transient failure, worth a short retry during an
# unattended overnight run; 4xx (401/403/404/429) is a meaningful answer, never
# retried here -- in particular 429 is handled by the caller via RateLimited,
# since blindly retrying against an already-exhausted pull budget just burns
# more of the retry budget for no gain.
_TRANSIENT_STATUS = frozenset({500, 502, 503, 504})

# Media types we accept for a manifest GET. Listing all four lets the registry
# hand back either a single-arch manifest or a multi-arch index/list, which we
# then resolve to the requested platform.
_MANIFEST_ACCEPT = ", ".join(
    (
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    )
)


@dataclass(frozen=True)
class ImageRef:
    """A resolved image reference: ``repository`` + tag-or-digest ``reference``."""

    repository: str  # e.g. "library/alpine", "teamtnt/foo"
    reference: str  # a tag ("latest", "3.19") or a "sha256:..." digest

    @property
    def is_digest(self) -> bool:
        return self.reference.startswith("sha256:")

    @property
    def namespace(self) -> str:
        return self.repository.split("/", 1)[0]

    def __str__(self) -> str:
        sep = "@" if self.is_digest else ":"
        return f"{self.repository}{sep}{self.reference}"


def parse_image(raw: str) -> ImageRef:
    """Normalize a user-typed image string into an :class:`ImageRef`.

    Handles: ``alpine`` -> ``library/alpine:latest``; ``user/img``; explicit
    ``:tag`` and ``@sha256:...`` digests; and strips a Docker Hub host prefix
    (``docker.io/``, ``index.docker.io/``, ``registry-1.docker.io/``).
    """
    s = raw.strip()
    for host in ("docker.io/", "index.docker.io/", "registry-1.docker.io/"):
        if s.startswith(host):
            s = s[len(host):]
            break

    if "@" in s:  # digest pin
        name, _, ref = s.partition("@")
    else:
        # A ':' is a tag only if it sits in the FINAL path segment (Hub has no
        # port, but this keeps parsing correct if a host slips through).
        last = s.rsplit("/", 1)[-1]
        if ":" in last:
            name, _, ref = s.rpartition(":")
        else:
            name, ref = s, "latest"

    name = name.strip("/")
    if "/" not in name:  # bare official image -> library/ namespace
        name = f"library/{name}"
    return ImageRef(repository=name, reference=ref)


@dataclass
class ManifestResult:
    """A resolved single-arch manifest plus the digest it was fetched at."""

    manifest: dict
    digest: str  # the platform manifest digest (Docker-Content-Digest)
    headers: dict  # response headers (carry the ratelimit-* budget on Hub)


class RegistryError(RuntimeError):
    """A non-recoverable registry response (auth, 404, malformed)."""


class RateLimited(RegistryError):
    """The registry pull budget is exhausted (HTTP 429). Distinct from a 404 so
    the hunt stops screening instead of mislabeling images as taken down."""


class DockerHubClient:
    """Minimal daemonless client over the OCI Distribution API."""

    def __init__(self, user: str | None = None, token: str | None = None, session=None, *,
                 registry: str | None = None, auth_url: str | None = None,
                 auth_service: str | None = None, api_url: str | None = None) -> None:
        # Explicit None means "use config"; empty string stays empty (anonymous).
        raw_user = config.DOCKERHUB_USER if user is None else user
        self.user = self._normalize_user(raw_user)
        self.token = config.DOCKERHUB_TOKEN if token is None else token
        # Registry profile (defaults to Docker Hub). The OCI Distribution flow is
        # identical across registries; only the host + token service differ, so
        # the same client serves GHCR (see ``for_ghcr``) by swapping these.
        self.registry = registry or config.DOCKERHUB_REGISTRY
        self.auth_url = auth_url or config.DOCKERHUB_AUTH_URL
        self.auth_service = auth_service or config.DOCKERHUB_AUTH_SERVICE
        self.api_url = api_url or config.DOCKERHUB_API_URL
        self.session = session or requests.Session()
        self.session.headers["User-Agent"] = config.USER_AGENT
        self._bearer_cache: dict[str, str] = {}

    @classmethod
    def for_ghcr(cls, session=None, token: str | None = None) -> DockerHubClient:
        """A client pointed at GHCR (ghcr.io). Same OCI token flow as Docker Hub;
        public image PULLS are anonymous, but a GitHub token lifts anonymous rate
        limits and is required for the separate package-listing discovery API
        (see ``feeds/github.py``: needs the ``read:packages`` scope)."""
        tok = config.GITHUB_TOKEN if token is None else token
        return cls(user="token" if tok else "", token=tok or "", session=session,
                   registry="ghcr.io", auth_url="https://ghcr.io/token",
                   auth_service="ghcr.io", api_url="https://api.github.com")

    @staticmethod
    def _normalize_user(raw: str | None) -> str | None:
        """A Docker Hub username is a single lowercase token, never contains
        whitespace. If the configured value carries stray text (e.g. a login was
        pasted as ``docker login <user>``), keep the last token and warn."""
        if not raw:
            return raw
        parts = raw.split()
        if len(parts) > 1:
            log.warning("DOCKERHUB_USER had extra text; using the last token as the "
                        "username (clean it up in .env to silence this)")
            return parts[-1]
        return raw

    @property
    def authenticated(self) -> bool:
        return bool(self.user and self.token)

    def _get_retry(self, url: str, *, headers: dict | None = None,
                   params: dict | None = None, max_attempts: int = 3,
                   backoff: float = 0.5):
        """GET with short exponential-backoff retry on transient failures
        (network errors, 5xx). Never retries a 4xx -- that is a real answer,
        not a blip. Overnight-run resilience: a single flaky response should
        not drop an image from the hunt.
        """
        last_exc: requests.RequestException | None = None
        for attempt in range(max_attempts):
            try:
                resp = self.session.get(url, headers=headers, params=params,
                                        timeout=config.HTTP_TIMEOUT)
            except requests.RequestException as exc:
                last_exc = exc
                if attempt < max_attempts - 1:
                    time.sleep(backoff * (2 ** attempt))
                    continue
                raise
            if resp.status_code in _TRANSIENT_STATUS and attempt < max_attempts - 1:
                log.warning("transient %s from %s; retrying (attempt %d/%d)",
                            resp.status_code, url, attempt + 1, max_attempts)
                time.sleep(backoff * (2 ** attempt))
                continue
            return resp
        raise last_exc  # pragma: no cover -- unreachable, loop always returns or raises

    # --- auth ---------------------------------------------------------------
    def _bearer(self, repository: str) -> str:
        """Fetch (and cache) a pull-scoped Bearer token for one repository."""
        if repository in self._bearer_cache:
            return self._bearer_cache[repository]
        params = {
            "service": self.auth_service,
            "scope": f"repository:{repository}:pull",
        }
        headers: dict[str, str] = {}
        if self.authenticated:
            basic = base64.b64encode(f"{self.user}:{self.token}".encode()).decode()
            headers["Authorization"] = f"Basic {basic}"
        resp = self._get_retry(self.auth_url, params=params, headers=headers)
        # Resilience: if authenticated auth fails (bad/expired token, malformed
        # login), fall back to an anonymous pull token rather than hard-stopping
        # the hunt. Public images still pull; only the budget drops to 100/6h.
        if resp.status_code != 200 and self.authenticated:
            log.warning("authenticated auth failed (%s) for %s; retrying anonymously",
                        resp.status_code, repository)
            resp = self._get_retry(self.auth_url, params=params)
        if resp.status_code != 200:
            raise RegistryError(f"auth failed ({resp.status_code}) for {repository}")
        body = resp.json()
        token = body.get("token") or body.get("access_token")
        if not token:
            raise RegistryError(f"auth response had no token for {repository}")
        self._bearer_cache[repository] = token
        return token

    def _get(self, url: str, repository: str, *, accept: str | None = None):
        headers = {"Authorization": f"Bearer {self._bearer(repository)}"}
        if accept:
            headers["Accept"] = accept
        return self._get_retry(url, headers=headers)

    # --- registry (manifest + config only; NO layer pull) -------------------
    def _manifest_url(self, ref: ImageRef) -> str:
        return f"https://{self.registry}/v2/{ref.repository}/manifests/{ref.reference}"

    def _raw_manifest(self, ref: ImageRef) -> tuple[dict, dict]:
        resp = self._get(self._manifest_url(ref), ref.repository, accept=_MANIFEST_ACCEPT)
        if resp.status_code == 429:
            raise RateLimited(f"pull budget exhausted (429) at {ref}")
        if resp.status_code == 404:
            raise RegistryError(f"manifest not found: {ref}")
        if resp.status_code != 200:
            raise RegistryError(f"manifest GET {resp.status_code} for {ref}")
        return resp.json(), dict(resp.headers)

    def resolve_manifest(
        self, ref: ImageRef, *, platform: tuple[str, str] | None = None
    ) -> ManifestResult:
        """Return a single-arch manifest, resolving a multi-arch index if needed.

        ``platform`` is (os, arch); defaults to the configured linux/amd64.
        """
        os_, arch = platform or (config.DEFAULT_PLATFORM_OS, config.DEFAULT_PLATFORM_ARCH)
        manifest, headers = self._raw_manifest(ref)
        media = manifest.get("mediaType", "")
        entries = manifest.get("manifests")
        if entries and ("index" in media or "list" in media or not manifest.get("config")):
            chosen = None
            for entry in entries:
                p = entry.get("platform", {})
                if p.get("os") == os_ and p.get("architecture") == arch:
                    chosen = entry
                    break
            chosen = chosen or entries[0]  # fall back to the first arch
            sub = ImageRef(ref.repository, chosen["digest"])
            sub_manifest, sub_headers = self._raw_manifest(sub)
            # Prefer the platform manifest's own ratelimit headers; fall back to
            # the index response's.
            return ManifestResult(sub_manifest, chosen["digest"], {**headers, **sub_headers})
        digest = headers.get("Docker-Content-Digest") or headers.get("docker-content-digest") or ""
        return ManifestResult(manifest, digest, headers)

    def get_config(self, ref: ImageRef, manifest: dict) -> dict:
        """Fetch the image config blob (Entrypoint/Cmd/Env/Labels/history)."""
        digest = (manifest.get("config") or {}).get("digest")
        if not digest:
            return {}
        url = f"https://{self.registry}/v2/{ref.repository}/blobs/{digest}"
        resp = self._get(url, ref.repository)
        if resp.status_code != 200:
            raise RegistryError(f"config blob GET {resp.status_code} for {ref}")
        return resp.json()

    def download_blob(self, repository: str, digest: str, dest, *, max_bytes: int) -> bool:
        """Stream a layer blob to ``dest`` (Tier-2). False if missing or over cap.

        This is the ONLY method that pulls a layer, and it counts against the
        pull budget -- callers gate it behind Tier-1 promotion + a run limit. The
        blob is written to disk and never executed (static-only invariant).
        """
        url = f"https://{self.registry}/v2/{repository}/blobs/{digest}"
        headers = {"Authorization": f"Bearer {self._bearer(repository)}"}
        try:
            with self.session.get(url, headers=headers, stream=True,
                                  timeout=config.HTTP_TIMEOUT) as resp:
                if resp.status_code != 200:
                    return False
                written = 0
                with open(dest, "wb") as fh:
                    for chunk in resp.iter_content(1 << 16):
                        written += len(chunk)
                        if written > max_bytes:
                            log.warning("layer %s exceeds %d bytes; skipping", digest[:19], max_bytes)
                            return False
                        fh.write(chunk)
            return True
        except (requests.RequestException, OSError) as exc:
            log.warning("blob download failed for %s: %s", repository, exc)
            return False

    # --- Hub metadata (public; no registry auth needed) ---------------------
    def hub_metadata(self, repository: str) -> dict:
        """Docker Hub repository metadata: pull_count, star_count, dates, flags.

        Returns {} on any non-200 so a missing/renamed repo never breaks a probe.
        """
        ns, _, name = repository.partition("/")
        url = f"{self.api_url}/repositories/{ns}/{name}/"
        try:
            resp = self._get_retry(url)
        except requests.RequestException:
            return {}
        return resp.json() if resp.status_code == 200 else {}


def parse_ratelimit(headers: dict) -> tuple[int | None, int | None]:
    """Extract (limit, remaining) pulls from Docker Hub's ratelimit-* headers.

    Values look like ``100;w=21600``; the leading integer is the count. Returns
    (None, None) when the headers are absent (authenticated paid pulls, or GHCR).
    """
    def _first_int(value: str | None) -> int | None:
        if not value:
            return None
        head = value.split(";", 1)[0].strip()
        return int(head) if head.isdigit() else None

    lower = {k.lower(): v for k, v in headers.items()}
    return _first_int(lower.get("ratelimit-limit")), _first_int(lower.get("ratelimit-remaining"))
