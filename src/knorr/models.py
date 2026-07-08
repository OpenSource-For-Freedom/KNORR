"""Data contract for the container engine (stdlib dataclasses; no pydantic).

One product record: :class:`ImageFinding` -- a malicious (or candidate) container
image, why it is flagged, and the provenance breadcrumb that surfaced it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class DetectionMethod(StrEnum):
    """How a candidate image was discovered (provenance breadcrumb)."""

    OSM_CONTAINER = "osm_container"  # OSM-flagged malicious image (dockerhub feed)
    PUBLISHER_PIVOT = "publisher_pivot"  # other image under a proven-bad publisher
    HUB_SEARCH = "hub_search"  # Docker Hub keyword search (miner families, etc.)
    TYPOSQUAT = "typosquat"  # impersonates an Official/Verified image name
    PACKAGE_PIVOT = "package_pivot"  # bakes in a known-malicious package (SBOM)
    LAYER_PIVOT = "layer_pivot"  # shares a confirmed-malicious layer digest
    DOCKERFILE_SCAN = "dockerfile_scan"  # malicious Dockerfile code found via GitHub search


class FindingStatus(StrEnum):
    """Lifecycle of an image finding."""

    CANDIDATE = "candidate"  # discovered, not yet screened
    SCREENED = "screened"  # passed Tier-1, queued for Tier-2
    CONFIRMED = "confirmed"  # intrinsic evidence (Tier-1 config or Tier-2)
    REMOVED = "removed"  # 401/404 at pull: image delisted/taken down
    REJECTED = "rejected"  # recognized false positive (retained, not deleted)


@dataclass
class ImageFinding:
    """A malicious-container finding. ``image`` (namespace/repo) is the dedup key."""

    image: str  # "namespace/repo", lowercased
    reference: str = "latest"  # tag or sha256:digest that was analyzed
    digest: str | None = None  # resolved platform-manifest digest (immutable pin)
    detection_method: DetectionMethod = DetectionMethod.HUB_SEARCH
    status: FindingStatus = FindingStatus.CANDIDATE
    score: int = 0
    signals: list[str] = field(default_factory=list)  # "category/rule" fired
    reasoning: str = ""
    publisher: str | None = None
    pull_count: int | None = None
    osm_severity: str | None = None
    osm_tags: list[str] = field(default_factory=list)
    attribution: str | None = None  # campaign / actor, when known
    tier: str | None = None  # which gate confirmed it ("A:cryptomining", ...)
    confirming: list[dict] = field(default_factory=list)  # [{category,rule,evidence}]
    evidence: dict = field(default_factory=dict)  # scanner outputs, layer digests
    first_seen_run: str | None = None
    last_seen_run: str | None = None

    @property
    def namespace(self) -> str:
        return self.image.split("/", 1)[0]

    def add_signals(self, pairs: list[tuple[str, str]]) -> None:
        merged = set(self.signals) | {f"{c}/{r}" for c, r in pairs}
        self.signals = sorted(merged)
