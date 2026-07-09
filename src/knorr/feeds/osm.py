"""OpenSourceMalware adapter for the container engine.

OSM's malicious-container intel lives under ``ecosystem=dockerhub`` (report_type
``container``); its malicious *package* intel lives under the package ecosystems.
Knörr consumes both: container records seed direct validation targets, and the
package set drives the SBOM match in Tier-2 (an image that installs a
known-malicious package ships known malware).

``query-latest`` is a recent-window firehose, so "present here" means "in OSM's
current window". Bearer auth with the OSM token.
"""

from __future__ import annotations

import logging
from collections import defaultdict

import requests

from .. import config

log = logging.getLogger(__name__)

CONTAINER_ECOSYSTEM = "dockerhub"
PACKAGE_ECOSYSTEMS = (
    "npm", "pypi", "crates", "nuget", "maven", "go",
    "packagist", "rubygems", "vscode", "openvsx",
)


def _threats(payload: object) -> list[dict]:
    if isinstance(payload, dict):
        for key in ("threats", "results", "data"):
            value = payload.get(key)
            if isinstance(value, list):
                return [t for t in value if isinstance(t, dict)]
    if isinstance(payload, list):
        return [t for t in payload if isinstance(t, dict)]
    return []


class OsmClient:
    """Poll OSM query-latest across the container + package ecosystems."""

    def __init__(self, token: str | None = None, session=None) -> None:
        self.token = token if token is not None else config.OSM_API_KEY
        self.session = session or requests.Session()
        self.session.headers["User-Agent"] = config.USER_AGENT

    def _get(self, ecosystem: str) -> list[dict]:
        if not self.token:
            raise RuntimeError("OSM token missing: set KN_OSM_API_KEY / GW_OSM_API_KEY")
        headers = {"Authorization": f"Bearer {self.token}", "Accept": "application/json"}
        resp = self.session.get(
            config.osm_endpoint("query-latest"),
            params={"ecosystem": ecosystem}, headers=headers, timeout=config.HTTP_TIMEOUT,
        )
        if resp.status_code != 200:
            log.warning("osm: %s -> HTTP %s", ecosystem, resp.status_code)
            return []
        return _threats(resp.json())

    def container_targets(self) -> list[dict]:
        """Malicious Docker Hub images OSM has flagged (the direct seed set).

        Each dict: {image, reference, severity, tags, threat, source}. ``image``
        is a normalized ``namespace/repo`` (tag split off into ``reference``).
        """
        out: list[dict] = []
        for t in self._get(CONTAINER_ECOSYSTEM):
            ref = (t.get("resource_identifier") or t.get("package_name") or "").strip()
            if not ref:
                continue
            # strip a registry host and split an explicit tag
            for host in ("docker.io/", "registry-1.docker.io/", "index.docker.io/"):
                if ref.lower().startswith(host):
                    ref = ref[len(host):]
            image, reference = ref, "latest"
            if "@" in image:
                image, _, reference = image.partition("@")
            elif ":" in image.rsplit("/", 1)[-1]:
                image, _, reference = image.rpartition(":")
            out.append({
                "image": image.strip("/").casefold(),
                "reference": reference,
                "severity": t.get("severity_level"),
                "tags": t.get("tags") or [],
                "threat": (t.get("threat_description") or t.get("payload_description") or "")[:400],
                "source": t.get("researcher_organization") or t.get("verified_by") or "OSM",
            })
        return out

    def _search(self, params: dict) -> dict:
        if not self.token:
            raise RuntimeError("OSM token missing: set KN_OSM_API_KEY / GW_OSM_API_KEY")
        headers = {"Authorization": f"Bearer {self.token}", "Accept": "application/json"}
        resp = self.session.get(config.osm_endpoint("search"), params=params,
                                headers=headers, timeout=config.HTTP_TIMEOUT)
        if resp.status_code != 200:
            log.warning("osm search %s -> HTTP %s", params, resp.status_code)
            return {}
        return resp.json()

    def container_catalog(self) -> set[str]:
        """The FULL OSM container catalog (paginated), not the recent window.

        This is the authoritative novelty check: query-latest only shows OSM's
        recent slice, so an image submitted earlier could age out of it and be
        wrongly re-reported. ``search`` returns the whole database.
        """
        out: set[str] = set()
        page = 1
        while True:
            data = self._search({"report_type": "container", "page": page, "limit": 100})
            rows = data.get("data") or []
            for r in rows:
                rid = (r.get("resource_identifier") or "").strip()
                if rid:
                    out.add(rid.casefold())
            if not rows or page >= data.get("total_pages", 1):
                break
            page += 1
        return out

    def already_reported(self, resource_identifier: str) -> bool:
        """Exact per-resource existence check across ALL report types."""
        data = self._search({"q": resource_identifier})
        return bool(data.get("total", 0))

    def current_reports(self, ecosystem: str = CONTAINER_ECOSYSTEM) -> dict[str, dict]:
        """CHECK OSM FIRST: what OSM currently reports for ``ecosystem``, from the
        recent-window ``query-latest`` feed, as ``{resource_key: {id, status,
        resource}}``.

        A hit here is authoritative "already reported". A miss only means "not in
        the recent window" -- it does NOT prove novelty (see :meth:`container_catalog`
        / :meth:`existing_resource` for the full-history check). Backs
        ``osm_submit.py``'s ``--reconcile``/``--audit``, which need each
        submission's live status, not just a novelty bool.
        """
        out: dict[str, dict] = {}
        for t in self._get(ecosystem):
            rid = (t.get("resource_identifier") or t.get("package_name") or "").strip()
            if not rid:
                continue
            out[rid.casefold()] = {
                "id": t.get("id"), "status": t.get("status"),
                "verified_by": t.get("verified_by"), "resource": rid,
            }
        return out

    def existing_resource(self, term: str) -> dict | None:
        """Full-history exact lookup for one resource (any report_type): the
        pre-existing OSM record for ``term``, or ``None`` if truly novel.

        Unlike :meth:`already_reported` (a bare bool), this returns the actual
        record (id, status) so a caller can tell verified from pending from a
        different researcher's duplicate. Backs ``--audit``/``--reconcile``.
        """
        data = self._search({"q": term})
        want = term.strip().casefold()
        for row in data.get("data") or []:
            rid = str(row.get("resource_identifier") or row.get("package_name") or "")
            if rid.strip().casefold() == want:
                return row
        return None

    def malicious_packages(self, ecosystems: tuple[str, ...] = PACKAGE_ECOSYSTEMS) -> dict:
        """Known-malicious packages for the SBOM match.

        Returns ``{ecosystem: {package_name_lower: {version, ...}}}``. A version
        set of ``{"*"}`` means "all versions" (OSM did not pin one).
        """
        catalog: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
        for eco in ecosystems:
            for t in self._get(eco):
                name = (t.get("package_name") or t.get("resource_identifier") or "").strip()
                if not name:
                    continue
                version = (t.get("version_info") or "").strip() or "*"
                catalog[eco][name.casefold()].add(version if version.lower() != "all" else "*")
        return {eco: {n: v for n, v in pkgs.items()} for eco, pkgs in catalog.items()}
