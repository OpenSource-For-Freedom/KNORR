"""Discovery: surface candidate images to screen (PRD section 11.4).

Sources here hit the public Docker Hub API (no registry auth needed):

* ``hub_search`` -- keyword search (miner families, campaign terms). The
  novel-image multiplier: finds images OSM never catalogued.
* ``publisher_images`` -- enumerate every repo under a proven-bad publisher
  (the owner pivot: one confirmed miner -> the account's whole fleet).
* ``typosquat_candidates`` -- impersonations of Official/Verified image names.

Each returns candidate dicts; discovery never confirms, it only surfaces leads
for Tier-1 screening.
"""

from __future__ import annotations

import logging

import requests

from .. import config

log = logging.getLogger(__name__)

# Miner families, coins, and campaign terms that surface cryptojacking images.
DEFAULT_SEARCH_TERMS = (
    # miner families
    "xmrig", "cpuminer", "ccminer", "nbminer", "t-rex miner", "lolminer",
    "phoenixminer", "ethminer", "nanominer", "teamredminer", "srbminer",
    "xmr-stak", "ariominer", "verus miner", "randomx",
    # coins / generic
    "monero miner", "coinminer", "crypto miner", "mining pool", "stratum",
    "cryptonight", "supportxmr", "nicehash", "unmineable",
    # known campaigns / droppers
    "kinsing", "kdevtmpfsi", "teamtnt", "watchdog miner",
)

# Official/Verified images most impersonated; the typosquat detector's anchors.
TYPOSQUAT_TARGETS = (
    "alpine", "ubuntu", "nginx", "python", "node", "redis", "mysql",
    "postgres", "tensorflow", "busybox", "golang", "openjdk",
)


def _hub_get(session, path: str, params: dict) -> dict:
    try:
        resp = session.get(f"{config.DOCKERHUB_API_URL}{path}", params=params,
                           timeout=config.HTTP_TIMEOUT)
    except requests.RequestException as exc:
        log.warning("hub GET %s failed: %s", path, exc)
        return {}
    return resp.json() if resp.status_code == 200 else {}


def hub_search(terms=DEFAULT_SEARCH_TERMS, *, per_term: int = 25, pages: int = 1,
              session=None) -> list[dict]:
    """Docker Hub keyword search -> candidate images (skips Official images).

    ``pages`` paginates each term (page_size=100 max per Hub's API): a single
    page-1 fetch samples only the top ~25 of what is often 500-1000+ matching
    repos for a common term like "xmrig", so real coverage needs pagination, not
    just more terms. Stops early for a term once a page returns fewer results
    than requested (exhausted).
    """
    session = session or requests.Session()
    session.headers["User-Agent"] = config.USER_AGENT
    page_size = min(max(per_term, 25), 100)
    out: dict[str, dict] = {}
    for term in terms:
        for page in range(1, pages + 1):
            data = _hub_get(session, "/search/repositories/",
                            {"query": term, "page_size": page_size, "page": page})
            results = data.get("results", [])
            for r in results:
                name = (r.get("repo_name") or "").strip().casefold()
                if not name or r.get("is_official"):
                    continue
                if "/" not in name:  # official/library images -> skip (curated)
                    continue
                out.setdefault(name, {
                    "image": name,
                    "publisher": name.split("/", 1)[0],
                    "pull_count": r.get("pull_count"),
                    "star_count": r.get("star_count"),
                    "source_term": term,
                })
            if len(results) < page_size:
                break  # this term is exhausted; no point requesting further pages
    return list(out.values())


def publisher_images(namespace: str, *, page_size: int = 100, max_pages: int = 5,
                     session=None) -> list[dict]:
    """Every repository under one Docker Hub namespace (the owner pivot), paginated."""
    session = session or requests.Session()
    session.headers["User-Agent"] = config.USER_AGENT
    out = []
    page = 1
    while page <= max_pages:
        data = _hub_get(session, f"/repositories/{namespace}/",
                        {"page_size": page_size, "page": page})
        results = data.get("results", [])
        for r in results:
            name = f"{namespace}/{r.get('name')}".casefold()
            out.append({
                "image": name,
                "publisher": namespace,
                "pull_count": r.get("pull_count"),
                "source_term": f"publisher:{namespace}",
            })
        if not data.get("next") or len(results) < page_size:
            break
        page += 1
    return out


def typosquat_candidates(targets=TYPOSQUAT_TARGETS, *, per_term: int = 25, session=None) -> list[dict]:
    """Search each Official name and keep near-miss namespaced impersonations.

    A user repo whose *repo* name equals an Official image (e.g. ``someuser/alpine``)
    or is one edit away is a possible impersonation lead. Heuristic only; the
    confirmation gate still requires intrinsic evidence.
    """
    session = session or requests.Session()
    session.headers["User-Agent"] = config.USER_AGENT
    out: dict[str, dict] = {}
    for target in targets:
        data = _hub_get(session, "/search/repositories/",
                        {"query": target, "page_size": per_term})
        for r in data.get("results", []):
            name = (r.get("repo_name") or "").strip().casefold()
            if "/" not in name or r.get("is_official"):
                continue
            repo = name.split("/", 1)[1]
            if repo == target or _one_edit(repo, target):
                out.setdefault(name, {
                    "image": name, "publisher": name.split("/", 1)[0],
                    "pull_count": r.get("pull_count"), "source_term": f"typosquat:{target}",
                })
    return list(out.values())


def _one_edit(a: str, b: str) -> bool:
    """True if ``a`` is within one substitution of ``b`` (same length only)."""
    if a == b or len(a) != len(b):
        return False
    return sum(x != y for x, y in zip(a, b, strict=True)) == 1
