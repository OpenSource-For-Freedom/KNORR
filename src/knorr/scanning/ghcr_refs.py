"""GHCR image-reference discovery via GitHub code search.

GHCR has no public keyword-search API (unlike Docker Hub/Quay), so the only
GHCR discovery source built so far is the account pivot -- which needs a
known-bad account in hand before it can find anything. This closes that gap:
search GitHub code (Dockerfiles, compose files, Kubernetes manifests -- any
file, since these references show up in many shapes) for
``ghcr.io/<owner>/<image>`` references whose image NAME itself matches our
malicious vocabulary (miner families, campaign terms), and surface both the
image and its owner. The owner becomes a fresh seed for the account pivot the
next run, compounding the same way the Docker Hub publisher pivot does.

Reuses the exact GitHub code-search machinery built for the Dockerfile
scanner (``feeds/github.py``). Discovery only surfaces leads; the full
Tier-1/Tier-2 confirmation gate still applies before anything is trusted.
"""

from __future__ import annotations

import logging
import re
import time

log = logging.getLogger(__name__)

_GHCR_REF = re.compile(r"ghcr\.io/([\w.\-]+/[\w.\-]+?)(?::[\w.\-]+)?(?=[\"'\s]|$)", re.I)

# Malicious-vocabulary terms to pair with "ghcr.io" in the search query, and to
# require IN the extracted reference itself for precision (mirrors hub_search:
# a candidate surfaces because the term appears in its own name, not because it
# appears anywhere in an unrelated file that happens to also mention ghcr.io).
DEFAULT_GHCR_TERMS = (
    "xmrig", "cpuminer", "ccminer", "monero", "cryptominer", "kinsing",
    "xmr-stak", "nbminer", "miner",
)


def search_ghcr_image_refs(
    client, terms=DEFAULT_GHCR_TERMS, *, per_query: int = 15, pace: float = 7.0,
    known: set[str] | None = None, progress=None,
) -> list[dict]:
    """Search GitHub code for ``ghcr.io/<owner>/<image>`` references naming a
    malicious-vocabulary term. Returns candidate dicts: ``{image, publisher,
    source_term}``, ``image`` prefixed ``ghcr.io/`` (the registry-host key).
    """
    known = known or set()
    seen_files: set[str] = set()  # file-level dedup, distinct from `known` images
    out: dict[str, dict] = {}
    for i, term in enumerate(terms):
        query = f'"ghcr.io" "{term}"'
        items = client.search_code(query, per_page=per_query)
        if progress:
            progress(f"  [{i + 1}/{len(terms)}] {query!r} -> {len(items)} file(s)")
        for it in items:
            repo = it.get("repository", {}).get("full_name", "")
            path = it.get("path", "")
            file_key = f"{repo}:{path}".casefold()
            if not repo or file_key in seen_files:
                continue
            seen_files.add(file_key)
            text = client.get_content(repo, path)
            if not text:
                continue
            for m in _GHCR_REF.finditer(text):
                ref = m.group(1).strip("/").casefold()
                if "/" not in ref or term.casefold() not in ref:
                    continue  # precision filter: term must be in the ref itself
                image = f"ghcr.io/{ref}"
                if image in known:
                    continue
                owner = ref.split("/", 1)[0]
                out.setdefault(image, {"image": image, "publisher": owner,
                                       "source_term": term})
        if i < len(terms) - 1:
            time.sleep(pace)
    return list(out.values())
