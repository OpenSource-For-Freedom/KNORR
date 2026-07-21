"""The hunt pipeline: discover -> Tier-1 screen -> confirm -> Tier-2 -> registry.

Static analysis only. Tier-1 fetches manifest + config (no layer pull) and
confirms config-evident malice (a miner with a baked-in pool/wallet, a reverse
shell). Tier-2 pulls layers only for promoted-but-unconfirmed leads, bounded by
``--limit`` to protect the pull budget. Nothing is ever executed; no gold is
auto-delivered and nothing is auto-submitted to OSM.
"""

from __future__ import annotations

import logging
import sys
import time
from datetime import UTC, datetime

from . import config
from .artifacts import write_findings_csv, write_summary
from .db import Database
from .feeds import OsmClient
from .models import DetectionMethod, FindingStatus, ImageFinding
from .registry import (
    DockerHubClient,
    ImageRef,
    RateLimited,
    RegistryError,
    parse_ratelimit,
)
from .scanning import (
    confirm,
    pull_and_scan,
    sbom_match,
    scan_config,
    score_signals,
    strings_from_config,
    trivy_sbom,
)
from .scanning.discovery import (
    DEFAULT_SEARCH_TERMS,
    hub_search,
    publisher_images,
    typosquat_candidates,
)
from .scanning.iocs import extract_iocs, pool_owned_by_publisher

log = logging.getLogger(__name__)

# Registry host prefixes we key non-Docker-Hub findings under (so a ghcr ns/repo
# never collides with a Docker Hub ns/repo, and the pull path knows the host).
_REGISTRY_PREFIXES = ("ghcr.io/",)

# Seed accounts for the GHCR account pivot: GitHub owners we ourselves proved
# authored malicious code (a reverse shell welded into their own Dockerfile, via
# the `knorr dockerfiles` scanner), not just aggregators of other people's files.
GHCR_SEED_ACCOUNTS = ("DVKunion", "CKmaenn", "wearenotpoliticallycorrect")


def _pull_ref(image: str, reference: str) -> ImageRef:
    """Build the OCI pull reference, stripping any registry-host key prefix."""
    repo = image
    for host in _REGISTRY_PREFIXES:
        if repo.startswith(host):
            repo = repo[len(host):]
            break
    return ImageRef(repo, reference)

_CAMPAIGN_TAGS = ("dprk", "lazarus", "teamtnt", "kinsing", "watchdog",
                  "unit42-cryptojacking-docker", "commando-cat")


def _mon(msg: str) -> None:
    """Monitored-run progress line (stderr, kept off the stdout summary)."""
    print(msg, file=sys.stderr, flush=True)


def _capture_iocs(f, extra_texts: list[str] | None = None) -> None:
    """Store extracted IOCs on a confirmed finding, and flag benign personal
    miners (pool is the publisher's own domain) so they are not treated as
    cryptojacking downstream. ``extra_texts`` carries the full config strings so a
    pool/wallet in an ENV var is captured even if it fired no detection rule."""
    iocs = extract_iocs(list(f.confirming) + list(extra_texts or []))
    f.evidence["iocs"] = iocs
    if "cryptojacking" in (f.tier or "") and pool_owned_by_publisher(iocs, f.publisher):
        f.evidence["likely_tool"] = True
        f.reasoning += (" | note: mining pool is the publisher's own domain, "
                        "likely a personal miner tool rather than cryptojacking")


def _is_known_good_publisher(f: ImageFinding) -> bool:
    """True if the image's publisher/namespace is a known-good vendor.

    Prevents auto-confirming a legitimate vendor's own tooling or test fixtures
    (a security company's demo image, a miner project's own upstream repo) --
    the exact shape of two real incidents in one night (aquasec, xmrig). Checked
    against both the tracked publisher field and the image's own namespace, so
    it still catches a case where publisher wasn't populated by discovery.
    """
    namespace = f.image.split("/", 1)[0] if "/" in f.image else f.image
    candidates = {(f.publisher or "").casefold(), namespace.casefold()}
    return bool(candidates & config.KNOWN_GOOD_PUBLISHERS)


def _osm_cross_check(f: ImageFinding, osm: OsmClient) -> None:
    """Cross-check a freshly-confirmed finding against OSM's OWN database.

    Independent corroboration: OSM already carries a VERIFIED report for this
    exact image, from another researcher entirely, is a strong signal our
    confirmation is right (recorded, not gating). A FALSE_POSITIVE verdict is
    the opposite: another set of reviewers already looked at this exact image
    and rejected it, so we should not trust our own Tier-1/Tier-2 confirm
    alone either -- downgrade to SCREENED (held for review), not silently
    stay CONFIRMED. Born from the d0whc3r/kali-ssh incident: a metasploit-
    framework install line confirmed it locally and it was submitted to OSM
    before anyone checked whether OSM (or its own reviewers) had an opinion.
    Fails open (network/API error never blocks a confirm) since this is a
    corroboration signal, not a required gate.
    """
    try:
        hit = osm.existing_resource(f.image)
    except Exception as exc:  # noqa: BLE001
        log.warning("OSM cross-check failed for %s: %s", f.image, exc)
        return
    if not hit:
        return
    status = str(hit.get("status") or "").lower()
    if status == "false_positive":
        f.status = FindingStatus.SCREENED
        f.reasoning += (f" | OSM cross-check: another researcher's report for this exact "
                        f"image was marked FALSE_POSITIVE by OSM (id "
                        f"{str(hit.get('id'))[:8]}) -- held for review, not auto-confirmed")
    elif status == "verified":
        f.evidence["osm_corroboration"] = {"id": hit.get("id"), "status": "verified"}
        f.reasoning += (f" | corroborated: OSM already has this image VERIFIED "
                        f"(id {str(hit.get('id'))[:8]}) by another researcher")


def _attribution(tags: list[str]) -> str | None:
    lower = [t.casefold() for t in tags]
    for camp in _CAMPAIGN_TAGS:
        if camp in lower:
            return camp
    return None


def _discover(sources: set[str], osm: OsmClient, tier1_limit: int,
              confirmed_publishers: set[str] | None = None,
              known: set[str] | None = None) -> dict[str, ImageFinding]:
    """Discover candidates, EXCLUDING images already in the registry (``known``).

    Without this exclusion every round rediscovers the same ~1000+ candidates in
    the same order, and since Tier-1 always screens ``items[:tier1_limit]`` from
    the FRONT of the list, a low/moderate budget never reaches sources appended
    later -- in practice the publisher pivot (our highest-yield source: it found
    isukim/cryptominer and donafro/monero) sat past position 686 in a 1103-item
    list and was never reached even once across a full 2-hour, 12-round run.

    Two fixes here: (1) skip anything already in ``known`` so the list is small
    and 100% fresh candidates, and (2) put the publisher pivot right after the
    OSM seed (proven, compounding, highest precision) instead of last, so a
    budget-constrained round still reaches it before the large, lower-precision
    hub_search set.
    """
    candidates: dict[str, ImageFinding] = {}
    known = known or set()
    # Compounding owner pivot: every publisher we already proved malicious is
    # re-enumerated for siblings, so the registry finds more each run.
    bad_publishers: set[str] = set(confirmed_publishers or set())

    def _add(image: str, **kwargs) -> None:
        if image.casefold() in known:
            return
        candidates.setdefault(image, ImageFinding(image=image, **kwargs))

    if "osm_container" in sources:
        targets = osm.container_targets()
        _mon(f"  osm_container: {len(targets)} OSM-flagged image(s)")
        for t in targets:
            bad_publishers.add(t["image"].split("/", 1)[0])
            _add(t["image"], reference=t.get("reference") or "latest",
                 detection_method=DetectionMethod.OSM_CONTAINER,
                 publisher=t["image"].split("/", 1)[0],
                 osm_severity=t.get("severity"), osm_tags=t.get("tags") or [],
                 attribution=_attribution(t.get("tags") or []),
                 reasoning=f"OSM-flagged malicious image: {t.get('threat','')[:180]}")

    # Publisher pivot SECOND (highest yield, compounding, proven-bad accounts),
    # so a budget-constrained round reaches it before the much larger and
    # lower-precision hub_search/typosquat sets ever get a chance to crowd it out.
    if "publisher" in sources and bad_publishers:
        pivot_new = 0
        for ns in sorted(bad_publishers):
            for r in publisher_images(ns):
                before = len(candidates)
                _add(r["image"], detection_method=DetectionMethod.PUBLISHER_PIVOT,
                     publisher=ns, pull_count=r.get("pull_count"),
                     reasoning=f"other image under proven-bad publisher {ns}")
                pivot_new += len(candidates) - before
        _mon(f"  publisher pivot: {pivot_new} new candidate(s) across "
             f"{len(bad_publishers)} bad publisher(s)")

    if "search" in sources:
        hits = hub_search(DEFAULT_SEARCH_TERMS, pages=4)
        _mon(f"  hub search: {len(hits)} candidate(s) across {len(DEFAULT_SEARCH_TERMS)} terms "
             f"(paginated)")
        for r in hits:
            _add(r["image"], detection_method=DetectionMethod.HUB_SEARCH,
                 publisher=r["publisher"], pull_count=r.get("pull_count"),
                 reasoning=f"surfaced by Docker Hub search '{r.get('source_term')}'")

    if "typosquat" in sources:
        hits = typosquat_candidates()
        _mon(f"  typosquat: {len(hits)} impersonation candidate(s)")
        for r in hits:
            _add(r["image"], detection_method=DetectionMethod.TYPOSQUAT,
                 publisher=r["publisher"], pull_count=r.get("pull_count"),
                 reasoning=f"name impersonates Official image ({r.get('source_term')})")

    return candidates


def _discover_ghcr(accounts, db: Database, known: set[str] | None = None,
                   sources: set[str] | None = None) -> dict[str, ImageFinding]:
    """GHCR discovery: account pivot (packages under known-bad GitHub owners) +
    image-reference search (GHCR has no keyword-search API, so this mines
    GitHub code for ``ghcr.io/<owner>/<image>`` references naming a malicious
    term instead -- the GHCR analog of ``hub_search``).

    The account pivot needs GITHUB_TOKEN to carry ``read:packages``; it
    degrades to 0 candidates (with a clear warning) if it does not, rather
    than failing the hunt.
    """
    from .feeds.github import GitHubClient
    from .scanning.ghcr_refs import search_ghcr_image_refs
    candidates: dict[str, ImageFinding] = {}
    known = known or set()
    sources = sources or {"publisher"}
    gh = GitHubClient()

    if "search" in sources:
        hits = search_ghcr_image_refs(gh, known=known, progress=_mon)
        _mon(f"  ghcr image-ref search: {len(hits)} candidate(s)")
        for r in hits:
            candidates.setdefault(r["image"], ImageFinding(
                image=r["image"], detection_method=DetectionMethod.HUB_SEARCH,
                publisher=r["publisher"],
                reasoning=f"ghcr.io reference found in GitHub code, naming '{r['source_term']}'"))

    if "publisher" in sources:
        accounts = set(accounts) | {row["publisher"] for row in db.conn.execute(
            "SELECT DISTINCT publisher FROM image_findings WHERE status='confirmed' "
            "AND image LIKE 'ghcr.io/%' AND publisher IS NOT NULL") if row["publisher"]}
        pivot_new = 0
        for owner in sorted(accounts):
            names = gh.account_container_packages(owner)
            for name in names:
                img = f"ghcr.io/{owner}/{name}".casefold()
                if img not in known and img not in candidates:
                    candidates[img] = ImageFinding(
                        image=img, detection_method=DetectionMethod.PUBLISHER_PIVOT,
                        publisher=owner,
                        reasoning=f"container package under known-bad GitHub account {owner}")
                    pivot_new += 1
        _mon(f"  ghcr account pivot: {pivot_new} new candidate(s) across "
             f"{len(accounts)} account(s)")
    return candidates


def run_hunt(args) -> int:
    run_id = args.run_id or f"hunt-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}"
    sources = {s.strip() for s in args.sources.split(",") if s.strip()}
    registry = getattr(args, "registry", "docker")
    # allow "osm_package" alias but the SBOM set is loaded on demand below
    db = Database.open(args.db)
    db.start_run(run_id, datetime.now(UTC).isoformat())
    client = DockerHubClient.for_ghcr() if registry == "ghcr" else DockerHubClient()
    osm = OsmClient()

    _mon(f"=== knorr hunt {run_id}  [registry: {registry}] ===")
    _mon(f"auth: {'authenticated' if client.authenticated else 'anonymous'}"
         f" | sources: {sorted(sources)} | tier2: {args.scan} (limit {args.limit})")

    _mon("[1/4] discover")
    known = db.known_images()
    _mon(f"  {len(known)} image(s) already in the registry (excluded from re-discovery)")
    if registry == "ghcr":
        raw_accounts = getattr(args, "ghcr_accounts", None)
        accounts = ([a.strip() for a in raw_accounts.split(",") if a.strip()]
                    if raw_accounts else GHCR_SEED_ACCOUNTS)
        candidates = _discover_ghcr(accounts, db, known=known, sources=sources)
    else:
        confirmed_pubs = db.confirmed_publishers()
        if confirmed_pubs:
            _mon(f"  compounding pivot on {len(confirmed_pubs)} previously-confirmed publisher(s)")
        candidates = _discover(sources, osm, args.tier1_limit,
                               confirmed_publishers=confirmed_pubs, known=known)
    _mon(f"  -> {len(candidates)} unique NEW candidate image(s)")

    osm_packages: dict = {}
    if args.scan and "osm_package" in sources:
        osm_packages = osm.malicious_packages()
        n = sum(len(v) for v in osm_packages.values())
        _mon(f"  loaded {n} OSM malicious package(s) for the SBOM match")

    # --- Tier-1 screen -----------------------------------------------------
    _mon("[2/4] Tier-1 screen (manifest + config, no layer pull)")
    screened: list[ImageFinding] = []
    confirmed_t1 = 0
    removed = 0
    budget_remaining = None
    items = list(candidates.values())[: args.tier1_limit]
    stopped_early = 0
    for i, f in enumerate(items, 1):
        # Budget guard: stop screening before the pull budget is exhausted, so
        # remaining images are left as candidates (unchecked) rather than being
        # mislabeled as removed by a 429.
        if budget_remaining is not None and budget_remaining < 8:
            stopped_early = len(items) - i + 1
            _mon(f"  pull budget low (~{budget_remaining} left); stopping Tier-1 at "
                 f"{i - 1}/{len(items)}, {stopped_early} left as candidates for next run")
            break
        ref = _pull_ref(f.image, f.reference)
        try:
            manifest = client.resolve_manifest(ref)
        except RateLimited:
            stopped_early = len(items) - i + 1
            _mon(f"  hit pull budget (429); stopping Tier-1 at {i - 1}/{len(items)}")
            break
        except RegistryError:
            f.status = FindingStatus.REMOVED
            f.reasoning += " | image unavailable (401/404): delisted or taken down"
            removed += 1
            db.upsert_finding(f, run_id)
            continue
        f.digest = manifest.digest or f.digest
        limit_v, rem = parse_ratelimit(manifest.headers)
        if rem is not None:
            budget_remaining = rem
        try:
            cfg = client.get_config(ref, manifest.manifest)
        except RegistryError:
            cfg = {}
        signals = scan_config(cfg)
        f.score = score_signals(signals)
        f.add_signals([(s.category, s.rule) for s in signals])
        f.evidence["manifest_layers"] = len(manifest.manifest.get("layers") or [])
        ok, tier, confirming = confirm(signals)
        if ok and _is_known_good_publisher(f):
            f.status = FindingStatus.SCREENED
            f.tier = tier
            f.reasoning += (f" | held for review: known-good publisher, would have "
                            f"confirmed at Tier-1 ({tier}) -- verify before trusting")
            screened.append(f)
        elif ok:
            f.status = FindingStatus.CONFIRMED
            f.tier = tier
            f.confirming = [{"category": s.category, "rule": s.rule, "evidence": s.evidence}
                            for s in confirming]
            _capture_iocs(f, strings_from_config(cfg))
            f.reasoning += f" | CONFIRMED at Tier-1 ({tier})"
            _osm_cross_check(f, osm)
            if f.status == FindingStatus.CONFIRMED:
                confirmed_t1 += 1
                _mon(f"  [{i}/{len(items)}] CONFIRM {f.image}  ({tier}, score {f.score})")
            else:
                screened.append(f)
                _mon(f"  [{i}/{len(items)}] held (OSM FALSE_POSITIVE) {f.image}  ({tier})")
        elif f.score >= 4 or f.detection_method == DetectionMethod.OSM_CONTAINER:
            f.status = FindingStatus.SCREENED
            screened.append(f)
        else:
            f.status = FindingStatus.CANDIDATE
        db.upsert_finding(f, run_id)
        if args.pace:
            time.sleep(args.pace)
    _mon(f"  -> {confirmed_t1} confirmed at Tier-1, {len(screened)} promoted to Tier-2, "
         f"{removed} removed/unavailable"
         + (f" | pull budget ~{budget_remaining} left" if budget_remaining is not None else ""))

    # --- Tier-2 analyze ----------------------------------------------------
    confirmed_t2 = 0
    if args.scan and screened:
        _mon(f"[3/4] Tier-2 (pull + unpack + scan), capped at {args.limit} image(s)")
        for j, f in enumerate(screened[: args.limit], 1):
            ref = _pull_ref(f.image, f.reference)
            try:
                manifest = client.resolve_manifest(ref)
            except RegistryError:
                continue
            _mon(f"  [{j}/{min(args.limit, len(screened))}] pull {f.image} "
                 f"({len(manifest.manifest.get('layers') or [])} layers)")
            t2 = pull_and_scan(client, ref.repository, manifest.manifest,
                               workdir=config.WORK_DIR)
            sbom_hits = []
            if osm_packages:
                pkgs = trivy_sbom(f"{ref.repository}:{f.reference}",
                                  username=client.user, token=client.token)
                sbom_hits = sbom_match(pkgs, osm_packages)
                if pkgs:
                    t2.trivy_ran = True
            all_signals = t2.signals
            f.add_signals([(s.category, s.rule) for s in all_signals])
            # Recompute the score to include Tier-2 layer signals: an image with a
            # clean config but a malicious baked-in file scored 0 at Tier-1.
            f.score = max(f.score, score_signals(all_signals))
            f.evidence.update({"tier2_files_scanned": t2.files_scanned,
                               "tier2_layers_pulled": t2.layers_pulled,
                               "sbom_hits": sbom_hits})
            ok, tier, confirming = confirm(all_signals, sbom_hits=sbom_hits)
            if ok and _is_known_good_publisher(f):
                f.status = FindingStatus.SCREENED
                f.tier = tier
                f.reasoning += (f" | held for review: known-good publisher, would have "
                                f"confirmed at Tier-2 ({tier}) -- verify before trusting")
            elif ok:
                f.status = FindingStatus.CONFIRMED
                f.tier = tier
                f.confirming = [{"category": s.category, "rule": s.rule, "evidence": s.evidence}
                                for s in confirming] or [{"sbom": h} for h in sbom_hits]
                _capture_iocs(f)
                f.reasoning += f" | CONFIRMED at Tier-2 ({tier})"
                _osm_cross_check(f, osm)
                if f.status == FindingStatus.CONFIRMED:
                    confirmed_t2 += 1
                    _mon(f"      CONFIRM {f.image}  ({tier})")
                else:
                    _mon(f"      held (OSM FALSE_POSITIVE) {f.image}  ({tier})")
            else:
                f.reasoning += " | Tier-2 found no confirming evidence"
            db.upsert_finding(f, run_id)
    else:
        _mon("[3/4] Tier-2 skipped (--scan off or nothing promoted)")

    # --- persist + report --------------------------------------------------
    _mon("[4/4] write artifacts")
    confirmed_rows = db.confirmed()
    counts = {
        "candidates": len(candidates),
        "tier1_screened": len(screened),
        "confirmed_tier1": confirmed_t1,
        "confirmed_tier2": confirmed_t2,
        "confirmed_total": len(confirmed_rows),
        "removed": removed,
    }
    db.finish_run(run_id, datetime.now(UTC).isoformat(), counts)
    csv_path = write_findings_csv(db, run_id)
    summary = {"run_id": run_id, "counts": counts,
               "confirmed": [
                   {"image": r["image"], "tier": r["tier"], "score": r["score"],
                    "method": r["detection_method"], "attribution": r["attribution"],
                    "reasoning": r["reasoning"]}
                   for r in confirmed_rows]}
    summary_path = write_summary(run_id, summary)
    db.close()

    _mon("")
    _mon(f"=== RESULT: {len(confirmed_rows)} confirmed malicious image(s) "
         f"({confirmed_t1} Tier-1, {confirmed_t2} Tier-2), {removed} removed ===")
    for r in sorted(confirmed_rows, key=lambda x: -x["score"])[:25]:
        attr = f"  [{r['attribution']}]" if r["attribution"] else ""
        _mon(f"  {r['tier'] or 'confirmed':22} score {r['score']:>3}  {r['image']}{attr}")
    _mon(f"\nartifacts: {csv_path.name}, {summary_path.name}  (in {config.ARTIFACTS_DIR})")
    print(f"{len(confirmed_rows)} confirmed; see artifacts/{csv_path.name}")
    return 0
