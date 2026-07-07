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
    quay_publisher_images,
    quay_search,
    typosquat_candidates,
)
from .scanning.iocs import extract_iocs, pool_owned_by_publisher

log = logging.getLogger(__name__)

# Registry host prefixes we key non-Docker-Hub findings under (so a quay ns/repo
# never collides with a Docker Hub ns/repo, and the pull path knows the host).
_REGISTRY_PREFIXES = ("quay.io/", "ghcr.io/")


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


def _attribution(tags: list[str]) -> str | None:
    lower = [t.casefold() for t in tags]
    for camp in _CAMPAIGN_TAGS:
        if camp in lower:
            return camp
    return None


def _discover(sources: set[str], osm: OsmClient, tier1_limit: int,
              confirmed_publishers: set[str] | None = None) -> dict[str, ImageFinding]:
    candidates: dict[str, ImageFinding] = {}
    # Compounding owner pivot: every publisher we already proved malicious is
    # re-enumerated for siblings, so the registry finds more each run.
    bad_publishers: set[str] = set(confirmed_publishers or set())

    if "osm_container" in sources:
        targets = osm.container_targets()
        _mon(f"  osm_container: {len(targets)} OSM-flagged image(s)")
        for t in targets:
            bad_publishers.add(t["image"].split("/", 1)[0])
            candidates.setdefault(t["image"], ImageFinding(
                image=t["image"], reference=t.get("reference") or "latest",
                detection_method=DetectionMethod.OSM_CONTAINER,
                publisher=t["image"].split("/", 1)[0],
                osm_severity=t.get("severity"), osm_tags=t.get("tags") or [],
                attribution=_attribution(t.get("tags") or []),
                reasoning=f"OSM-flagged malicious image: {t.get('threat','')[:180]}"))

    # Novel discovery (search + typosquat) is screened right after the OSM set,
    # BEFORE the publisher pivot, so a tier1 cap never crowds out images OSM does
    # not already have (the whole point is contributing novel findings).
    if "search" in sources:
        hits = hub_search(DEFAULT_SEARCH_TERMS)
        _mon(f"  hub search: {len(hits)} candidate(s) across {len(DEFAULT_SEARCH_TERMS)} terms")
        for r in hits:
            candidates.setdefault(r["image"], ImageFinding(
                image=r["image"], detection_method=DetectionMethod.HUB_SEARCH,
                publisher=r["publisher"], pull_count=r.get("pull_count"),
                reasoning=f"surfaced by Docker Hub search '{r.get('source_term')}'"))

    if "typosquat" in sources:
        hits = typosquat_candidates()
        _mon(f"  typosquat: {len(hits)} impersonation candidate(s)")
        for r in hits:
            candidates.setdefault(r["image"], ImageFinding(
                image=r["image"], detection_method=DetectionMethod.TYPOSQUAT,
                publisher=r["publisher"], pull_count=r.get("pull_count"),
                reasoning=f"name impersonates Official image ({r.get('source_term')})"))

    if "publisher" in sources and bad_publishers:
        for ns in sorted(bad_publishers):
            for r in publisher_images(ns):
                candidates.setdefault(r["image"], ImageFinding(
                    image=r["image"], detection_method=DetectionMethod.PUBLISHER_PIVOT,
                    publisher=ns, pull_count=r.get("pull_count"),
                    reasoning=f"other image under OSM-flagged publisher {ns}"))
        _mon(f"  publisher pivot: enumerated {len(bad_publishers)} bad publisher(s)")

    return candidates


def _discover_quay(sources: set[str], db: Database) -> dict[str, ImageFinding]:
    """Quay.io discovery (public, no key). Findings keyed under ``quay.io/``."""
    candidates: dict[str, ImageFinding] = {}
    if "search" in sources:
        hits = quay_search(DEFAULT_SEARCH_TERMS)
        _mon(f"  quay search: {len(hits)} candidate(s) across {len(DEFAULT_SEARCH_TERMS)} terms")
        for r in hits:
            img = f"quay.io/{r['image']}"
            candidates.setdefault(img, ImageFinding(
                image=img, detection_method=DetectionMethod.HUB_SEARCH, publisher=r["publisher"],
                reasoning=f"surfaced by Quay search '{r.get('source_term')}'"))
    if "publisher" in sources:
        quay_pubs = {row["publisher"] for row in db.conn.execute(
            "SELECT DISTINCT publisher FROM image_findings WHERE status='confirmed' "
            "AND image LIKE 'quay.io/%' AND publisher IS NOT NULL") if row["publisher"]}
        for ns in sorted(quay_pubs):
            for r in quay_publisher_images(ns):
                img = f"quay.io/{r['image']}"
                candidates.setdefault(img, ImageFinding(
                    image=img, detection_method=DetectionMethod.PUBLISHER_PIVOT, publisher=ns,
                    reasoning=f"other image under proven-bad Quay publisher {ns}"))
        if quay_pubs:
            _mon(f"  quay publisher pivot on {len(quay_pubs)} prior bad publisher(s)")
    return candidates


def run_hunt(args) -> int:
    run_id = args.run_id or f"hunt-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}"
    sources = {s.strip() for s in args.sources.split(",") if s.strip()}
    registry = getattr(args, "registry", "docker")
    # allow "osm_package" alias but the SBOM set is loaded on demand below
    db = Database.open(args.db)
    db.start_run(run_id, datetime.now(UTC).isoformat())
    client = DockerHubClient.for_quay() if registry == "quay" else DockerHubClient()
    osm = OsmClient()

    _mon(f"=== knorr hunt {run_id}  [registry: {registry}] ===")
    _mon(f"auth: {'authenticated' if client.authenticated else 'anonymous'}"
         f" | sources: {sorted(sources)} | tier2: {args.scan} (limit {args.limit})")

    _mon("[1/4] discover")
    if registry == "quay":
        candidates = _discover_quay(sources, db)
    else:
        confirmed_pubs = db.confirmed_publishers()
        if confirmed_pubs:
            _mon(f"  compounding pivot on {len(confirmed_pubs)} previously-confirmed publisher(s)")
        candidates = _discover(sources, osm, args.tier1_limit, confirmed_publishers=confirmed_pubs)
    _mon(f"  -> {len(candidates)} unique candidate image(s)")

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
        if ok:
            f.status = FindingStatus.CONFIRMED
            f.tier = tier
            f.confirming = [{"category": s.category, "rule": s.rule, "evidence": s.evidence}
                            for s in confirming]
            _capture_iocs(f, strings_from_config(cfg))
            f.reasoning += f" | CONFIRMED at Tier-1 ({tier})"
            confirmed_t1 += 1
            _mon(f"  [{i}/{len(items)}] CONFIRM {f.image}  ({tier}, score {f.score})")
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
            if ok:
                f.status = FindingStatus.CONFIRMED
                f.tier = tier
                f.confirming = [{"category": s.category, "rule": s.rule, "evidence": s.evidence}
                                for s in confirming] or [{"sbom": h} for h in sbom_hits]
                _capture_iocs(f)
                f.reasoning += f" | CONFIRMED at Tier-2 ({tier})"
                confirmed_t2 += 1
                _mon(f"      CONFIRM {f.image}  ({tier})")
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
