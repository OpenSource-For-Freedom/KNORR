"""Command-line entry point for Knörr.

``probe``  -- Tier-1 only: fetch one image's manifest + config (no layer pull),
             score the config signatures, and print the pull-rate headroom. The
             cheap sanity check to run against live Docker Hub before trusting
             the full pipeline.
``hunt``   -- the full pipeline (discover -> Tier-1 -> Tier-2 -> registry).
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from . import config


def _cmd_probe(args: argparse.Namespace) -> int:
    """Tier-1 probe of a single image: manifest + config + signature score."""
    from .registry import DockerHubClient, RegistryError, parse_image, parse_ratelimit
    from .scanning import scan_config, score_signals

    ref = parse_image(args.image)
    client = DockerHubClient()
    auth = "authenticated (200 pulls/6h)" if client.authenticated else "ANONYMOUS (100 pulls/6h)"
    print(f"probe {ref}   [{auth}]")
    if not client.authenticated:
        print("  note: set DOCKER_LOGIN / DOCKER_API_KEY (or KN_DOCKERHUB_*) for the "
              "higher budget.")

    try:
        result = client.resolve_manifest(ref, platform=(args.os, args.arch))
    except RegistryError as exc:
        print(f"  error: {exc}")
        return 2

    limit, remaining = parse_ratelimit(result.headers)
    layers = result.manifest.get("layers") or []
    total_mb = sum(layer.get("size", 0) for layer in layers) / 1_000_000
    print(f"  platform:   {args.os}/{args.arch}")
    print(f"  digest:     {result.digest or '(not reported)'}")
    print(f"  layers:     {len(layers)}  (~{total_mb:.1f} MB compressed, NOT pulled)")
    if limit is not None:
        print(f"  pull budget: {remaining}/{limit} remaining this window")

    try:
        config_json = client.get_config(ref, result.manifest)
    except RegistryError as exc:
        print(f"  error fetching config blob: {exc}")
        return 2

    cfg = config_json.get("config") or {}
    entrypoint = cfg.get("Entrypoint")
    cmd = cfg.get("Cmd")
    print("\n  --- image config (Tier-1 surface, no layer pull) ---")
    print(f"  ENTRYPOINT: {entrypoint}")
    print(f"  CMD:        {cmd}")
    print(f"  USER:       {cfg.get('User') or '(root)'}")
    print(f"  ENV:        {len(cfg.get('Env') or [])} var(s)")
    print(f"  LABELS:     {len(cfg.get('Labels') or {})}")
    print(f"  history:    {len(config_json.get('history') or [])} build step(s)")

    signals = scan_config(config_json)
    print(f"\n  --- Tier-1 signature scan: score {score_signals(signals)}, "
          f"{len(signals)} signal(s) ---")
    if not signals:
        print("  (clean at Tier-1; nothing in config/history matched a signature)")
    for sig in signals:
        print(f"  [{sig.category}/{sig.rule}]")
        print(f"      {sig.evidence}")

    if args.json:
        payload = {
            "image": str(ref), "digest": result.digest,
            "platform": f"{args.os}/{args.arch}", "layers": len(layers),
            "score": score_signals(signals),
            "signals": [{"category": s.category, "rule": s.rule, "evidence": s.evidence}
                        for s in signals],
        }
        Path(args.json).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"\n  wrote {args.json}")
    return 0


def _cmd_hunt(args: argparse.Namespace) -> int:
    """Full hunt: discover -> Tier-1 -> Tier-2 -> registry (see hunt.py)."""
    from .hunt import run_hunt

    config.ensure_dirs()
    return run_hunt(args)


def _finding_from_dockerfile_hit(hit):
    """Map a DockerfileHit onto the same ImageFinding record the registry hunt
    uses, so malicious Dockerfile code shows up in the SAME registry (and
    dashboard) as malicious images, instead of only ever being printed to a
    console and forgotten. Keyed ``github.com/<owner>/<repo>:<path>`` (not a
    pullable OCI image; this artifact is a source file, not a container), with
    the GitHub blob URL stashed in evidence for the dashboard link.
    """
    from .models import DetectionMethod, FindingStatus, ImageFinding

    if hit.confirmed:
        status = FindingStatus.CONFIRMED
    elif hit.score >= 4:
        status = FindingStatus.SCREENED
    else:
        status = FindingStatus.CANDIDATE
    cats = sorted({s.split("/")[0] for s in hit.signals})
    f = ImageFinding(
        image=f"github.com/{hit.repo}:{hit.path}".casefold(),
        reference=hit.path,
        detection_method=DetectionMethod.DOCKERFILE_SCAN,
        status=status,
        score=hit.score,
        signals=list(hit.signals),
        publisher=hit.repo.split("/", 1)[0].casefold(),
        tier=hit.tier,
        confirming=list(hit.confirming),
        reasoning=f"malicious Dockerfile code in {hit.repo}/{hit.path} "
                 f"(facets: {', '.join(cats) or '-'})",
        evidence={"dockerfile_url": hit.url, "path": hit.path},
    )
    return f


def _cmd_dockerfiles(args: argparse.Namespace) -> int:
    """Scan GitHub for malicious Dockerfile CODE (non-crypto: revshell/C2/exfil/dropper)."""
    from .db import Database
    from .feeds.github import GitHubClient
    from .scanning.dockerfile import scan_dockerfiles

    if not config.GITHUB_TOKEN:
        print("error: no GitHub token (set KN_GITHUB_TOKEN / GW_GITHUB_TOKEN).")
        return 2
    config.ensure_dirs()
    db = Database.open(args.db)
    known = {img[len("github.com/"):] for img in db.known_images() if img.startswith("github.com/")}
    print(f"scanning GitHub for malicious Dockerfiles (pace {args.pace}s/query, "
          f"{len(known)} file(s) already known)...\n")
    run_id = f"dockerfiles-{args.per_query}-{args.pace}"
    try:
        hits = scan_dockerfiles(GitHubClient(), per_query=args.per_query, pace=args.pace,
                                known=known, progress=lambda m: print(m, file=sys.stderr))
        for hit in hits:
            db.upsert_finding(_finding_from_dockerfile_hit(hit), run_id)
    finally:
        db.close()

    confirmed = [h for h in hits if h.confirmed]
    candidates = [h for h in hits if not h.confirmed]
    confirmed.sort(key=lambda h: -h.score)
    print(f"\n=== {len(confirmed)} CONFIRMED malicious Dockerfile(s), "
          f"{len(candidates)} candidate(s) screened -- {len(hits)} persisted to the "
          f"registry (db: {args.db}) ===\n")
    for h in confirmed:
        cats = sorted({s.split('/')[0] for s in h.signals})
        print(f"[{h.tier}]  {h.repo}/{h.path}")
        print(f"    facets: {', '.join(cats)}")
        for c in h.confirming[:2]:
            print(f"    proof [{c['category']}/{c['rule']}]: {c['evidence'][:130]}")
        print(f"    {h.url}\n")
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    """Serve the live threat-telemetry dashboard (read-only over the registry)."""
    from .dashboard import serve

    print(f"Knorr dashboard -> http://{args.host}:{args.port}  (db: {args.db})")
    serve(db_path=args.db, host=args.host, port=args.port)
    return 0


def _cmd_watch(args: argparse.Namespace) -> int:
    """Long-running hunt loop with alerts on new confirmed findings."""
    from .watch import watch

    config.ensure_dirs()
    webhook = config.ALERT_WEBHOOK
    if not webhook:
        print("note: no KN_ALERT_WEBHOOK/GW_DISCORD_WEBHOOK configured; "
              "hunting will run but nothing will be alerted.")
    registries = [r.strip() for r in args.registries.split(",") if r.strip()]
    summary = watch(duration_seconds=args.duration, db_path=args.db, webhook=webhook,
                    registries=registries, round_pause=args.interval)
    json.dump(summary, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="knorr", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    probe = sub.add_parser("probe", help="Tier-1 probe of one image (no layer pull).")
    probe.add_argument("--image", required=True, help="Image ref, e.g. alpine or user/img:tag.")
    probe.add_argument("--os", default=config.DEFAULT_PLATFORM_OS, help="Platform OS.")
    probe.add_argument("--arch", default=config.DEFAULT_PLATFORM_ARCH, help="Platform arch.")
    probe.add_argument("--json", default=None, help="Write the probe result to this JSON path.")
    probe.set_defaults(func=_cmd_probe)

    hunt = sub.add_parser("hunt", help="Full pipeline: discover -> Tier-1 -> Tier-2 -> registry.")
    hunt.add_argument("--db", type=Path, default=config.DB_PATH, help="SQLite path.")
    hunt.add_argument("--registry", choices=["docker", "ghcr"], default="docker",
                      help="Registry to hunt: docker (Docker Hub) or ghcr "
                           "(GitHub Container Registry).")
    hunt.add_argument("--ghcr-accounts", default=None,
                      help="Comma-separated GitHub owners to pivot on for --registry ghcr "
                           "(default: the built-in known-bad seed list).")
    hunt.add_argument("--limit", type=int, default=15,
                      help="Max images to Tier-2 pull+scan (protects the pull budget).")
    hunt.add_argument("--tier1-limit", type=int, default=120,
                      help="Max candidates to Tier-1 screen (cheap manifest+config).")
    hunt.add_argument("--scan", action="store_true",
                      help="Run Tier-2 pull+scan on promoted candidates (else Tier-1 only).")
    hunt.add_argument("--sources", default="osm_container,osm_package,search,typosquat",
                      help="Comma-separated discovery sources to enable.")
    hunt.add_argument("--run-id", default=None, help="Override the generated run id.")
    hunt.add_argument("--pace", type=float, default=1.0,
                      help="Seconds between registry calls (politeness).")
    hunt.set_defaults(func=_cmd_hunt)

    dfiles = sub.add_parser("dockerfiles",
                            help="Scan GitHub for malicious Dockerfile code (non-crypto threats).")
    dfiles.add_argument("--db", type=Path, default=config.DB_PATH,
                       help="SQLite path (findings persist to the registry).")
    dfiles.add_argument("--per-query", type=int, default=15, help="Results per search query.")
    dfiles.add_argument("--pace", type=float, default=7.0, help="Seconds between code searches.")
    dfiles.set_defaults(func=_cmd_dockerfiles)

    serve = sub.add_parser("serve", help="Serve the live threat-telemetry dashboard.")
    serve.add_argument("--db", type=Path, default=config.DB_PATH, help="SQLite path.")
    serve.add_argument("--host", default="127.0.0.1", help="Bind host.")
    serve.add_argument("--port", type=int, default=8789, help="Bind port.")
    serve.set_defaults(func=_cmd_serve)

    watch_p = sub.add_parser(
        "watch", help="Long-running hunt loop with alerts on new confirmed findings.")
    watch_p.add_argument("--db", type=Path, default=config.DB_PATH, help="SQLite path.")
    watch_p.add_argument("--duration", type=int, default=7200,
                         help="Total seconds to run (default 7200 = 2h).")
    watch_p.add_argument("--interval", type=float, default=600.0,
                         help="Seconds to pause between rounds (default 600 = 10m).")
    watch_p.add_argument("--registries", default="docker,ghcr",
                         help="Comma-separated registries to rotate through each round.")
    watch_p.set_defaults(func=_cmd_watch)
    return parser


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(
        level=logging.INFO, format="%(levelname)s %(name)s: %(message)s", stream=sys.stderr)
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\ninterrupted.", file=sys.stderr)
        return 130
    except Exception:  # noqa: BLE001
        logging.getLogger("knorr.cli").exception("command failed")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
