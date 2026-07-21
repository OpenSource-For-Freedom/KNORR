"""``knorr watch``: a long-running, budget-aware hunting loop with alerts.

Runs repeated hunts across registries for a configured duration, posting an
alert (Discord, if ``KN_ALERT_WEBHOOK``/``GW_DISCORD_WEBHOOK`` is set) for
every NEW finding that is genuinely HIGH-confidence: the exact same
``confidence()`` gate that decides what is eligible to auto-submit to OSM (see
``scanning/confidence.py``, public because it is just pattern-matching over
already-public confirming evidence). A "review" or "byo" bucketed finding
(an ENV-default wallet, a parameterized tool) is held, not alerted, so the
Discord channel never shows something as submission-ready when it is not.

Each round runs in-process (no subprocess) and is independently exception-
guarded, so a single bad round -- a network blip, a hung scan -- never ends
the whole watch; it just logs and moves on to the next round.
"""

from __future__ import annotations

import argparse
import json
import logging
import time
from pathlib import Path

import requests

from . import config
from .db import Database
from .registry import DockerHubClient, ImageRef, RateLimited, RegistryError, parse_ratelimit
from .scanning.confidence import confidence, severity_level, wallet_to_images

log = logging.getLogger(__name__)


def _alerted_path_for(db_path: Path) -> Path:
    """Where the alert-dedup state lives for a given registry DB.

    Colocated with (and named after) the DB it tracks -- NOT a single global
    path -- so watching two different DBs (or a test's tmp DB) never share or
    contaminate each other's alerted-image history.
    """
    return db_path.with_name(f"{db_path.stem}.watch_alerted.json")


def _load_alerted(path: Path) -> set[str]:
    try:
        return set(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, ValueError):
        return set()


def _save_alerted(path: Path, alerted: set[str]) -> None:
    path.write_text(json.dumps(sorted(alerted)), encoding="utf-8")


def _post_alert(webhook: str | None, embed: dict) -> bool:
    if not webhook:
        return False
    try:
        resp = requests.post(webhook, json={"embeds": [embed]}, timeout=config.HTTP_TIMEOUT)
        return resp.status_code in (200, 204)
    except requests.RequestException as exc:
        log.warning("alert post failed: %s", exc)
        return False


def _pull_budget() -> int:
    """Best-effort Docker Hub pull budget check. 200 (optimistic) if unknown,
    0 if the budget is confirmed exhausted."""
    try:
        client = DockerHubClient()
        manifest = client.resolve_manifest(ImageRef("library/alpine", "latest"))
        _, remaining = parse_ratelimit(manifest.headers)
        return remaining if remaining is not None else 200
    except RateLimited:
        return 0
    except RegistryError:
        return 100


def _new_confirmed_findings(
    db: Database, baseline: set[str], alerted: set[str], wallet_map: dict[str, set[str]],
) -> list:
    """Confirmed findings not present at watch start and not yet alerted, gated
    to HIGH confidence only (the same bar OSM submission uses). A likely-tool
    flag, a BYO-shaped command, or an ENV-default wallet under review never
    alerts here; it is held exactly as it would be before OSM submission.
    """
    out = []
    for row in db.conn.execute("SELECT * FROM image_findings WHERE status='confirmed'"):
        image = row["image"]
        if image in baseline or image in alerted:
            continue
        evidence = json.loads(row["evidence"] or "{}")
        if evidence.get("likely_tool"):
            continue
        confirming = json.loads(row["confirming"] or "[]")
        if not confirming:
            continue  # no intrinsic proof to show or to submit
        if confidence(row, confirming, wallet_map=wallet_map) != "high":
            continue  # review/byo: held for manual review, never shown as submission-ready
        out.append(row)
    return out


def _finding_url(row, evidence: dict) -> str:
    image = row["image"]
    if evidence.get("dockerfile_url"):
        return evidence["dockerfile_url"]
    if image.startswith("ghcr.io/"):
        return f"https://{image}"
    if image.startswith("github.com/"):
        return f"https://{image.split(':', 1)[0]}"
    return f"https://hub.docker.com/r/{image}"


def _alert_embed(row) -> dict:
    """Mirror the fields that would actually go into an OSM submission
    (severity, the confirming proof line, the extracted infrastructure), not a
    fixed crypto-shaped template: a reverse-shell Dockerfile finding shows its
    proof line instead of four irrelevant blank Miner/Pool/Coin/Wallet fields.
    """
    evidence = json.loads(row["evidence"] or "{}")
    iocs = evidence.get("iocs", {})
    confirming = json.loads(row["confirming"] or "[]")
    image = row["image"]

    fields = [
        {"name": "Severity", "value": severity_level(row).upper(), "inline": True},
        {"name": "Confidence", "value": "HIGH, submission-eligible", "inline": True},
        {"name": "Score", "value": str(row["score"]), "inline": True},
        {"name": "Tier", "value": row["tier"] or "-", "inline": True},
    ]
    if row["pull_count"]:
        fields.append({"name": "Pulls", "value": str(row["pull_count"]), "inline": True})
    if row["attribution"]:
        fields.append({"name": "Campaign", "value": row["attribution"], "inline": True})

    # Crypto infrastructure, only when this finding actually has any: a
    # reverse-shell or dropper finding has no miner/pool/wallet to show.
    if any(iocs.get(k) for k in ("miners", "pools", "wallets", "coin")):
        if iocs.get("miners"):
            fields.append({"name": "Miner", "value": ", ".join(iocs["miners"]), "inline": True})
        if iocs.get("coin"):
            fields.append({"name": "Coin", "value": iocs["coin"], "inline": True})
        if iocs.get("pools"):
            fields.append({"name": "Pool", "value": iocs["pools"][0], "inline": True})
        if iocs.get("wallets"):
            fields.append({"name": "Payout wallet", "value": iocs["wallets"][0][:80],
                          "inline": False})

    # The actual proof: the same confirming line that would go into the OSM
    # payload_description, verbatim.
    top = next((c for c in confirming if isinstance(c, dict)), None)
    if top:
        ev = " ".join((top.get("evidence") or "").split())[:300]
        fields.append({"name": f"Proof: {top.get('category')}/{top.get('rule')}",
                       "value": f"```{ev}```", "inline": False})

    return {
        "title": f"Confirmed malicious container: {image}",
        "url": _finding_url(row, evidence),
        "color": 0xCC2222,
        "fields": fields,
        "footer": {"text": "Knorr container threat registry, report_type: container"},
    }


def _run_one_hunt(registry: str, db_path: Path, tier1_limit: int, limit: int, pace: float) -> None:
    """One hunt round, in-process. Exception-guarded: a crash here (a network
    blip, a hung Trivy call) is logged and skipped, never kills the watch loop."""
    from .hunt import run_hunt
    args = argparse.Namespace(
        registry=registry, db=db_path, sources="search,publisher", scan=True,
        tier1_limit=tier1_limit, limit=limit, pace=pace, run_id=None, ghcr_accounts=None,
    )
    try:
        run_hunt(args)
    except Exception:  # noqa: BLE001
        log.exception("hunt round failed (registry=%s); continuing to the next round", registry)


def watch(
    *, duration_seconds: int, db_path: Path, webhook: str | None,
    registries: list[str], round_pause: float = 600.0,
) -> dict:
    """Run repeated hunts for ``duration_seconds``, alerting on new HIGH-
    confidence findings only (the same bar OSM submission uses). Rotates
    through ``registries``; Docker Hub rounds are skipped (not failed) when
    the pull budget is low, letting it recover.
    Returns ``{"rounds": int, "new_alerts": int}``.
    """
    start = time.time()
    end = start + duration_seconds
    config.ensure_dirs()
    db_path = Path(db_path)
    alerted_path = _alerted_path_for(db_path)

    db = Database.open(db_path)
    baseline = {r["image"] for r in db.conn.execute("SELECT image FROM image_findings")}
    db.close()
    alerted = _load_alerted(alerted_path)

    log.info("watch start: baseline=%d duration=%ds registries=%s",
             len(baseline), duration_seconds, registries)
    _post_alert(webhook, {
        "title": "Knorr watch started",
        "description": ("Alerting only on new HIGH-confidence findings, the same bar "
                        f"used for OSM submission. Baseline: {len(baseline)}."),
        "color": 0x2266CC, "footer": {"text": "Knorr"}})

    rounds = 0
    new_total = 0
    idx = 0
    while time.time() < end:
        rounds += 1
        registry = registries[idx % len(registries)]
        idx += 1
        if registry == "docker":
            budget = _pull_budget()
            if budget >= 25:
                _run_one_hunt("docker", db_path, min(150, max(20, budget - 10)), 3, 0.2)
            else:
                log.info("docker pull budget low (~%d); skipping this round", budget)
        else:
            # GHCR has no daemon-side pull budget to protect (unlike Docker
            # Hub), so its round is sized by the widened DEFAULT_GHCR_TERMS
            # search instead: more Tier-1 screening headroom and a bigger
            # Tier-2 confirm slice to actually work through the larger
            # candidate pool it now surfaces.
            _run_one_hunt(registry, db_path, 80, 5, 0.2)

        db = Database.open(db_path)
        wallet_map = wallet_to_images(db)
        fresh = _new_confirmed_findings(db, baseline, alerted, wallet_map)
        db.close()
        for row in fresh:
            if _post_alert(webhook, _alert_embed(row)):
                alerted.add(row["image"])
                _save_alerted(alerted_path, alerted)
                new_total += 1
                log.info("alerted: %s (score %s)", row["image"], row["score"])

        remaining = end - time.time()
        log.info("round %d done; new alerts total %d; ~%ds left", rounds, new_total, int(remaining))
        if remaining <= 0:
            break
        time.sleep(min(round_pause, max(0, remaining)))

    summary = {"rounds": rounds, "new_alerts": new_total}
    _post_alert(webhook, {
        "title": "Knorr watch complete",
        "description": f"{rounds} round(s). {new_total} new confirmed finding(s) alerted.",
        "color": 0x22AA66, "footer": {"text": "Knorr"}})
    return summary
