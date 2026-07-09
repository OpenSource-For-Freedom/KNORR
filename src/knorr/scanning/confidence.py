"""Confidence tiering + severity classification for confirmed findings.

Public (unlike ``osm_submit.py``, which stays out of the public repo by
design): these are pure pattern-matching heuristics over data already public
in the registry (confirming evidence, pull_count, tier) -- nothing here is
OSM-submission-secret. Shared by the private OSM submission gate AND the
public dashboard/``knorr watch`` alerting, so "what we alert on" and "what we
actually submit to OSM" are always computed by the exact same logic instead of
two versions quietly drifting apart.
"""

from __future__ import annotations

import json
import re

# A miner whose pool/wallet come from runtime variables ($WALLET, ${POOL},
# %USER%) is a bring-your-own-config TOOL, not cryptojacking: it mines to whoever
# runs it supplies, not to a baked-in attacker. These must never be treated as
# submission-ready (the giansalex/monero-miner false positive: 12.7M pulls,
# entrypoint ./xmrig --url=$POOL --user=$WALLET). Held for manual review instead.
_ENV_VAR = re.compile(r"\$\{?\w+\}?|%\w+%")
_MINER_CMD = re.compile(
    r"(xmrig|ariominer|nanominer|ccminer|cpuminer|srbminer|nbminer|minerd|xmr-stak|"
    r"t-rex|lolminer|/[\w.\-]*miner\b|--url|--pool|-wallet|(?<!\w)-o\s)", re.I)
# A wallet supplied as a literal command flag value (not an ENV assignment).
# Accepts single- and double-dash forms (nanominer uses ``-wallet``, xmrig
# ``--user``/``-u``, srbminer ``--wallet``).
CMD_WALLET_RE = re.compile(r"(?:--?wallet|--?user|-u)[=\s]+[A-Za-z0-9]{40,}", re.I)
# A wallet assigned via ENV (WALLET=..., WALLET_ADDRESS=...), not a command
# flag -- overridable, so weaker evidence than a literal flag value (the
# madebytimo/xmrig case: WALLET_ADDRESS=... in the image config, not a --user
# flag; genuinely gray-area, not confirm-alone-worthy).
_ENV_WALLET = re.compile(r"\b\w*WALLET\w*\s*=\s*[A-Za-z0-9]{40,}", re.I)


def is_byo_tool(confirming: list) -> bool:
    """True if the auto-run miner command parameterizes its pool/wallet/user."""
    for c in confirming:
        ev = c.get("evidence", "") if isinstance(c, dict) else ""
        if _MINER_CMD.search(ev) and _ENV_VAR.search(ev):
            return True
    return False


def has_literal_command_wallet(confirming: list) -> bool:
    """True if a real payout wallet is welded into the miner command itself
    (highest confidence: the image auto-mines to the attacker with no override)."""
    for c in confirming:
        ev = c.get("evidence", "") if isinstance(c, dict) else ""
        if _MINER_CMD.search(ev) and CMD_WALLET_RE.search(ev):
            return True
    return False


def has_env_only_wallet(confirming: list) -> bool:
    """True if a wallet is only ever assigned via an ENV var (e.g.
    ``WALLET_ADDRESS=...``), never welded into the command line itself --
    genuinely gray-area: real infrastructure, but overridable at runtime."""
    return any(_ENV_WALLET.search(c.get("evidence", "") if isinstance(c, dict) else "")
              for c in confirming)


def wallet_to_images(db) -> dict[str, set[str]]:
    """Map payout wallet -> the set of confirmed images that carry it.

    Feeds the shared-wallet promotion: two proven-bad publishers (isukim,
    donafro) each ran MULTIPLE images against one fixed Monero wallet. A
    sibling that shares an already-confirmed wallet is provably the same
    operation, regardless of whether ITS OWN command happens to look like a
    parameterized BYO tool or an ENV-default template.
    """
    mapping: dict[str, set[str]] = {}
    for r in db.conn.execute("SELECT image, evidence FROM image_findings WHERE status='confirmed'"):
        ev = json.loads(r["evidence"] or "{}")
        for w in ev.get("iocs", {}).get("wallets", []):
            mapping.setdefault(w, set()).add(r["image"])
    return mapping


def shares_confirmed_wallet(row, wallet_map: dict[str, set[str]]) -> bool:
    """True if this row's payout wallet also appears on ANOTHER confirmed image."""
    ev = json.loads(row["evidence"] or "{}")
    return any(len(wallet_map.get(w, set()) - {row["image"]}) > 0
              for w in ev.get("iocs", {}).get("wallets", []))


def confidence(row, confirming: list, *, wallet_map: dict[str, set[str]] | None = None) -> str:
    """high | review | byo. The ONLY thing that governs auto-submit-to-OSM
    (high only); everything else (review, byo) is held for manual review and
    must never be presented as submission-ready."""
    tier = row["tier"] or ""
    if "cryptojacking" in tier:
        # A wallet shared with another already-confirmed image is independent,
        # stronger evidence than the command-shape heuristics below: it proves
        # the same operator, even if this particular image's own command looks
        # like a parameterized "BYO tool" or ENV-default template.
        if wallet_map and shares_confirmed_wallet(row, wallet_map):
            return "high"
        if is_byo_tool(confirming):
            return "byo"
        # A hardcoded wallet in the command auto-mines to the attacker; a wallet
        # only in an ENV default (overridable) or a very high pull count is a
        # gray-area personal/template image that a human should review.
        if has_literal_command_wallet(confirming) and (row["pull_count"] or 0) <= 1_000_000:
            return "high"
        return "review"
    # intrinsic non-crypto Tier-A (reverse shell, C2, malware, rootkit, escape)
    if tier.startswith("A"):
        return "high"
    return "review"  # Tier-B corroborated


# ---- severity + plain-language behaviour ------------------------------------
_SEVERITY = {
    "reverse_shell": "critical", "c2": "critical", "malware_family": "critical",
    "rootkit": "critical", "container_escape": "critical",
    "cryptojacking": "high", "steal-and-send": "high", "obfuscation": "high",
    "malicious-dependency": "high", "persistent-dropper": "high", "escape+payload": "critical",
}
BEHAVIOR = {
    "cryptojacking": ("The image runs a cryptocurrency miner hardcoded to an attacker's "
        "pool and wallet, so running the container silently mines coins for the attacker "
        "on the victim's CPU. This is unauthorized resource theft."),
    "reverse_shell": ("The image opens a reverse shell, making any host that runs it dial "
        "back to an attacker-controlled server and hand over a command prompt."),
    "c2": ("The image carries command-and-control tooling that connects a running container "
        "to attacker infrastructure for remote control."),
    "malware_family": ("The image contains code matching a known malware or botnet family."),
    "obfuscation": ("The image decodes and executes a hidden, encoded payload at runtime."),
    "steal-and-send": ("The image reads credentials or cloud metadata and exfiltrates them "
        "to an attacker-controlled channel."),
    "malicious-dependency": ("The image installs a software package already catalogued as "
        "malware, so running it pulls in known malicious code."),
}


def tier_key(tier: str | None) -> str:
    return (tier or "").split(":", 1)[-1] or "malware"


def severity_level(row) -> str:
    return _SEVERITY.get(tier_key(row["tier"]), "high")


_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def severity_rank(row) -> int:
    """0-4 danger rank from the finding's severity level, worst first. Used to
    sort a submission batch most-dangerous-first, and by ``--min-severity``."""
    return _SEVERITY_RANK.get(severity_level(row), 0)
