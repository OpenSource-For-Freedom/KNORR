"""Precision-first confirmation gate (PRD section 11.3).

Every threat facet is detected and scored in ``config_scan``; this decides what
may be *confirmed* malicious. Tier-A signatures confirm alone (near-zero
legitimate base rate). Tier-B needs corroboration (each half is benign alone: a
credential read, a project's own webhook). Dual-use idioms (nmap, --privileged,
LD_PRELOAD, a lone miner binary) are scored for ranking but never confirm.
"""

from __future__ import annotations

from .config_scan import ConfigSignal
from .hosts import has_suspicious_fetch

# --- Tier-A: any one of these confirms alone (intrinsic malice) --------------
_CONFIRM_ALONE = frozenset({
    # reverse shell / C2 handler
    "bash-tcp", "nc-exec", "mkfifo-shell", "python-revshell", "perl-revshell",
    "php-revshell", "ruby-revshell", "powershell-revshell", "socat-shell",
    "c2-framework",
    # decode-and-run loaders (obfuscated second stage). fetch-decode-exec is
    # host-gated below (googlesource serves base64 legitimately); these others
    # are malware-specific enough to confirm alone.
    "python-exec-decode", "eval-atob",
    "hex-escape-exec", "xxd-revert", "shellcode-blob",
    # rootkit (named preload rootkit libs). NB: a bare write to /etc/ld.so.preload
    # is dual-use (jemalloc, profilers set it legitimately), so "ldso-preload" is
    # a scored persistence signal that needs corroboration, not confirm-alone.
    "preload-rootkit",
    # named malware / botnet families
    "mirai-gafgyt", "linux-cryptobot",
    # intrinsic container-escape primitives
    "cgroup-release-agent", "nsenter-host",
})

# cryptojacking = a miner PLUS a hardcoded payout target (auto-mines to an
# attacker on run). A lone miner binary is a legitimate tool and never confirms.
_MINER = frozenset({"miner-binary", "miner-executable"})
_MINER_PAYOUT = frozenset({"monero-wallet", "miner-wallet-flag", "kill-competitors"})

# --- Tier-B: steal-and-send and other corroborated pairs --------------------
_CRED = frozenset({
    "cloud-metadata", "aws-creds", "gcp-creds", "azure-creds", "ssh-keys",
    "k8s-token", "env-dump", "shadow-read", "git-creds",
})
_EXFIL = frozenset({
    "discord-webhook", "telegram-bot", "slack-webhook", "generic-webhook",
    "curl-post-data", "paste-exfil", "dns-exfil",
})
_PERSIST = frozenset({
    "cron-inject", "systemd-drop", "rc-local", "profile-inject", "ssh-authkeys",
})
_DROPPER = frozenset({"curl-pipe-shell", "raw-ip-fetch", "tor-onion-fetch", "raw-paste-fetch"})
_ESCAPE_DUAL = frozenset({"host-mount", "privileged", "cap-add-admin", "chroot-host", "proc-root"})


# Fetch/download rules that only count against an attacker host. raw-ip-fetch
# and tor-onion-fetch are intrinsically suspicious (raw IP / onion) so they
# always count; the rest are host-gated so `curl get.docker.com | sh` is ignored.
_HOST_GATED = frozenset({"curl-pipe-shell", "raw-paste-fetch", "fetch-decode-exec"})
_ALWAYS_SUSPICIOUS = frozenset({"raw-ip-fetch", "tor-onion-fetch"})


def confirm(
    signals: list[ConfigSignal], *, sbom_hits: list[dict] | None = None
) -> tuple[bool, str | None, list[ConfigSignal]]:
    """Return (confirmed, tier_label, confirming_signals)."""
    rules = {s.rule for s in signals}

    def keep(rule_set) -> list[ConfigSignal]:
        return [s for s in signals if s.rule in rule_set]

    # Which download/fetch signals actually target attacker infra. A host-gated
    # rule counts only if some occurrence points at a suspicious host; the
    # intrinsically-suspicious ones (raw IP, onion) always count.
    active_dl = set(_ALWAYS_SUSPICIOUS & rules)
    for rule in _HOST_GATED & rules:
        if any(has_suspicious_fetch(s.evidence) for s in signals if s.rule == rule):
            active_dl.add(rule)

    # --- Tier-A --------------------------------------------------------------
    if (_MINER & rules) and (_MINER_PAYOUT & rules):
        return True, "A:cryptojacking", keep(_MINER | _MINER_PAYOUT)
    if "fetch-decode-exec" in active_dl:  # network-fetched obfuscated dropper
        return True, "A:obfuscation", keep({"fetch-decode-exec"})
    if "curl-pipe-shell" in active_dl:  # curl <attacker-host> | sh (host-gated)
        return True, "A:dropper", keep(active_dl)
    alone = _CONFIRM_ALONE & rules
    if alone:
        cat = next(s.category for s in signals if s.rule in alone)
        return True, f"A:{cat}", keep(alone)
    if sbom_hits:
        return True, "A:malicious-dependency", []

    # --- Tier-B (corroborated) ----------------------------------------------
    if (_CRED & rules) and (_EXFIL & rules):
        return True, "B:steal-and-send", keep(_CRED | _EXFIL)
    if (_PERSIST & rules) and active_dl:
        return True, "B:persistent-dropper", keep(_PERSIST | active_dl)
    if (_ESCAPE_DUAL & rules) and (active_dl or (_CRED | _MINER) & rules):
        return True, "B:escape+payload", keep(_ESCAPE_DUAL | active_dl | _CRED | _MINER)

    return False, None, []
