"""Host reputation for fetch/download gating.

``curl X | sh`` is a dropper when X is attacker infrastructure and a normal
install when X is reputable (nvm, nodesource, get.docker.com, googlesource).
So download/fetch signals confirm only against a SUSPICIOUS host: a raw IP, a
paste/transfer host, a Tor onion, or an ephemeral dynamic-DNS / throwaway-TLD
domain. Reputable and ordinary hosts never confirm on their own.
"""

from __future__ import annotations

import re

_URL_HOST = re.compile(r"https?://(?:[^/@\s]*@)?([A-Za-z0-9.\-]+)", re.I)
_IP = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_ONION = re.compile(r"\b[a-z2-7]{16,56}\.onion\b", re.I)

_PASTE_HOSTS = frozenset({
    "pastebin.com", "paste.ee", "ix.io", "0x0.st", "termbin.com", "transfer.sh",
    "file.io", "anonfiles.com", "controlc.com", "rentry.co", "oshi.at", "sprunge.us",
})
# Reputable install / source hosts: never a dropper on their own.
_REPUTABLE = (
    "github.com", "githubusercontent.com", "googlesource.com", "google.com",
    "nodesource.com", "npmjs.org", "npmjs.com", "pypi.org", "python.org",
    "docker.com", "docker.io", "claude.ai", "anthropic.com", "rustup.rs", "bun.sh",
    "nodejs.org", "golang.org", "go.dev", "debian.org", "ubuntu.com",
    "alpinelinux.org", "fedoraproject.org", "microsoft.com", "apache.org",
    "cloudflare.com", "jsdelivr.net", "unpkg.com", "gitlab.com", "bitbucket.org",
    "sourceforge.net", "kubernetes.io", "helm.sh", "hashicorp.com", "gnu.org",
    "kernel.org", "sh.rustup.rs", "deno.land", "get.docker.com", "packages.microsoft.com",
)
# Throwaway TLDs + dynamic-DNS providers that legitimate software rarely fetches from.
_EPHEMERAL_TLD = re.compile(r"\.(?:tk|top|xyz|gq|ml|cf|ga|pw|cc|club|work|surf|rest)$", re.I)
_DYNDNS = re.compile(
    r"\b[\w.\-]+\.(?:duckdns\.org|ngrok\.io|serveo\.net|hopto\.org|no-ip\.\w+|"
    r"myftp\.\w+|zapto\.org|portmap\.io|dynu\.\w+)\b", re.I)


def _reputable(host: str) -> bool:
    h = host.lower().rstrip(".")
    return any(h == r or h.endswith("." + r) for r in _REPUTABLE)


def is_suspicious_host(host: str) -> bool:
    h = host.lower().rstrip(".")
    if _IP.match(h) or h in _PASTE_HOSTS:
        return True
    if _reputable(h):
        return False
    return bool(_EPHEMERAL_TLD.search(h) or _DYNDNS.search(h))


def has_suspicious_fetch(text: str) -> bool:
    """True if any URL / IP / onion in ``text`` points at attacker-like infra."""
    if _ONION.search(text or ""):
        return True
    return any(is_suspicious_host(h) for h in _URL_HOST.findall(text or ""))
