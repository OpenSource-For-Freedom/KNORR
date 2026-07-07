"""Extract structured IOCs from confirming evidence (shared by hunt + submit).

Pulls the attacker's infrastructure out of the confirming lines so it is captured
on the finding at hunt time: mining pool, payout wallet, C2 host, source repo,
miner binary, and the coin. Also flags the benign-tool case where the pool is the
publisher's own domain (a personal miner, not cryptojacking).
"""

from __future__ import annotations

import re

_POOL = re.compile(
    r"(?:stratum\+(?:tcp|ssl)://|-o\s+|--url[=\s]+|--pool[=\s]+|POOL(?:_URL)?=)"
    r"(?:https?://)?([a-z0-9][a-z0-9.\-]*\.[a-z]{2,}(?::\d{2,5})?)", re.I)
_XMR = re.compile(r"\b[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")
_WALLET_FLAG = re.compile(
    r"(?:--?wallet|--?user|-u|WALLET=|POOL_USER=)[=\s]*([A-Za-z0-9]{40,})", re.I)
# A captured "pool" that is really a filename (curl -o get-pip.py, python.tar.xz)
# is not infrastructure; drop those.
_NOT_POOL = re.compile(
    r"\.(?:py|sh|xz|gz|tgz|bz2|zip|txt|json|asc|tar|conf|cfg|ya?ml|md|deb|rpm|whl)$", re.I)
_HOST = re.compile(r"https?://([a-z0-9][a-z0-9.\-]*\.[a-z]{2,})", re.I)
_IPHOST = re.compile(r"https?://(\d{1,3}(?:\.\d{1,3}){3})")
_REPO = re.compile(r"(github\.com/[\w.\-]+/[\w.\-]+)", re.I)
_MINER = re.compile(
    r"\b(xmrig|ariominer|ccminer|cpuminer|t-rex|nbminer|lolminer|xmr-stak|"
    r"kdevtmpfsi|minerd|nanominer|teamredminer|srbminer)\b", re.I)


def _as_texts(items: list) -> list[str]:
    """Accept a list of confirming dicts (use .evidence) or raw strings."""
    out: list[str] = []
    for it in items:
        if isinstance(it, dict):
            out.append(it.get("evidence", ""))
        elif isinstance(it, str):
            out.append(it)
    return out


def extract_iocs(items: list) -> dict:
    """Return {pools, wallets, c2, repos, miners, coin} from confirming dicts or
    raw config strings. Passing the full config (not just the confirming lines)
    captures a pool/wallet even when it sits in an ENV var that fired no rule."""
    text = "\n".join(_as_texts(items))
    pools = sorted({m.rstrip(".") for m in _POOL.findall(text)
                    if not _NOT_POOL.search(m.rstrip("."))})
    wallets = sorted(set(_XMR.findall(text)) | {
        w for w in _WALLET_FLAG.findall(text) if not w.lower().startswith("docker")})
    pool_hosts = {p.split(":")[0] for p in pools}
    c2 = sorted(h for h in (set(_HOST.findall(text)) | set(_IPHOST.findall(text)))
                if h not in pool_hosts and "github.com" not in h)
    repos = sorted(set(_REPO.findall(text)))
    miners = sorted({m.lower() for m in _MINER.findall(text)})
    coin = "Monero (XMR)" if (any("xmr" in p or "monero" in p for p in pools)
                              or any(w[0] in "48" for w in wallets)) else None
    return {"pools": pools, "wallets": wallets, "c2": c2, "repos": repos,
            "miners": miners, "coin": coin}


def pool_owned_by_publisher(iocs: dict, publisher: str | None) -> bool:
    """True if a mining pool host contains the publisher's name (a personal miner,
    e.g. publisher ``metal3d`` pooling to ``xmr.metal3d.org``). A strong benign-tool
    signal: the author mines to their own pool, not an anonymous attacker pool."""
    if not publisher or len(publisher) < 4:
        return False
    p = publisher.casefold()
    return any(p in host.casefold() for host in iocs.get("pools", []))
