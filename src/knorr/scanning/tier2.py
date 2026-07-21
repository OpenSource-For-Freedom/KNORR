"""Tier-2: pull the image's layers and STATICALLY scan the unpacked contents.

Daemonless (our own registry blob pulls + gzip/tar extraction; never a Docker
daemon, never ``docker run``). Confirms images whose malicious payload is a file
inside a layer rather than a string in the image config -- e.g. an ``xmrig``
whose pool + wallet live in a baked-in ``config.json``.

Bounded to protect the host and the pull budget: a per-layer byte cap, a total
byte cap per image, a per-file read cap, and a scanned-file count cap. Only
text-ish/small files are decoded and scanned; large binaries are hashed later
(Phase 2), never executed. Extraction is path-traversal-safe.

Optionally shells out to Trivy (if installed) for an SBOM used in the
malicious-package match; Trivy statically analyses, it does not run the image.
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
import tarfile
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from .config_scan import ConfigSignal, scan_texts

log = logging.getLogger(__name__)

# Bounds (untrusted content).
_MAX_LAYER_BYTES = 250_000_000
_MAX_TOTAL_BYTES = 600_000_000
_MAX_FILE_READ = 2_000_000
_MAX_FILES_SCANNED = 40_000
# Extensions / names worth decoding as text (miner configs, scripts, manifests).
_TEXT_SUFFIXES = {
    ".json", ".sh", ".bash", ".py", ".js", ".yml", ".yaml", ".conf", ".cfg",
    ".ini", ".txt", ".env", ".service", ".xml", ".toml", ".ps1", ".pl", ".rb",
}
_TEXT_NAMES = {"config", "entrypoint", "start", "run", "cmd", "dockerfile"}
# OS / distro / vendor paths whose text (docs, man pages, licenses, perl unicode
# tables, changelogs) trips keyword rules on prose -- e.g. a malware-family or C2
# name appearing in glib's copyright or a Perl debugger comment. Miner configs and
# dropper scripts never live here, so skipping them removes the false-positive
# LOCUS without losing real payloads (the zenidine/nizadam perl-unicode FP).
_IGNORE_LAYER_PATH = re.compile(
    # NOTE: "usr/local/X" is FHS-standard for locally-installed toolchains (a
    # bundled Node/Python/Go under /usr/local rather than /usr) -- the earlier
    # "usr/local/lib|usr/local/go"-only form missed usr/local/include, which let
    # OpenSSL's generated fipskey.h (a hex FIPS key constant, not shellcode) slip
    # through and false-positive on aquasec/codesec-remediation (score 50).
    r"(^|/)(usr/(share|lib|lib64|include|src)|usr/local/(share|lib|lib64|include|src|go)|"
    r"lib|lib64|var/lib/dpkg|site-packages|dist-packages|node_modules/[^/]+/(docs?|test)|"
    r"perl\d?|perl-base|unicore|man\d?)(/|$)"
    r"|/doc/|copyright$|changelog(\.\w+)?$|(^|/)LICENSE|\.pod$|\.1$|\.3$|\.md$"
    r"|(^|/)(README|INSTALL|NEWS|AUTHORS)(\.\w+)?$"
    r"|_test\.go$"
    # Security/APM vendor instrumentation configs legitimately NAME the malware
    # families and attack patterns they detect (a WAF ruleset listing "mirai",
    # "gafgyt", etc. as signatures to watch for) -- describing an attack is not
    # committing one (the same principle as a comment never confirming, applied
    # to a security tool's own detection-rule data). Observed on dd-trace's
    # appsec/recommended.json inside aquasec/codesec-remediation.
    r"|node_modules/(?:@datadog/|dd-trace/|@sentry/|newrelic/|elastic-apm-node/)"
    r"|appsec/recommended\.json$"
    # GNU autotools' generated boilerplate (config.sub/config.guess carry the
    # exact same FSF copyright/portability-triplet text across every autotools
    # project regardless of what it builds) and CMake's own auto-generated
    # build bookkeeping -- both proven to false-positive on c2-framework and
    # malware_family rules for images that build a real open-source miner
    # (ccminer, xmrig) from source (the cryptoandcoffee/pmietlicki cluster).
    r"|(^|/)config\.(?:sub|guess)$|CMakeFiles/|(^|/)CMakeCache\.txt$"
    # Stock package/OS files whose CANONICAL default content coincidentally
    # matches a signature (an example ~/.ssh/id_rsa path in ssh_config's own
    # comments, glibc/fakeroot's own wrapper scripts, the static IANA
    # protocol-number table) -- present verbatim in nearly every Debian-based
    # image regardless of what the image actually does.
    r"|(^|/)etc/ssh/sshd?_config$|(^|/)etc/(?:protocols|services)$"
    r"|(^|/)usr/bin/(?:catchsegv|fakeroot(?:-sysv|-tcp)?)$"
    # Compiler/codegen output: a protobuf-generated _pb2.py (or its grpc
    # sibling) is a mechanical data/enum dump, never hand-written payload
    # (the bowwow/poke-man false positive: a Pokemon-species enum file).
    r"|_pb2(?:_grpc)?\.py$"
    # XMRig's own shipped "*_example.*" template scripts use angle-bracket
    # PLACEHOLDER syntax (-u <wallet address>, -o <pool address>), never a
    # real value, and its donate.h/.cpp is the project's own well-documented
    # opt-in donation wallet, not a targeted attacker's payout -- both proven
    # to false-confirm cryptojacking on the cryptoandcoffee ccminer cluster
    # (the images had NO actual hardcoded wallet anywhere else in the layer).
    r"|_example\.\w+$|(^|/)donate\.(?:h|cpp)$"
    # Vendored third-party code: a "thirdparty/" (or "3rdparty/") directory is
    # explicitly not-this-project's-own code by the project's own naming
    # convention, the same "vendor code" principle as node_modules/usr-lib
    # above. sqlmap's own bundled Mozilla chardet library and a ported Unix
    # crypt(3) implementation both false-confirmed malware_family/obfuscation
    # rules this way (the marcomsousa/sqlmap false positive).
    r"|(^|/)(?:3rd|third)party/"
    # sqlmap's own shipped wordlist (a huge dictionary of arbitrary short
    # strings is all but guaranteed to coincidentally contain a malware-family
    # substring) and its default config TEMPLATE (documentation/example
    # values, not this image's own operational configuration).
    r"|(^|/)sqlmap/data/txt/|(^|/)sqlmap\.conf$",
    re.I,
)
# Trivy pkg Type -> OSM ecosystem, for the SBOM match.
_TRIVY_ECO = {
    "npm": "npm", "node-pkg": "npm", "yarn": "npm", "pnpm": "npm",
    "pip": "pypi", "python-pkg": "pypi", "poetry": "pypi",
    "gomod": "go", "gobinary": "go",
    "gemspec": "rubygems", "bundler": "rubygems",
    "cargo": "crates", "nuget": "nuget", "dotnet-core": "nuget",
    "jar": "maven", "pom": "maven", "gradle": "maven",
    "composer": "packagist",
}


@dataclass
class Tier2Result:
    signals: list[ConfigSignal] = field(default_factory=list)  # from layer files
    sbom_hits: list[dict] = field(default_factory=list)  # OSM pkgs found installed
    files_scanned: int = 0
    layers_pulled: int = 0
    trivy_ran: bool = False
    evidence: dict = field(default_factory=dict)


def _is_texty(name: str, size: int) -> bool:
    p = name.lower().rsplit("/", 1)[-1]
    if any(p.endswith(s) for s in _TEXT_SUFFIXES):
        return True
    if p in _TEXT_NAMES or p.startswith("config"):
        return True
    return size < 4096  # tiny extensionless files (scripts) are cheap to read


def _scan_layer_tar(tar_path: Path, budget: dict) -> list[ConfigSignal]:
    """Extract a gzip layer tar in-memory and scan text files. No disk writes.

    The whole extraction runs inside one try/except so a corrupt or adversarial
    layer (a truncated tar, a bad member mid-iteration) degrades to "no signals
    from this layer" rather than crashing the hunt -- important for unattended
    overnight runs pulling arbitrary untrusted images.
    """
    signals: list[ConfigSignal] = []
    try:
        with tarfile.open(tar_path, "r:*") as tf:
            for member in tf:
                if budget["files"] >= _MAX_FILES_SCANNED:
                    break
                if not member.isfile():
                    continue
                name = member.name.lstrip("./")
                if ".." in Path(name).parts:  # traversal guard (we only read, but be safe)
                    continue
                if _IGNORE_LAYER_PATH.search(name):  # OS/vendor docs -> prose false positives
                    continue
                if not _is_texty(name, member.size) or member.size > _MAX_FILE_READ:
                    continue
                budget["files"] += 1
                try:
                    fh = tf.extractfile(member)
                    if fh is None:
                        continue
                    text = fh.read().decode("utf-8", errors="ignore")
                except (OSError, tarfile.TarError):
                    continue
                for sig in scan_texts([text]):
                    # tag the evidence with the file it came from
                    signals.append(ConfigSignal(sig.category, sig.rule, f"{name}: {sig.evidence}"))
    except (tarfile.TarError, OSError) as exc:
        log.warning("cannot open/read layer tar: %s", exc)
    return signals


def pull_and_scan(client, repository: str, manifest: dict, *, workdir: Path | None = None) -> Tier2Result:
    """Pull each layer (bounded) and scan unpacked text files for signatures."""
    result = Tier2Result()
    layers = manifest.get("layers") or []
    tmp = Path(tempfile.mkdtemp(prefix="knorr-t2-", dir=str(workdir) if workdir else None))
    budget = {"files": 0}
    total = 0
    try:
        for layer in layers:
            digest = layer.get("digest")
            size = layer.get("size", 0)
            if not digest or size > _MAX_LAYER_BYTES or total + size > _MAX_TOTAL_BYTES:
                continue
            dest = tmp / f"{digest.replace(':', '_')}.tar.gz"
            if not client.download_blob(repository, digest, dest, max_bytes=_MAX_LAYER_BYTES):
                continue
            result.layers_pulled += 1
            total += size
            result.signals.extend(_scan_layer_tar(dest, budget))
            dest.unlink(missing_ok=True)  # drop the blob as soon as it is scanned
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    result.files_scanned = budget["files"]
    # dedup signals by (category, rule, evidence)
    seen: set[tuple[str, str, str]] = set()
    deduped: list[ConfigSignal] = []
    for s in result.signals:
        k = (s.category, s.rule, s.evidence)
        if k not in seen:
            seen.add(k)
            deduped.append(s)
    result.signals = deduped
    return result


def trivy_sbom(image_ref: str, *, username: str | None = None, token: str | None = None,
               timeout: int = 300) -> list[dict]:
    """Return installed packages via Trivy (daemonless remote pull). [] if absent.

    Each dict: {ecosystem, name, version}. Trivy statically analyses the image;
    it does not execute it. Auth is passed via env so Trivy uses our pull budget.
    """
    if shutil.which("trivy") is None:
        return []
    import os
    env = dict(os.environ)
    if username and token:
        env["TRIVY_USERNAME"], env["TRIVY_PASSWORD"] = username, token
    cmd = [
        "trivy", "image", "--quiet", "--format", "json", "--scanners", "vuln",
        "--list-all-pkgs", "--image-src", "remote", "--timeout", f"{timeout}s", image_ref,
    ]
    try:
        # encoding/errors explicit: Trivy emits UTF-8, but Python defaults to the
        # locale codec (cp1252 on Windows) which crashes on non-latin1 bytes.
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=timeout + 30, env=env)
        payload = json.loads(proc.stdout or "{}")
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        log.warning("trivy failed for %s: %s", image_ref, exc)
        return []
    pkgs: list[dict] = []
    for res in payload.get("Results") or []:
        eco = _TRIVY_ECO.get((res.get("Type") or "").lower())
        if not eco:
            continue
        for pkg in res.get("Packages") or []:
            name = pkg.get("Name")
            if name:
                pkgs.append({"ecosystem": eco, "name": name.casefold(),
                             "version": (pkg.get("Version") or "").strip()})
    return pkgs


def sbom_match(packages: list[dict], osm_packages: dict) -> list[dict]:
    """Installed packages that are OSM-listed malicious (exact version or all)."""
    hits: list[dict] = []
    for pkg in packages:
        versions = (osm_packages.get(pkg["ecosystem"]) or {}).get(pkg["name"])
        if versions and (pkg["version"] in versions or "*" in versions):
            hits.append(pkg)
    return hits
