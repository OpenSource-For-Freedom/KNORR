# Changelog

## 0.1.0

First capability-complete release: multi-registry hunting, a hardened
discovery pipeline, and a public long-running watch mode.

### Added

- **OSM cross-check in the confirm path** (`hunt.py`'s `_osm_cross_check`, both
  Tier-1 and Tier-2 confirm sites): every freshly-confirmed finding now gets a
  live lookup against OSM's own database. A VERIFIED report for the exact same
  image from another researcher is recorded as corroboration; a FALSE_POSITIVE
  verdict auto-downgrades the finding to held-for-review instead of silently
  staying confirmed. Fails open on any network/API error. Closes the gap that
  let `d0whc3r/kali-ssh` (see Fixed, below) reach OSM submission unchecked.
- GHCR discovery vocabulary widened from 9 to 26 terms (parity with Docker
  Hub's search list), and the GHCR round's Tier-1/Tier-2 budget in `knorr
  watch` raised to actually work through the larger candidate pool.
- **OSM submission CLI parity with `git_warden`** (`osm_submit.py`, local-only):
  `--min-severity`/`--owners` filters applied with severity-first ordering
  (new `severity_rank`, shared alongside `severity_level` in the public
  `scanning/confidence.py`); a pre-send **liveness recheck** that re-resolves
  the image manifest (or re-fetches the raw Dockerfile) right before POSTing,
  so a payload removed since our scan is never sent to fail OSM review;
  **corroborated infrastructure IOC reports** for mining-pool/C2 hosts seen
  across 2+ confirmed images (`report_type: domain`, its own local submit
  ledger, gated by `--no-domains`/`--min-corroboration`); and three read-only
  reviewer commands, `--queue` (what is ready to submit), `--reconcile` and
  `--audit` (what OSM's live state says about our past submissions, with
  duplicate-canonical-id detection), plus an interactive `--wizard`
  walkthrough. `OsmClient` (public, `feeds/osm.py`) gained `current_reports()`
  and `existing_resource()` to back the new reconcile/audit commands.
- **GitHub Container Registry (GHCR)** as a second hunted registry
  (`--registry ghcr`): daemonless OCI client profile, account-pivot discovery,
  and a GitHub-code-search image-reference discovery source (GHCR has no
  public keyword-search API, so this mines Dockerfiles/compose/k8s manifests
  for `ghcr.io/<owner>/<image>` references naming a malicious term).
- **`knorr watch`**: a public, first-class long-running hunt loop with
  Discord/webhook alerts on new confirmed findings. Budget-aware, rotates
  across registries, and is resilient to a single bad round.
- **Known-good-publisher allowlist**: legitimate vendors (the upstream
  `xmrig` project, `aquasec`, and others) can no longer auto-confirm; a match
  is held for manual review instead.
- **Shared-wallet auto-promotion**: a review/BYO-bucketed image whose payout
  wallet matches an already-confirmed image is promoted to high-confidence
  regardless of its own command shape (proven on the `isukim`/`donafro`
  cryptojacking fleets).
- **OSM submission ledger** (`osm_submit.py --ledger`): a methodology and
  precision-stats Markdown report for review/audit.
- Retry/backoff for transient registry errors (5xx, network), so a single
  flaky response no longer drops an image from a long-running hunt.
- CI (`ruff` + `pytest` on push/PR to `main`).
- Malicious Dockerfile findings now persist into the same shared registry the
  dashboard reads, instead of only ever being printed to a console and
  forgotten; `knorr dockerfiles` upserts every hit, keyed
  `github.com/<owner>/<repo>:<path>`.
- Dashboard: a registry column and per-finding outbound link (Docker Hub,
  GHCR, or the GitHub blob URL for a Dockerfile finding), a "tools flagged"
  KPI, a project hero-image background, and a registries-seen summary badge.

### Changed

- Dashboard default port moved from 8788 to 8789 to stop colliding with
  git_warden's dashboard when both run locally at once.

### Fixed

- **Docker Hub discovery starvation**: the publisher pivot (the highest-yield
  discovery source) sat past position 686 in a ~1,100-item candidate list and
  was never reached by a budget-constrained Tier-1 screen. Fixed by excluding
  already-known images from rediscovery and reordering the publisher pivot
  ahead of the much larger, lower-precision search set.
- **Search pagination**: `hub_search` sampled only page 1 (~25 results) of
  what is often 500-1000+ matches for a common term; now paginates.
- Several false-positive classes caught and fixed: OpenSSL's generated
  `fipskey.h` misread as a shellcode blob, a security vendor's own AppSec
  ruleset misread as a named malware family, an AWS devops image's empty
  credential-env declaration misread as a set secret, and the upstream
  `xmrig`/`xmrig-proxy` projects misread as cryptojacking distributions.
- Removed Quay.io support (searched, but its public miner surface was
  consistently legitimate BYO tooling; zero confirmations across a full run).
- **Discord alert / OSM submission mismatch**: `knorr watch` alerted on any
  confirmed finding, regardless of confidence bucket, so a review-bucket or
  BYO-tool finding (an ENV-default wallet, a parameterized miner) displayed
  identically to a genuinely submission-ready one. The confidence tiering used
  to gate OSM submission is now extracted into a public module
  (`scanning/confidence.py`) shared by both the private submission path and
  `knorr watch`'s alerting, so the two can never drift apart again; alerts now
  only fire on the same `high`-confidence bar OSM submission uses, and show
  the actual severity, confidence tier, and confirming proof line instead of a
  fixed crypto-shaped template.
- **Generic-boilerplate false positives, resolved at the root** (previously
  tracked as a known issue): `mirai-gafgyt`/`linux-cryptobot`/`c2-framework`/
  `preload-rootkit` were matching GNU/FSF copyright boilerplate (`config.sub`,
  `config.guess`), CMake's own build bookkeeping, README/INSTALL prose,
  protobuf-generated `_pb2.py` files, stock Debian/OS files (`ssh_config`,
  `/etc/protocols`, glibc's `catchsegv`/`fakeroot`), and vendored third-party
  code (a `thirdparty/` directory) rather than actual malware. Tier-2's
  ignore-path list (`scanning/tier2.py`) now excludes all of these.
  Additionally: `linux-cryptobot`'s bare `dero` term collided with the real
  Dero cryptocurrency that miners like xmrig legitimately support (tightened
  to require `deromoner`), and xmrig's own shipped example/template scripts
  (angle-bracket `<wallet address>` placeholder syntax) and donation-mechanism
  source (`donate.h`) were misread as a hardcoded attacker payout. Re-auditing
  the 21 confirmed images this affected: 14 kept confirmed with corrected
  (lower) scores, 7 were false positives with no confirming evidence left.
- **Metasploit/msfvenom no longer confirm alone.** `c2-framework` bundled them
  with genuinely near-exclusively-malicious frameworks (Cobalt Strike, Sliver,
  Havoc), but Metasploit is mainstream, legal, and ships by default in Kali
  Linux; a bare "apt-get install metasploit-framework" reads as a security
  researcher's own toolbox as much as malice. They now live in a separate
  dual-use `pentest-toolkit` signal that is scored but never confirms alone.
  Caught because `d0whc3r/kali-ssh` had already been submitted to OSM on this
  exact false signal (its "C2 host" evidence was gitlab.com/www.kali.org);
  that submission is rejected locally and needs manual follow-up on OSM, since
  its API has no retraction/update endpoint.
- **sqlmap's own bundled assets** (a wordlist, its default config template,
  and vendored third-party libraries under `thirdparty/`) were misread as
  malware-family/rootkit/C2/obfuscation signals on `marcomsousa/sqlmap`, a
  mainstream, legal SQL-injection testing tool.

## 0.0.1

Initial MVP: Docker Hub hunting (Tier-1 config screen, Tier-2 layer pull +
scan), the full-spectrum static signature library, the precision-first
confirmation gate, the Dockerfile-in-git scanner, the dashboard, and the local
OSM submission path.
