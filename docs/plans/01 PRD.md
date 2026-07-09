# KNÖRR
### Malicious Container Intelligence Engine
**Product Requirements Document**

| | |
|---|---|
| **Document** | Product Requirements Document (PRD) |
| **Project** | Knörr: Malicious Container & Image Intelligence Engine |
| **Repository** | `knorr` (private) |
| **Owner** | OpenSource-For-Freedom / Tim Gorrie |
| **Status** | Draft v0.1 (see implementation status below) |
| **Visibility** | Private repository, gated feed (later phase) |
| **Date** | July 6, 2026 |
| **Template** | Built on the [`git_warden`](../../../git_warden) architecture (malicious-repo engine) |

> **Implementation status (updated):** the name landed on **Knörr** (this PRD's
> naming discussion below is left as-written, historical). Docker Hub and GHCR
> hunting, the Dockerfile-in-git scanner, the dashboard, `knorr watch`, and the
> local OSM submission path are all built and live; Quay.io was evaluated and
> removed (see the [CHANGELOG](../../CHANGELOG.md)). For the current CLI surface,
> architecture diagram, and test/CI status, see the [README](../../README.md).
> This document is retained as the original point-in-time plan, not living
> documentation.

> **The Knörr is the Norse ocean-going cargo ship**, the deep-hulled vessel that
> hauled freight across the North Atlantic, the ancestor of every container ship
> afloat today. Its *vörðr* (Old Norse for "warden" / guardian spirit, the root
> of the word *warden* itself) watches the cargo. Knörr never sails an image; it
> reads what the cargo *is* and senses what it would *do* once unloaded.
>
> *Name is provisional and swappable. Norse alternatives on the table:*
> ***Naglfar*** *(the ship built of the dead, evocative of an image assembled
> from many poisoned layers), or* ***Vörðr*** *(lean fully into the "warden"
> etymology).*

---

## 1. Executive Summary

Knörr is a defensive threat-intelligence engine that **discovers, statically
analyzes, and catalogs malicious container images** across public registries —
launching on **Docker Hub**, expanding later to GHCR, Quay, ECR Public, and
GitLab. It also inspects the **container-build surface in source repositories**
(Dockerfiles, `docker-compose`, and related build files) where malicious images
are assembled before they are ever pushed.

Knörr ingests authoritative open-source threat intelligence — chiefly
**OpenSourceMalware (OSM)**, whose feed already carries a `container` report type
— correlates it to images and publishers on each registry, runs established
container-analysis tooling against high-confidence candidates, and surfaces
validated findings to a human reviewer before anything is treated as confirmed.

Knörr is the **container sibling** to two existing OSM-facing engines built on
the same substrate: **`git_paca`** (malicious *packages*) and **`git_warden`**
(malicious *repositories*). All three feed novel, evidence-backed findings back
into the OSM registry. Knörr closes the gap between them: a malicious npm/pypi
package (`git_paca`) baked into an image, delivered by a repo's Dockerfile
(`git_warden`), and shipped as a runnable image (**Knörr**) is one supply-chain
kill chain observed from three angles.

The guiding principle is inherited verbatim: **accuracy over volume.** Knörr
publishes a small number of high-confidence findings rather than a large number
of unverified ones. The system is built for intelligence and remediation, not
enforcement or offense.

---

## 2. Problem Statement

Public container registries are a soft, high-yield target. A single `docker pull`
executed in CI, on a developer laptop, or on a Kubernetes node runs attacker code
with the privileges of the workload — frequently as root, frequently with cloud
credentials and metadata endpoints in reach. The dominant abuse patterns are
well documented and still thriving:

- **Cryptojacking at scale.** Malicious images bundling XMRig / cpuminer /
  configured to a Monero pool have been pushed to Docker Hub in the millions of
  pulls (the `azurenql`, `docker111`, `zoolu2` campaigns; TeamTNT, Kinsing,
  WatchDog, Kiss-a-dog, Commando Cat, the *Graboid* self-spreading worm). The
  image *is* the delivery vehicle.
- **Typosquatting and impersonation of official images.** `a1pine` for `alpine`,
  `tensorf1ow` for `tensorflow`, `dockerofficial/*` namespaces trading on the
  trust of Verified/Official publishers.
- **Baked-in supply-chain malware.** An image whose layers install a
  known-malicious npm/pypi package, or curl-pipe a second stage from attacker
  infrastructure at build time, ships that malware to every consumer.
- **Backdoors and stealers in `ENTRYPOINT`/`CMD`.** Reverse shells, cloud
  metadata theft (`169.254.169.254`), planted SSH keys, `/etc/ld.so.preload`
  rootkits (e.g. `libprocesshider`) hidden inside otherwise-plausible base
  images.

Each registry is monitored in isolation, and the **layer** — the actual unit of
malicious payload — is invisible to most scrutiny. Because OCI layers are
content-addressed (`sha256:…`) and reused verbatim, one poisoned layer can be
laminated into hundreds of differently-named images across many publishers, yet
defenders have no unified, cross-image view linking an image to its **lineage**
(shared layers, shared base), its **publisher**, and the real-world campaign it
serves.

> **Core problem:** Malicious container images — and the Dockerfiles that build
> them — proliferate across registries faster than fragmented, image-by-image
> detection can keep up, while the content-addressed layer that carries the
> payload goes uncorrelated.

---

## 3. Goals

1. **Unified container registry.** Build a single, accurate, cross-registry
   intelligence registry of malicious container images and the malicious
   Dockerfiles that produce them.
2. **Layer-aware detection.** Organize detection by image config
   (`ENTRYPOINT`/`CMD`/`ENV`/`LABEL`), unpacked-layer filesystem contents,
   embedded-binary hashes, SBOM package set, base-image lineage, shared malicious
   layer digests, and publisher reputation — not just image name.
3. **OSM contribution loop.** Feed novel, evidence-backed findings back to OSM as
   `report_type: container` (and `repository` for malicious Dockerfiles),
   complementing `git_paca` (packages) and `git_warden` (repos).
4. **Human-in-the-loop.** Require analyst validation before any candidate is
   promoted to confirmed ("gold") status.
5. **Defensible, static-first methodology.** Maintain a compliant, transparent,
   auditable process aligned to registry terms of service and to NIST SP 800-190
   (Container Security) / CIS Docker Benchmark guidance. **Never execute a
   target image** in the MVP.

---

## 4. Non-Goals

Explicitly out of scope, at least for the initial releases:

- **Replacing commercial/OSS scanners.** Knörr *orchestrates* Trivy, Grype/Syft,
  ClamAV, and YARA as inputs; it does not attempt to replace them.
- **Runtime detection / detonation at launch.** MVP is **static-only**: pull,
  unpack, read. Sandboxed detonation is a **Phase 2** capability (§8, §11.5), and
  the finding schema and confirmation gate are designed now so it drops in later
  without rework.
- **Real-time scanning at launch.** Runs are weekly and manually initiated until
  stability is proven.
- **Private registries / private images.** Only public images are in scope.
- **Automated enforcement.** No automated takedowns, registry reports, or DMCA
  actions; output is intelligence for human decision-making.
- **Kubernetes / Helm deployment-layer intel.** Deferred; the unit of analysis is
  the image and its build files, not the orchestration manifest.

---

## 5. Success Metrics

Knörr optimizes for **precision**. It is preferable to drop a correct candidate
than to publish a false positive.

| Metric | Target | Rationale |
|---|---|---|
| True-positive rate (published) | ~95% | Sustains registry credibility |
| False positives (published / gold) | ~0 | A single bad call damages reputation disproportionately |
| Source corroboration | ≥ 2 independent signals per confirmed image | Prevents single-source error propagation |
| Pull budget adherence | 100% of runs under registry rate limits | A blown budget stalls the whole hunt |
| Review latency | Weekly batch | Stability and accuracy prioritized over speed |

> **Stance:** Catch fifty images with confidence rather than five hundred with
> noise. Start on Docker Hub, build reputation, then scale to the other
> registries.

---

## 6. Dual-Use and Abuse Mitigation

A registry of malicious images is also a directory an attacker could use in
reverse — to find working malware to reuse or to identify collaborators. The
architecture treats this as a first-class risk (inherited from `git_warden`):

- **Private hosting.** The repository is private; findings are exposed only
  through a gated feed in a later phase.
- **Publish rules, not the raw registry.** Detection rules, YARA signatures, and
  methodology may be shared publicly; the consolidated list of live malicious
  images and their pullable digests is not.
- **No re-hosting of payloads.** Knörr stores *evidence* (digests, file paths,
  hashes, config excerpts, YARA hits) — never the extracted malicious binaries
  themselves. Unpacked layers are analyzed in scratch and force-removed on every
  exit path.
- **Human review channel.** A webhook delivers gold findings to a controlled
  channel for validation before broader distribution.
- **Auditability.** Access is authenticated and logged so queries can be reviewed
  (later phase).

---

## 7. Initial Scope

### 7.1 Entry Points (breadcrumbs → images)

The first iteration begins from **known indicators and known-bad publishers**,
not blind crawling of the whole registry. Seed categories:

- **OSM container indicators.** OSM's `container` report type — the images the
  community has already flagged — are validated directly (clone-free Tier-1, then
  Tier-2 pull-and-unpack) rather than trusted on the label alone.
- **OSM package indicators.** Known-malicious npm/pypi/etc. packages (the same
  intel `git_paca` curates) become SBOM-match targets: an image that installs one
  ships known malware.
- **Cryptojacking campaign seeds.** A pinned seed list of miner families,
  Monero/pool IOCs, and historically-abused Docker Hub namespaces (TeamTNT,
  Kinsing, WatchDog, etc.).
- **Typosquat targets.** The set of Official / Verified image names to detect
  impersonations of.
- **Dockerfile intel from `git_warden`.** Repositories `git_warden` already
  surfaces whose container-build files (`FROM` a malicious base, `RUN curl … | sh`
  from attacker infra, `ADD` a known-bad binary) are themselves image-supply-chain
  findings.

From each seed, Knörr performs **recursive discovery**: other tags of the same
image, other images under the same publisher, and — the container-native
multiplier — **other images that share a confirmed-malicious layer digest**.

### 7.2 Registry Sequencing

**Docker Hub is the launch registry** (largest malicious surface, richest public
metadata API). GHCR, Quay, ECR Public, and the GitLab Container Registry are
deferred to Phase 2 once the core hunting loop and validation are stable.

### 7.3 What "container" means here

Two artifact classes are in scope:

1. **Published registry images** — `registry/namespace/repo:tag@sha256:digest`.
   The primary product.
2. **Container-build files in source repos** — `Dockerfile`, `Containerfile`,
   `docker-compose.yml`, and referenced build scripts. The pre-publish
   supply-chain surface; a malicious build file is a finding in its own right and
   a lead toward the image it produces.

---

## 8. Phased Plan and Timeline

The MVP is delivered over three weeks; later capabilities are sequenced into
Phase 2.

| Phase | Window | Deliverable |
|---|---|---|
| **MVP — Week 1** | Ingestion + registry client | Normalize OSM `container` + `package` intel and campaign seeds into a SQLite store with strict Pydantic validation. Daemonless Docker Hub / OCI registry client (manifest, config, tags, publisher metadata) with rate-limit budgeting. |
| **MVP — Week 2** | Tier-1 screen + Tier-2 static analysis | **Tier-1**: score image *without pulling layers* (config blob + Hub metadata + name). **Tier-2**: `skopeo`-based daemonless pull, unpack layers, run the container static-analysis stack (config scanner, layer/rootfs YARA + ClamAV, SBOM→OSM match, embedded-binary hashing), confirmation gate. |
| **MVP — Week 3** | Discovery multipliers + gold delivery | Layer-digest pivot, publisher pivot, typosquat detector, Dockerfile-in-git scanner. Wall of Shame + webhook gold delivery. Local OSM submission path (`report_type: container`). |
| **Phase 2** | Post-MVP | **Sandboxed detonation** (gVisor/Firecracker microVM, egress-captured); GHCR / Quay / ECR / GitLab expansion; central orchestration; gated web dashboard. |

---

## 9. Resources and Technology Stack

Mirrors `git_warden` so the two share tooling, CI, and operator muscle memory.

| Concern | Choice | Notes |
|---|---|---|
| Runtime | GitHub Actions | `workflow_dispatch` only at MVP; runner hardened first (egress audit) |
| Language | Python 3.12+ (private scripts) | No off-the-shelf framework for the core hunting logic |
| Storage | SQLite | Version-controlled; no external DB in Phase 1 |
| Registry I/O | `skopeo` (daemonless) + OCI Distribution API over `requests` | **No Docker daemon** — inspecting/copying without a daemon keeps us far from execution |
| Layer unpack | `skopeo copy` → `oci-layout` → manual `tar` extract (whiteout-aware, bomb-bounded) | Never `docker load`; never `docker run` |
| Static analysis | Trivy, Grype/Syft (SBOM), ClamAV, YARA | Orchestrated, not reinvented (see §11) |
| Validation | Pydantic | Schema enforcement / normalization across sources |
| Transformation | pandas | Shaping + dedup (by digest and by layer set) |
| Logging | Python logging + JSON/CSV artifacts | Per-run summaries for audit |
| Gold output | Parquet → webhook | Confirmed findings only |

---

## 10. Ingestion Sources

Week-one ingestion pulls from independent intelligence sources and correlates
them. These are the breadcrumbs that connect a container to a campaign, which
Knörr maps back to registry images and publishers.

- **OpenSourceMalware (OSM)** — community-verified malicious intelligence via
  `GET /query-latest`. Knörr consumes the **`container`** ecosystem/report type
  (which `git_warden` deliberately skips) plus **`package`** records for SBOM
  matching. Private API, Bearer auth. *This is the primary source.*
- **git_warden hand-off** — malicious repositories whose Dockerfiles/compose files
  are container-build findings (shared SQLite view or artifact exchange).
- **Cryptomining / botnet IOC feeds** — Monero pool domains (`*.supportxmr.com`,
  `pool.hashvault.pro`, `xmr.pool.minergate.com`, `stratum+tcp://…`), known miner
  binary hashes, and abused-namespace lists (curated seed file, refreshed from
  public campaign write-ups).
- **MalwareBazaar / abuse.ch** — file-hash corroboration for embedded binaries.
- **Google News / OSINT RSS + CISA advisories** — campaign context and newly
  named malicious images/publishers (reuses `git_warden`'s feed adapters).

> To expand per source: endpoint, auth method, response schema, and
> parse/normalization strategy (carried over from the `git_warden` feed contract).

---

## 11. Detection Architecture

This is the heart of Knörr and where it diverges most from `git_warden`. The
two-tier structure is preserved — **cheap screen first, expensive analysis only
for survivors** — but the units change from "repo files" to "image config +
layers."

### 11.1 Tier-1 Screen — *no layer pull*

The container equivalent of `git_warden`'s README triage. Knörr fetches only the
**manifest** and the small **image config blob** (which holds `ENTRYPOINT`,
`CMD`, `ENV`, `LABEL`, `USER`, exposed ports, and the build `history`) plus Docker
Hub metadata (description, `pull_count`, `star_count`, `last_updated`,
`is_official`/`is_verified`, publisher). **No layer blobs are downloaded.** This
is cheap and high-signal. Tier-1 scores:

- **Config signatures**: mining-pool URLs / `stratum+tcp://`, miner binary names
  in `CMD`/`ENTRYPOINT` (`xmrig`, `ccminer`, `t-rex`, `xmr-stak`), reverse-shell
  one-liners, `curl … | sh` / `wget … | bash` from attacker infra, `base64 -d | sh`,
  references to `169.254.169.254`, embedded wallet addresses (Monero `4…`/`8…`
  base58), suspicious `ENV` secrets.
- **History signatures**: build steps that `RUN curl`-pipe a stage or add a
  binary from a non-reputable host.
- **Name / lineage**: typosquat distance to an Official/Verified image; publisher
  reputation from prior findings.

Survivors are promoted to Tier-2; intel-driven candidates (OSM-flagged, known-bad
publisher, shared malicious layer) reach Tier-2 on their discovery signal, not
their name — exactly as `git_warden` promotes IOC/owner hits.

### 11.2 Tier-2 Static Analysis — *pull, unpack, read (never run)*

Daemonless `skopeo copy` into an `oci-layout`, then whiteout-aware `tar` extract
of each layer into a bounded scratch rootfs. Analysis runs over the assembled
filesystem and the per-layer diffs:

- **Config/entrypoint scanner** (deep version of Tier-1 over the fully-resolved
  config).
- **Rootfs YARA + ClamAV** — miner families, Mirai/Gafgyt, meterpreter/Cobalt
  Strike stagers, `libprocesshider`-style rootkits, planted `authorized_keys`,
  crontab persistence.
- **Embedded-binary hashing** — SHA-256 every ELF/PE in the layers; match against
  OSM hashes + MalwareBazaar.
- **SBOM → OSM match** — Syft/Trivy SBOM of installed packages; flag any package
  **at a version** catalogued malicious by OSM/`git_paca`. *(Direct reuse of
  existing OSM intel — a container that installs known malware is confirmable.)*
- **Layer fingerprinting** — record every layer `sha256` for the lineage pivot
  (§11.4) and cross-image dedup.

### 11.3 Confirmation Gate (precision-first)

Same philosophy as `git_warden`: everything is **detected and scored** (retained
in run artifacts), but **confirmation** requires a near-zero-legit-base-rate
signature. Structured for the Phase-2 detonation stage to slot in as an
additional confirming source.

- **Tier-A — confirm alone** (intrinsically malicious): a mining pool + wallet in
  `ENTRYPOINT`/`CMD`; a known-miner or known-malware **binary hash** in a layer; a
  reverse shell in config; an **OSM-listed package at its compromised version** in
  the SBOM; a YARA match from a malware-family ruleset; a build step that
  fetch-and-runs from confirmed attacker infra.
- **Tier-B — corroborated** (benign alone, malicious together): credential-file
  access **plus** an exfil channel in the same layer; a typosquat name **plus** a
  suspicious config; a shared-malicious base layer **plus** any Tier-B signal.
- **Dual-use, never alone**: `nmap`/`curl` present, base64 in a config, a debug
  tool in the image — scored for ranking, never confirming.

### 11.4 Discovery Multipliers (the container-native pivots)

- **Layer-digest pivot** — the analog of `git_warden`'s reusable code-signature
  search, and *stronger*, because layers are content-addressed. A confirmed
  image's distinctive malicious layer `sha256` is a pivot key to find sibling
  images that laminated the exact same layer (via same-publisher enumeration,
  OSM shared-digest intel, and crawl).
- **Base-image lineage** — images whose **bottom** layers match a
  confirmed-malicious base inherit its poison.
- **Publisher pivot** — enumerate every repo/tag under a publisher we *proved*
  malicious (never under an impersonation *target*).
- **Package pivot** — Docker Hub search + SBOM crawl for images installing an
  OSM-flagged package.
- **Typosquat expansion** — generate and check impersonations of Official/Verified
  names.

### 11.5 Phase 2 — Sandboxed Detonation (architected now, built later)

For images where static analysis is *suggestive but not confirming* (runtime
deobfuscation, delayed miner start, config pulled at boot), a Phase-2 stage will
detonate the image in an **isolated microVM** (gVisor or Firecracker) with **no
real egress** — DNS sinkholed, traffic captured — observing pool connections, C2
beacons, spawned miners, and dropped files. It becomes an additional Tier-A
confirming source. The MVP finding schema reserves fields for detonation evidence
so no migration is needed.

---

## 12. Validation Philosophy

The validator is intentionally the strictest component (carried from
`git_warden`):

- **Multi-source corroboration.** A confirmed image must carry either one Tier-A
  intrinsic signature *or* two independent Tier-B signals. An OSM label alone
  **seeds** a scan; it never confirms one.
- **Single-source quarantine.** Single-signal candidates are flagged for manual
  review, not auto-published.
- **Retain everything.** Run artifacts keep all candidates — including recognized
  false positives with the reason they were rejected — so back-end review can
  confirm good data was never silently dropped.
- **Digest-pinned findings.** Every finding is pinned to an immutable
  `sha256:digest`, not a mutable `:tag`, so a re-tag can never invalidate or
  silently mutate a confirmed finding.

---

## 13. Rate-Limit Budget

Layer pulls are the expensive, throttled operation, so the architecture spends
them last and never twice on the same digest.

| Source | Approximate limit | Notes |
|---|---|---|
| Docker Hub **pulls** (layer blobs) | 100 / 6 h anon, 200 / 6 h free-auth (per IP) | The binding constraint; Tier-2 only, high-scorers only |
| Docker Hub **manifest/config** fetches | Lighter than blob pulls | Powers Tier-1 for *all* candidates |
| Docker Hub **Hub API** (search, tags, publisher) | Separate, generous | Discovery + metadata |
| OSM | ~1,000–2,000 / day | Private API |
| MalwareBazaar / abuse.ch | Per published limits | Hash lookups only |

Budget discipline: **Tier-1 (manifest + config, no blob pull) screens everything;
Tier-2 blob pulls run only for promoted candidates.** Every pulled layer is
cached by digest so lineage siblings never re-pull a shared layer. On a weekly
cadence this stays comfortably under budget. Each source is tested in isolation
first to confirm live limits.

---

## 14. Output Contract

### 14.1 Run Artifacts (full transparency)

Every run emits structured artifacts capturing the complete picture: all
candidate images (by digest), recognized false positives with rejection reasons,
validation flags, per-step summaries, layer-fingerprint maps, and CSV exports —
for inspection, audit, and rule refinement.

### 14.2 Gold Delivery (confirmed only)

The review channel receives only validated gold: confirmed malicious images, the
reasoning behind each call, and indicators of compromise (layer digest, file
path, binary hash, config excerpt, YARA rule) in human-readable form. Transport
payload is a gold Parquet dataset.

### 14.3 OSM Contribution (local, write-side)

A local, gitignored submit path (mirroring `git_warden`'s `osm_submit.py`) reports
novel confirmed true positives to OSM as **`report_type: container`** — carrying
`resource_identifier` (`registry/namespace/repo@sha256:…`), `severity_level`,
plain-language `threat_description` + `payload_description`, campaign `tags`, and
`evidence_references` (the confirming digest/hash/path) so reviewers can verify.
Malicious Dockerfiles submit as `report_type: repository`. Claim-first,
at-most-once delivery; only intrinsic-evidence findings OSM does not already have
are eligible.

---

## 15. Relationship to the OSM Engine Family

Knörr is the third engine on a shared substrate, all feeding one OSM registry:

| Engine | Unit of analysis | Discovers | Confirms on |
|---|---|---|---|
| **`git_paca`** | Package | Malicious npm/pypi/… packages | Package static evidence |
| **`git_warden`** | Repository | Malicious GitHub repos | Repo static evidence |
| **Knörr** | **Container image** | **Malicious images + Dockerfiles** | **Config / layer / SBOM / binary-hash evidence** |

Shared, reused verbatim where possible: the Pydantic data contract, SQLite
run/artifact schema, feed adapters (Google/CISA/OSINT), the OSM client, the
IOC-extraction and learning-loop primitives, the precision-first confirmation
philosophy, the analyst review CLI, and the OSM submit path. **Knörr consumes the
outputs of the other two** (OSM package intel → SBOM match; `git_warden` repos →
Dockerfile targets) and **contributes back** the container dimension neither can
see.

---

## 16. Open Questions

1. Daemonless pull: `skopeo` binary dependency vs. a pure-`requests` OCI client —
   which is the more portable CI story on the hardened runner?
2. Layer cache: content-addressed local cache keyed by digest — retention policy
   and disk budget on the near-full system drive.
3. Docker Hub ToS: confirm crawling/search/pull volumes are within acceptable use
   for a research program; whether to proactively notify Docker.
4. SBOM authority: when Trivy and Syft disagree on an installed package version,
   which is canonical for the OSM match?
5. Multi-arch: an image index fans out to per-arch manifests — scan all arches or
   pin to `linux/amd64` at MVP?
6. Detonation safety envelope (Phase 2): microVM choice, egress sinkhole design,
   and the legal/compliance sign-off for running attacker code even in isolation.
7. Schema versioning and data-retention policy for container findings and pulled
   layer evidence.

---

*Built on the `git_warden` malicious-repository engine. Static analysis only in
the MVP: images are pulled and read, never executed. Accuracy over volume.*
