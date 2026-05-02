# Security Review — `credential-process` and `otel-helper` binaries

This document captures a baseline security review of the two Go binaries this guidance ships to end-user endpoints. It is intended as a starting artifact for any organization adopting the solution — run the same tools against any future revision to regenerate this exact artifact set.

**Code scanned:** Go source tree under `source/go/`, HEAD `2f64a6f` of `main` at scan time.
**Scope:** the two Go binaries deployed to end-user endpoints (`credential-process` and `otel-helper`) and their transitive dependencies.
**Out of scope:** the `ccwb` Python CLI (deployed only to admin workstations), CloudFormation templates, Claude Code itself (maintained by Anthropic), AWS SDK internals (maintained by AWS).
**Scan date:** 2026-05-02.
**Tools used:** `gosec` 2.26.1, `govulncheck` (Homebrew-installed latest), `syft` (Homebrew-installed latest), Go toolchain 1.26.2.

---

## 1. What these binaries do (scope of responsibility)

### `credential-process`

**Purpose.** Implements AWS's [`credential_process` protocol](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html). When any AWS SDK caller needs credentials for a profile configured with `credential_process = <path-to-binary>`, the AWS SDK invokes this binary, captures its stdout as JSON, and uses those temporary credentials.

**What it does when called.**
1. Checks for cached STS session credentials (OS keyring or session file). If valid, outputs them to stdout and exits.
2. If no valid cache, opens a local TCP listener on `127.0.0.1:8400`, launches the user's browser to their IdP (Okta / Azure AD / Auth0 / Cognito User Pool), runs the OAuth2 authorization-code-with-PKCE flow.
3. Exchanges the resulting ID token for AWS credentials via `sts:AssumeRoleWithWebIdentity` (or `cognito-identity:GetCredentialsForIdentity` when federating through a Cognito Identity Pool).
4. Caches credentials locally (OS keyring where available, session-file fallback), writes the ID token to `~/.claude-code-session/<profile>-monitoring.json` (used by `otel-helper`), emits AWS credentials JSON to stdout.

**Data handled.** User's IdP ID token (JWT), AWS session credentials (temporary, ≤12h TTL), the user's own session-tag claims (as configured by the deploying organization — e.g. project, cost-center, zone, email, department). All locally scoped to one user on one machine.

**Permissions required.** Standard user. Writes to `~/.aws/`, `~/.claude-code-session/`, and the OS keyring (macOS Keychain / Windows Credential Manager / Linux Secret Service). Opens one localhost TCP port for the OAuth callback. Launches the default browser. No admin/root, no system services, no driver hooks.

**Blast radius if compromised.** Limited to the running user's IdP session and the AWS credentials assumable from their IdP-group membership. Cannot escalate to other users' data or other AWS accounts without a separate IdP + STS trust failure.

### `otel-helper`

**Purpose.** Reads the cached ID token that `credential-process` wrote, extracts user attributes, and emits them as HTTP headers that Claude Code attaches to its OpenTelemetry metric exports for per-user / per-project dashboards.

**What it does when called.**
1. Reads cached OTel headers from local file cache (happy path — avoids doing work).
2. If cache miss, reads the cached monitoring JWT from `~/.claude-code-session/<profile>-monitoring.json`.
3. Decodes the JWT locally (no signature verification — this binary is not a trust boundary; the JWT already traveled through the authenticated path).
4. Extracts fields (email, department, cost center, zone, etc.), formats them as `x-*` HTTP headers, prints JSON to stdout.

**Data handled.** A subset of the JWT claims used for OTel attribution. No AWS credentials, no write access to credentials files.

**Permissions required.** Standard user. Read-only access to cached JWT file. No network access.

**Blast radius if compromised.** Very limited — the binary can read a JWT the user already has. It cannot authenticate to anything, cannot modify AWS credentials, cannot reach network endpoints.

### Why these are separate binaries

Separation of concerns. `credential-process` is the auth critical path (must run to get AWS creds). `otel-helper` is the telemetry side-channel (runs only if monitoring is enabled). Splitting them means an incident in one doesn't automatically blast-radius the other, and monitoring is cleanly optional.

---

## 2. Binary provenance

**Source.** All code is in this repository. Current HEAD at scan time: `2f64a6f`.

**Build command.** Reproducible from source:

```bash
cd source/go && make all
```

Which runs, for each platform:

```bash
CGO_ENABLED=0 GOOS=<os> GOARCH=<arch> \
  go build -ldflags "-s -w -X github.com/bluedoors/ccwb-binaries/internal/version.Version=$(VERSION)" \
  -o bin/<binary>-<platform> ./cmd/<binary>/
```

`CGO_ENABLED=0` → statically linked, no libc dependency, no host-specific binary variations.
`-s -w` → strips debug symbols (smaller binaries; does NOT affect security posture).
`-X ...version.Version` → embeds version string for `--version` output.
PE version info embedded via `go-winres` `.syso` files committed at `source/go/cmd/*/rsrc_windows_amd64.syso` for Windows Defender AV compatibility.

**Go version at scan time.** `go 1.26.2`. Module declares `go 1.24` minimum.

**SHA-256 of each shipped binary** (commit `2f64a6f`):

```
c14f952093cbe3087ded08690389adb733b15e7cab730fdebcdf05dcccd68bee  credential-process-linux-arm64
a14f43c5cee18b0d85b1f0067f91b459938d243bbaf4d90b0b8d6b1e7f14de08  credential-process-linux-x64
4131fcd2872c3a59cec7f0f698104ec2b8670faaf11b9ac059a1ca14f71d75ed  credential-process-macos-arm64
a18b6a652c32d4f2aeca3f892ef053a7b4fb4965e684f99ea9d2d15d1ed2f2af  credential-process-macos-intel
9a72f389558f5efd43b98de8d835bc3630045b8ebbd646a6c6758079c197b41b  credential-process-windows.exe
0f4968f35dc54ceb035fd945bece077fc06cd71b0434b0fc09006f0a07be665a  otel-helper-linux-arm64
c100c0f1fdf1548f12f21627c5979a39d923651c88e8047b85a479fa5b9bd7e0  otel-helper-linux-x64
6a73cc46b904eab98996a3a48e8e877b929b9930864cf963e7c969bbfc8aeecc  otel-helper-macos-arm64
b971bdfecbd5774eb986f7b97e9fe7edbc09fc6a91572002773109ec8ff2e728  otel-helper-macos-intel
ddab3186f7dc5046c9cd5e9e69ee3ca06341f2523db4e4d11972442450f293db  otel-helper-windows.exe
```

Verify locally: `shasum -a 256 credential-process-macos-arm64`.

---

## 3. Software Bill of Materials (SBOM)

Full CycloneDX JSON SBOM for each of the 10 binaries under `security-review-artifacts/sbom/*.cdx.json`.

**Consolidated dependency list** (union across all 10 binaries):

| Module | Version | Purpose |
|---|---|---|
| `github.com/aws/aws-sdk-go-v2` | 1.41.4 | AWS SDK core |
| `github.com/aws/aws-sdk-go-v2/config` | 1.32.12 | SDK config loader |
| `github.com/aws/aws-sdk-go-v2/credentials` | 1.19.12 | Credential providers |
| `github.com/aws/aws-sdk-go-v2/feature/ec2/imds` | 1.18.20 | EC2 IMDS client (pulled transitively by `config`; credential-process uses its own OIDC+STS flow, not IMDS) |
| `github.com/aws/aws-sdk-go-v2/service/cognitoidentity` | 1.33.21 | Cognito GetCredentialsForIdentity |
| `github.com/aws/aws-sdk-go-v2/service/sts` | 1.41.9 | STS AssumeRoleWithWebIdentity |
| `github.com/aws/aws-sdk-go-v2/service/sso` | 1.30.13 | Pulled transitively by `config` (not called directly) |
| `github.com/aws/aws-sdk-go-v2/service/ssooidc` | 1.35.17 | Pulled transitively by `config` (not called directly) |
| `github.com/aws/smithy-go` | 1.24.2 | Smithy runtime (used by AWS SDK) |
| `github.com/99designs/keyring` | 1.2.2 | Cross-platform OS keyring abstraction |
| `github.com/danieljoos/wincred` | 1.1.2 | Windows Credential Manager binding |
| `github.com/godbus/dbus` | v0.0.0-20190726142602 | Linux Secret Service (libsecret) binding |
| `github.com/gsterjov/go-libsecret` | v0.0.0-20161001094733 | Linux Secret Service client |
| `github.com/dvsekhvalnov/jose2go` | 1.5.0 | JWE decrypt for file-keyring fallback (see §4) |
| `github.com/mtibben/percent` | 0.2.1 | URL percent-encoding helper |
| `github.com/pkg/browser` | v0.0.0-20240102092130 | Cross-platform browser launch |
| `golang.org/x/sys` | 0.3.0 | Standard syscalls (transitive) |
| `golang.org/x/term` | 0.3.0 | Terminal ops (transitive) |
| `gopkg.in/ini.v1` | 1.67.1 | INI parser for `~/.aws/config` |
| `stdlib` | go1.26.1 | Go standard library |

**`otel-helper` component footprint is 2 external dependencies per binary** (Go standard library and the main module itself — no AWS SDK, no keyring libraries, no HTTP server, no `pkg/browser`). That narrow surface is deliberate: `otel-helper` is a read-only JWT decoder and HTTP header formatter, so it doesn't need the full credential-path dependency tree. **`credential-process` has 24–26 external dependencies per binary** (AWS SDK, OS keyring bindings, browser launcher, INI parser — see the table above for the full list).

**No vendored copies** — all modules pulled from their canonical upstream Go module proxies at build time. `go.sum` (committed) pins each module's cryptographic hash; `go build` verifies on every build.

---

## 4. Dependency CVE scan — `govulncheck`

`govulncheck` is the official Go vulnerability scanner maintained by the Go team at Google ([golang/vuln on GitHub](https://github.com/golang/vuln), [go.dev/doc/security/vuln](https://go.dev/doc/security/vuln)). It reads the curated Go vulnerability database at [vuln.go.dev](https://vuln.go.dev) and flags only CVEs that affect **symbols the code actually reaches** (reducing false positives vs. naive dep-only scanners).

**Raw output:** `security-review-artifacts/govulncheck.txt` and `.json`.

**Findings: 2 vulnerabilities in 1 module.** Both in `github.com/dvsekhvalnov/jose2go@v1.5.0`. `govulncheck` does not assign numeric severity scores (a design choice by the Go security team — they publish vulnerability details and leave severity assessment to the consumer, since context usually matters more than a score). Full details at the `More info` link for each.

| ID | Type | Affected path | Fixed in |
|---|---|---|---|
| [GO-2025-4123](https://pkg.go.dev/vuln/GO-2025-4123) | DoS via crafted JWE with high compression ratio | `storage.ReadMonitoringTokenFromKeyring` → `keyring.fileKeyring.Get` → `jose2go.Decode` | `jose2go@v1.7.0` |
| [GO-2023-2409](https://pkg.go.dev/vuln/GO-2023-2409) | DoS when decrypting attacker-controlled input | Same path (read + write) | `jose2go@v1.5.1` |

**Risk assessment.** Both vulnerabilities require an attacker to feed crafted JWE-encrypted blobs into `jose2go.Decode`. In this codebase:

- The **only input** to `jose2go.Decode` is the `file-keyring` fallback blob stored at `~/.local/share/keyring/` (or equivalent).
- Only the logged-in user has write access to that path; files are created with 0600 permissions via Go's `os.OpenFile` flags.
- The "attacker" in the CVE threat model is therefore the same user attacking their own session — not a meaningful escalation. At worst, a local user can crash their own `credential-process`, requiring a fresh login.

**Platform-specific reachability.**

- **macOS:** Uses macOS Keychain via `github.com/99designs/go-keychain`. Bypasses `jose2go` entirely. Vulnerable path is **not reachable**.
- **Windows:** Uses Windows Credential Manager via `github.com/danieljoos/wincred`. Bypasses `jose2go` entirely. Vulnerable path is **not reachable**.
- **Linux (Secret Service available):** Uses libsecret / GNOME Keyring via `github.com/gsterjov/go-libsecret`. Bypasses `jose2go` entirely. Vulnerable path is **not reachable**.
- **Linux (no Secret Service):** Falls back to file-keyring. Vulnerable path **is reachable**, but only to the logged-in user attacking themselves as described above.

**Remediation.** A future binary release will bump `github.com/99designs/keyring` to a version that pulls `jose2go@v1.7.0` or later. Tracked as a dependency-maintenance item. No short-term action required for environments where OS keyrings are available (the typical case).

---

## 5. Static analysis — `gosec`

`gosec` is the widely-accepted OWASP-style SAST scanner for Go. It runs ~40 rules covering common security anti-patterns (unsafe crypto, subprocess injection, path traversal, hardcoded secrets, HTTP server misconfiguration, etc.).

**Raw output:** `security-review-artifacts/gosec.json` and `.txt`.

**Findings: 25 issues in 12 files.** (Scope scanned: 23 Go source files, 2,617 lines. The other 11 files triggered no findings.) Breakdown by rule:

| Rule ID | Severity / Confidence | Count | What it flags |
|---|---|---|---|
| G104 | LOW / HIGH | 12 | Unchecked error returns |
| G101 | HIGH / LOW | 4 | "Hardcoded credentials" (false positives — OAuth endpoint URLs) |
| G304 | MEDIUM / HIGH | 4 | File path from variable |
| G115 | HIGH / MEDIUM | 1 | Integer overflow int → int32 |
| G702 | HIGH / HIGH | 1 | Command injection via taint analysis |
| G204 | MEDIUM / HIGH | 1 | Subprocess launched with variable |
| G112 | MEDIUM / LOW | 1 | HTTP server without `ReadHeaderTimeout` (Slowloris-class) |
| G117 | MEDIUM / MEDIUM | 1 | Marshaled struct field matches secret pattern |

### Finding triage (annotated)

**G104 — unchecked errors (12 findings).** All in cleanup paths: `os.Setenv` restore after a temporary modification, `ln.Close()` after a listener is no longer needed, `os.Remove` for stale cache files. These are deliberate — cleanup failures shouldn't surface to the caller. Risk: none. A planned lint pass will tidy these to reduce gosec noise, not for security reasons.

**G101 — "hardcoded credentials" (4 findings).** Flagged on OAuth2 endpoint path literals (`/oauth2/authorize`, `/oauth2/token`) in `internal/provider/endpoints.go`. These are public IdP URL paths, not credentials. Confirmed by inspection — no actual secret in the code. Standard false positive for Go projects that interact with OAuth providers.

**G304 — file path from variable (4 findings).** All in `internal/otel/cache.go` and `internal/storage/*`. Paths are derived from a `profile` identifier validated upstream (`[A-Za-z0-9_-]+`, enforced at `ccwb init` time) joined with a hardcoded subdirectory under the user's HOME. Not attacker-controlled. Scope: single user's own files.

**G115 — integer overflow (1 finding).** `internal/federation/sts.go:53` converts `maxDuration int` to `int32` for the AWS SDK's `DurationSeconds` parameter. Maximum acceptable duration is 43,200 seconds (12 hours). Value is bounded at the Profile validator and again at STS policy. Not exploitable.

**G702 — command injection via taint analysis (1 finding).** `cmd/otel-helper/main.go:124` invokes `exec.Command(cpPath, "--profile", profile, "--get-monitoring-token")`. Both `cpPath` (derived from the binary's own install directory) and `profile` (validated alphanumeric identifier) are non-attacker-controlled. The `exec.Command` form passes arguments as a list — no shell interpolation, so injection isn't possible even if the args contained special characters. Risk: none.

**G204 — subprocess launched with variable.** Same call site as G702. Same analysis.

**G112 — Slowloris on HTTP server.** `internal/oidc/callback.go:50` creates an `http.Server` for the OAuth redirect URI without a `ReadHeaderTimeout`. The server is bound to `127.0.0.1:8400` — loopback-only, not reachable from the network. Slowloris would require a local attacker, at which point they already own the process. A planned hardening pass will add the timeout; it is not material for deployment.

**G117 — marshaled secret pattern.** `internal/storage/keyring.go:60` serializes a struct containing `SessionToken` to JSON for keyring storage. This is intentional — the whole purpose is to persist the AWS session tokens securely in the OS keyring. The storage itself is encrypted at rest by the OS (Keychain / Credential Manager / libsecret). The JSON is never written to disk in plaintext. Risk: none as designed.

### Summary

- **0 findings represent exploitable vulnerabilities in the intended deployment context.**
- **5 findings are false positives** (G101 × 4, G117 × 1 — flagging intentional design patterns).
- **13 findings are lint-level** (G104 unchecked errors × 12 + G115 bounded conversion × 1).
- **5 findings are mitigated by design** (G304 × 4 path-from-validated-input, G112 × 1 loopback-only).
- **2 findings are not exploitable** (G702, G204 — non-attacker-controlled subprocess invocation).

A planned remediation pass will address G104 and G112 to reduce noise in future scans, but neither is material for production rollout.

---

## 6. Transport & at-rest security posture

Summarized from the code, not machine-scanned:

| Channel | Protection |
|---|---|
| IdP OAuth flow | HTTPS to Okta / Azure AD / Auth0 / Cognito. PKCE S256 code challenge (prevents authorization-code interception on loopback). |
| OAuth redirect | Loopback only (`127.0.0.1:8400`), never reachable from LAN or internet. |
| STS / Cognito calls | HTTPS, SigV4-signed by the AWS SDK. |
| ID token in transit | Only between the user's browser and their IdP (HTTPS), and between this binary and the IdP's token endpoint (HTTPS). Never sent to anywhere else. |
| ID token at rest | OS keyring (primary). JWE-encrypted file-keyring fallback only where OS keyring is unavailable. |
| AWS credentials at rest | OS keyring (primary). File fallback (`~/.aws/credentials`) with 0600 permissions. |
| OTel telemetry | Sent to the deploying organization's own OTel collector (ALB + AWS ACM TLS). JWT attributes emitted as HTTP headers only; no raw JWT transmitted. |

**Local exposure.** The binaries do not transmit any user data anywhere other than the deploying organization's own IdP, AWS account, and OTel collector.

---

## 7. Review checklist

A suggested checklist for an enterprise security review adopting this guidance:

- [x] SAST scan performed → `gosec` 2.26.1, 25 findings, all triaged (§5)
- [x] Dependency CVE scan performed → `govulncheck`, 2 findings in 1 module, not reachable on OS-keyring-backed platforms (§4)
- [x] SBOM produced → CycloneDX JSON × 10 binaries (§3)
- [x] Binary provenance recorded → SHA-256 + commit SHA + build flags (§2)
- [x] Scope of responsibility documented → §1
- [x] Transport + at-rest security posture documented → §6
- [ ] Internal pipeline rebuild → If your organization's policy is to build third-party software through an internal pipeline (and ship from an internal artifact repository), the hashes here are a reference for byte-for-byte comparison against your rebuild. The Go build is deterministic for matching Go version + ldflags + `CGO_ENABLED=0`.
- [ ] AV / endpoint verification → Ad-hoc check recommended for the Windows binary. [VirusTotal](https://www.virustotal.com/) submission of `credential-process-windows.exe` is a quick smoke test.
- [ ] License audit → This project and all listed dependencies use permissive licenses (Apache-2.0 / MIT / BSD). A full `go-licenses` report can be generated on demand.

---

## 8. Re-running this review

All tooling is free, open-source, and reproducible on any developer workstation with Go installed.

```bash
brew install gosec govulncheck syft          # or install via `go install` for govulncheck/gosec
cd source/go
mkdir -p ../../security-review-artifacts/sbom
govulncheck -json ./... > ../../security-review-artifacts/govulncheck.json
govulncheck ./... > ../../security-review-artifacts/govulncheck.txt
gosec -fmt=json -out=../../security-review-artifacts/gosec.json ./...
for bin in prebuilt/v2.0.0/credential-process-* prebuilt/v2.0.0/otel-helper-*; do
  syft "$bin" -o cyclonedx-json="../../security-review-artifacts/sbom/$(basename $bin).cdx.json"
done
( cd prebuilt/v2.0.0 && shasum -a 256 credential-process-* otel-helper-* ) \
  > ../../security-review-artifacts/sha256sums.txt
```

Re-run at any time against a future commit to regenerate the same artifact set.

---

## Attachments

Available under `security-review-artifacts/`:

- `govulncheck.json` — full JSON output of dependency scan
- `govulncheck.txt` — human-readable summary
- `gosec.json` — full JSON output of SAST scan
- `gosec.txt` — human-readable log + findings
- `sbom/*.cdx.json` — 10 × CycloneDX-format SBOMs, one per prebuilt binary
- `sha256sums.txt` — SHA-256 hashes of all 10 prebuilt binaries
