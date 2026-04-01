# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Enterprise deployment tool for Claude Code with Amazon Bedrock. Provides OIDC-based federation (Okta, Azure AD, Auth0, Cognito User Pools) with AWS IAM to issue temporary credentials for Bedrock access. Two federation modes: Direct IAM (STS AssumeRoleWithWebIdentity, 12h sessions) and Cognito Identity Pool (8h sessions).

The system has three distinct audiences:
1. **IT Admins** use the `ccwb` CLI to deploy infrastructure, build packages, and distribute them
2. **End Users** receive pre-built binaries (credential-process + otel-helper) that handle authentication transparently via AWS CLI's credential_process protocol
3. **Claude Code** uses the temporary AWS credentials to call Amazon Bedrock

## Build & Development Commands

All commands run from `source/` unless noted otherwise.

```bash
# Install dependencies
cd source && poetry install

# Run all tests
cd source && poetry run pytest tests/ -v

# Run a single test file
cd source && poetry run pytest tests/test_models.py -v

# Run a single test by name
cd source && poetry run pytest tests/test_models.py::TestClassName::test_name -v

# Smoke tests (fast — catches import/syntax/instantiation errors)
cd source && poetry run pytest tests/test_smoke.py -q

# Lint and format
cd source && poetry run ruff check .
cd source && poetry run ruff format .

# Type check
cd source && poetry run mypy claude_code_with_bedrock/

# Validate CloudFormation templates
cfn-lint deployment/infrastructure/*.yaml

# Pre-commit (yaml lint, cfn-lint, ruff lint+format, smoke tests)
pre-commit run --all-files

# Go binaries — build all 10 (5 platforms × 2 binaries)
cd source/go && make all

# Go binaries — run unit tests (27 tests)
cd source/go && go test ./... -v
```

## Architecture

### Four Packages in `source/`

**`claude_code_with_bedrock/`** — The `ccwb` CLI (Cleo framework). Used by IT admins.
- `cli/commands/` — All CLI commands. Each is a Cleo `Command` subclass.
- `cli/utils/aws.py` — Boto3 helpers: region detection, Bedrock access checks, VPC/subnet listing
- `cli/utils/cloudformation.py` — `CloudFormationManager` class for stack CRUD with event streaming
- `cli/utils/cf_exceptions.py` — Custom exception hierarchy for CloudFormation errors
- `cli/utils/validators.py` — Input validators (domains, regions, stack names, client IDs)
- `cli/utils/display.py` — Rich table/text display for configuration info
- `cli/utils/progress.py` — Wizard progress save/resume (expires after 24h)
- `config.py` — `Profile` dataclass (~90 fields) and `Config` class. Profiles stored at `~/.ccwb/profiles/{name}.json`. Auto-migrates legacy format from `source/.ccwb-config/`.
- `models.py` — **Single source of truth** for Claude models, cross-region inference profiles, region mappings, quota policy models (`QuotaPolicy`, `UserQuotaUsage`, `PolicyType`, `EnforcementMode`)
- `validators.py` — `ProfileValidator` class with comprehensive profile validation
- `migration.py` — Auto-migration from v1.0 (single file) to v2.0 (profile-per-file) config format
- `quota_policies.py` — `QuotaPolicyManager` for DynamoDB CRUD on quota policies
- `utils/url_validation.py` — `detect_provider_type_secure()` using urlparse to prevent injection

**`go/`** — Go module for native cross-platform binaries (replaces PyInstaller/Nuitka).
- `cmd/credential-process/main.go` — Full OIDC auth + STS/Cognito federation + caching
- `cmd/otel-helper/main.go` — JWT decode + user attribute extraction for OTel
- `internal/config/` — Config.json loading, profile auto-detect, legacy field mapping
- `internal/provider/` — Domain-based provider detection (mirrors 6 Python files) + OIDC endpoint configs
- `internal/jwt/` — Base64url JWT decode without signature verification
- `internal/otel/` — User attribute extraction, HTTP header mapping, atomic file cache
- `internal/oidc/` — PKCE generation, full auth code flow, localhost callback server, token exchange
- `internal/federation/` — STS AssumeRoleWithWebIdentity (12h) + Cognito GetId/GetCredentialsForIdentity (8h)
- `internal/storage/` — Session file (INI), OS keyring (with Windows 4-entry split), monitoring token
- `internal/portlock/` — TCP port 8400 bind-based locking
- `internal/quota/` — HTTP quota check with JWT bearer auth
- `internal/browser/` — Cross-platform browser launch
- `internal/version/` — Version via `-ldflags`
- `prebuilt/v2.0.0/` — Pre-built binaries for all 5 platforms + generic install scripts
- `scripts/credential-process.ps1` — PowerShell alternative (zero AV risk)
- `Makefile` — Cross-compile all 10 binaries: `make all`

**`credential_provider/`** — Legacy Python standalone binary (being replaced by Go).
- `MultiProviderAuth` class orchestrates the full auth flow
- `PROVIDER_CONFIGS` dict defines OAuth2 endpoints per provider (Okta, Auth0, Azure, Cognito)
- **Auth flow**: Check cache → acquire port lock (localhost:8400) → PKCE OAuth2 browser flow → exchange code for tokens → optional quota check → exchange ID token for AWS credentials (STS or Cognito) → save to keyring/session → output JSON to stdout
- **Credential storage**: Two modes — OS keyring (macOS Keychain / Windows Credential Manager / Linux Secret Service) or session file (`~/.aws/credentials`). Windows keyring splits across 4 entries due to 2560-byte limit.
- **Port-based locking**: Prevents concurrent OIDC flows. Waits up to 60s for another process.
- **Monitoring token**: Saves ID token separately for otel-helper user attribution

**`otel_helper/`** — Legacy Python OTel helper (being replaced by Go).
- Extracts user attributes from JWT tokens for OpenTelemetry
- Two-layer caching: file cache first, falls back to credential-process subprocess
- Extracts: email, hashed user ID (UUID format), username, org, department, team, cost center, manager, location, role

### CloudFormation Templates (`deployment/infrastructure/`)

19 templates, all parameterized with `${AWS::Partition}` for Commercial + GovCloud.

**Authentication (deployed by `ccwb deploy`):**
- `bedrock-auth-{okta,auth0,azure,cognito-pool}.yaml` — IAM OIDC Provider + optional Cognito Identity Pool. Dual mode: `FederationType` parameter selects direct IAM or Cognito federation.
- `cognito-identity-pool.yaml` — Standalone Cognito Identity Pool with principal tag mapping
- `cognito-user-pool-setup.yaml` — Full Cognito User Pool with two app clients (CLI native + web distribution), Lambda custom resources for external IdP federation

**Monitoring (deployed by `ccwb deploy` when monitoring enabled):**
- `networking.yaml` — VPC (10.0.0.0/16) with 2 public subnets
- `otel-collector.yaml` — ECS Fargate (512 CPU/1024 MB) running OTel collector. Receives OTLP on ports 4317/4318. Extracts user attributes from HTTP headers into CloudWatch EMF metrics.
- `claude-code-dashboard.yaml` — DynamoDB metrics table (4 GSIs), 15 Lambda custom widgets, CloudWatch dashboard
- `metrics-aggregation.yaml` — EventBridge rule (5-min) + Lambda aggregator
- `logs-insights-queries.yaml` — 17 pre-built CloudWatch Logs Insights queries
- `analytics-pipeline.yaml` — CloudWatch Logs → Kinesis Firehose → Lambda transform → Parquet on S3 → Glue catalog → Athena workgroup with 10 named queries

**Distribution (deployed by `ccwb deploy distribution`):**
- `distribution.yaml` / `presigned-s3-distribution.yaml` — S3 bucket + IAM user for presigned URLs
- `landing-page-distribution.yaml` — S3 + ALB with OIDC auth + Lambda landing page

**Other:**
- `codebuild-windows.yaml` — CodeBuild projects for binary builds (legacy, replaced by Go cross-compilation)
- `quota-monitoring.yaml` — 2 DynamoDB tables + HTTP API Gateway with JWT authorizer + Lambda quota check
- `cognito-custom-domain-cert.yaml` — ACM certificate (must be us-east-1) for Cognito custom domain
- `s3bucket.yaml` — CFN artifacts bucket

### CLI Command Flow

```
ccwb init          → Interactive wizard, saves profile to ~/.ccwb/profiles/{name}.json
ccwb deploy        → Deploys CF stacks: auth → networking → otel → dashboard → analytics → quota
                     Saves otel_collector_endpoint to profile for offline packaging
ccwb deploy distribution → Deploys distribution stack (presigned-s3 or landing-page)
ccwb package       → Three build modes:
                     --prebuilt (default): Uses pre-built Go binaries from source/go/prebuilt/
                     --go: Cross-compiles Go binaries locally (requires Go installed)
                     (legacy): PyInstaller/Nuitka/Docker builds
                     All modes output: dist/{profile}/{timestamp}/ with binaries + config.json + installers
ccwb package-cb    → Trigger CodeBuild builds (legacy, not needed with Go)
ccwb builds        → List/download CodeBuild build artifacts
ccwb distribute    → Creates ZIP archives from dist/, uploads to S3, generates presigned URLs
ccwb status        → Shows deployment status, stack states, endpoints
ccwb test          → Verifies OIDC connectivity, identity pool, Bedrock access, quota API
ccwb destroy       → Deletes CF stacks in reverse dependency order
ccwb cleanup       → Removes local auth tools, AWS profile config, cached credentials
ccwb context {list,current,use,show} → Multi-profile management
ccwb quota {set-user,set-group,set-default,list,delete,show,usage,unblock,export,import}
```

### End-User Authentication Flow (credential-process)

```
AWS CLI calls credential-process binary (configured via aws configure)
  → Check cached credentials (keyring or ~/.aws/credentials)
  → If valid: return cached JSON to stdout
  → If expired: acquire port lock on localhost:8400
    → If port busy: wait up to 60s for other process to finish auth
    → Open browser to IdP (Okta/Azure/Auth0/Cognito) with PKCE
    → User authenticates, IdP redirects to localhost:8400/callback
    → Exchange auth code for ID token (with code_verifier)
    → Optional: check quota API (JWT in Authorization header)
    → Exchange ID token for AWS credentials:
        Direct: STS AssumeRoleWithWebIdentity (12h session)
        Cognito: GetId → GetCredentialsForIdentity (8h session)
    → Cache credentials + save monitoring token for otel-helper
    → Output credentials JSON to stdout
```

### Package Distribution Flow (ccwb package → ccwb distribute)

```
ccwb package --prebuilt (recommended):
  1. Copy pre-built Go binaries from source/go/prebuilt/latest/
  2. Copy generic install scripts (install.sh, install.bat, ccwb-install.ps1)
  3. Generate config.json from profile (federation config, quota settings)
  4. Generate claude-settings/settings.json from profile (Bedrock model, OTel endpoint)
  5. Output to dist/{profile}/{timestamp}/
  No Go, Docker, or AWS access required for this step.

ccwb distribute:
  1. Scan dist/ for profile/timestamp builds
  2. User selects a build (wizard, --latest, or explicit --build-profile + --timestamp)
  3. Read binaries from dist/ folder, create ZIP archives using writestr()
  4. Upload to S3 (presigned-s3) or per-platform to landing page bucket
  5. Generate presigned URLs or landing page serves authenticated downloads
```

### Go Binary Details

The Go binaries (`credential-process` and `otel-helper`) are **generic** — they contain zero customer-specific data. All configuration is read at runtime from `config.json`. This means:
- Binaries are built once and distributed to all customers
- Only `config.json` and `settings.json` are customer-specific
- Install scripts are also generic (read profile names from config.json)

**Build requirements for Windows (AV):**
- **Do NOT strip** (`-s -w` ldflags) — Windows Defender cloud ML (Wacatac.B!ml) flags stripped Go binaries
- **Embed PE version info** via `go-winres` — `.syso` files in `cmd/*/` are auto-linked by the Go compiler
- macOS/Linux builds CAN use `-s -w` safely

**Pre-built binaries** are stored at `source/go/prebuilt/v2.0.0/` and symlinked from `source/go/prebuilt/latest/`. These are committed to the repo so `ccwb package --prebuilt` works offline.

## Code Conventions

- Python 3.10-3.12, line length 120
- Go 1.22+, module `github.com/bluedoors/ccwb-binaries`
- Ruff for Python linting and formatting, mypy for type checking
- CLI commands are Cleo `Command` subclasses in `cli/commands/`
- Dataclasses for config models, Pydantic for validation where needed
- CloudFormation must use `${AWS::Partition}` for all ARNs (never hardcode `aws` or `aws-us-gov`)
- GovCloud Cognito uses partition-specific service principals
- Tests in `source/tests/` (unit) and `source/tests/cli/` (CLI command tests)
- Go tests in `source/go/internal/*/` — 27 tests covering jwt, provider, otel, oidc

## Critical Patterns

- **Model changes**: Update `models.py` — contains all model IDs, cross-region profiles, region mappings, and display name dictionaries. Also update `claude-code-dashboard.yaml` throttle metrics if adding new models.
- **Provider detection**: Duplicated in 7 locations (init.py, config.py, package.py, credential_provider, otel_helper, url_validation.py, **Go internal/provider/provider.go**). All must be kept in sync. Okta domains include `.okta.com`, `.oktapreview.com`, `.okta-emea.com`. Cognito has two domain formats: `*.auth.{region}.amazoncognito.com` and `cognito-idp.{region}.amazonaws.com`.
- **Config generation**: `package.py:_create_config()` creates the config.json embedded in end-user packages. The `provider_type` field must be a valid provider (okta/auth0/azure/cognito) or `"auto"` — never `"oidc"`, which crashes the credential_provider. Quota fields (`quota_api_endpoint`, `quota_fail_mode`, `quota_check_interval`) are now included when configured.
- **Profile-first reads**: `package.py` reads federation config (`federated_role_arn`, `identity_pool_name`) and `otel_collector_endpoint` from the profile first, falling back to CloudFormation stack outputs. This allows offline packaging after `ccwb deploy`.
- **Windows compatibility**: All ZIP operations in distribute.py and builds.py use `writestr()`/`read_bytes()` with retry loops instead of `extractall()` to handle Windows Defender scan locks and paths with spaces.
- **Windows AV**: Go binaries must NOT be stripped for Windows (no `-s -w`). Must embed PE version info via go-winres `.syso` files. Stripping is safe for macOS/Linux.
- **OIDC redirect URI**: Fixed at `http://localhost:8400/callback` for the credential provider.
- **Credential storage on Windows**: Keyring entries split across 4 keys due to 2560-byte Windows Credential Manager limit.
- **OTel cache**: Headers are cached regardless of JWT token expiry — headers are static user attributes that don't change when the token expires. This prevents browser re-auth storms when Okta JWTs expire (~1h) while STS credentials are still valid (12h).
- **Config migration**: `migration.py` auto-migrates from legacy single-file format (`source/.ccwb-config/`) to per-profile files (`~/.ccwb/profiles/`). The `Config.load()` method triggers this automatically.
- **Two federation modes**: Direct IAM (`federated_role_arn` + STS) and Cognito Identity Pool (`identity_pool_id`). Auto-detected from config. Direct mode provides 12h sessions with session tags for CloudTrail attribution.
- **Generic install scripts**: `install.sh`, `install.bat`, `ccwb-install.ps1` contain zero customer-specific values. They read profile names, regions, and domains from `config.json` at install time.
