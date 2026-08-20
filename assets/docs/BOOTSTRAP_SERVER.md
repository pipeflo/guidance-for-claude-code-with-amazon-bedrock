# Bootstrap Server

The CoWork Bootstrap Server delivers per-user configuration to Claude Desktop (CoWork) clients dynamically at sign-in. Instead of baking full configuration into static MDM profiles, administrators deploy a lightweight API endpoint that validates the user's OIDC token and returns their personalized settings — inference region, allowed models, OTEL endpoint, and session lifetime.

This enables organizations to change configuration centrally without re-deploying MDM profiles, support different config per user/group (future v2), and ensure configuration is only delivered to authenticated users with valid OIDC tokens.

## How It Works

```
┌─────────────┐     1. Sign in (OIDC)       ┌──────────────┐
│  CoWork     │ ──────────────────────────► │  OIDC IdP    │
│  (Client)   │ ◄────────────────────────── │  (Okta/Azure)│
│             │     2. Receive token        └──────────────┘
│             │
│             │     3. GET /config          ┌──────────────┐
│             │        Authorization:       │     ALB      │
│             │        Bearer <token>       │  (internal   │
│             │ ──────────────────────────► │  or public)  │
│             │                             └──────┬───────┘
│             │                                    │
│             │                             ┌──────▼───────┐
│             │                             │  Bootstrap   │
│             │                             │   Lambda     │
│             │     5. Return config JSON   │              │
│             │ ◄────────────────────────── │  4. Broker   │
└─────────────┘                             └──────┬───────┘
                                                   │
                                            ┌──────▼───────┐
                                            │     STS      │
                                            │ validates the│
                                            │ token + issues│
                                            │ tagged creds │
                                            └──────────────┘
```

1. User signs into CoWork via OIDC (standard flow)
2. CoWork receives an access token from the IdP
3. CoWork calls the bootstrap URL with the Bearer token
4. The Lambda screens the token cheaply, then hands it to STS
   `AssumeRoleWithWebIdentity`, which **validates it** and applies the session
   tags; the Lambda mints a short-lived Bedrock bearer token from the result
5. The Lambda returns per-user configuration JSON

### Where the JWT validation happens

Earlier versions used an API Gateway HTTP API whose native JWT authorizer
validated the token at the edge. That endpoint **could not be made private** —
per AWS, *"you can only configure REST APIs as private"* — and supported neither
resource policies nor AWS WAF. It was therefore replaced by an ALB, which cannot
validate JWTs (its `authenticate-oidc` action is a browser-redirect flow, the
wrong shape for a bearer-token API call).

**STS is now the authoritative validator.** `AssumeRoleWithWebIdentity` verifies
the signature against the IdP's published JWKS, checks `iss` against the IAM OIDC
provider, checks `aud` against that provider's `ClientIdList`, and enforces `exp`.
A forged, tampered, or expired token is rejected there, so the request returns
403 and **no credential is ever issued**. The STS call happens before profile
discovery and before any bearer token is minted.

The Lambda additionally runs a signature-free pre-check on `iss` / `aud` / `exp`
(60s clock skew). That exists to return a clean 401 and to avoid spending an STS
call on junk traffic — **it is not the security boundary.** A consequence of this
design is that the function needs no PyJWT/cryptography dependency and no Lambda
layer: it runs on the boto3/botocore already in the runtime.

## Configuration Options

The bootstrap server is configured during `ccwb init` and deployed with `ccwb deploy bootstrap`.

### Init Wizard

During `ccwb init`, after the CoWork 3P section:

```
CoWork configuration delivery:
  ❯ Static (default — MDM profile with inline config)
    Dynamic (bootstrap server — per-user config at sign-in)
```

### CloudFormation Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `OidcIssuerUrl` | OIDC issuer URL (pre-check) | (from profile) |
| `OidcAudience` | Expected access-token audience, e.g. `api://default` (pre-check) | (from profile) |
| `DefaultInferenceRegion` | AWS region for Bedrock inference | `us-east-1` |
| `DefaultInferenceModels` | Comma-separated allowed model IDs | Sonnet |
| `OtlpEndpoint` | OpenTelemetry collector endpoint | (optional) |
| `InferenceSessionLifetimeSec` | Session lifetime before re-auth | `28800` (8h) |
| `FederatedRoleArn` | Role the broker assumes for each user | (from profile) |
| `AlbScheme` | `internal` (private) or `internet-facing` | `internal` |
| `VpcId` | VPC for the load balancer | (required) |
| `SubnetIds` | ≥2 subnets in different AZs | (required) |
| `CertificateArn` | ACM certificate in this region | (required) |
| `AlbIngressCidr` | CIDR allowed on 443, normally the VPC CIDR | `10.0.0.0/8` |
| `AlbAdditionalIngressCidr` | Second allowed CIDR, e.g. VPN clients | (optional) |
| `DomainName` | Hostname clients connect to | (optional) |
| `HostedZoneId` | Route 53 zone for the alias record | (optional) |

## Endpoint: private or public

The bootstrap server sits behind an Application Load Balancer.

- **`AlbScheme: internal`** (default, recommended) — the load balancer has only
  private IPs, so the endpoint is reachable **exclusively** from inside the VPC or
  over connectivity you already own.
- **`AlbScheme: internet-facing`** — public endpoint. Attach an AWS WAF web ACL
  (possible with an ALB; it never was with an HTTP API).

> **This solution provisions no connectivity.** VPN, Direct Connect, Transit
> Gateway and VPC peering are out of scope, as are hosted zones and certificates.
> The VPC, subnets, certificate and DNS are inputs you supply. With
> `AlbScheme: internal`, devices that cannot reach the VPC will fail at sign-in.

### DNS is required — but it does not have to be public

The load balancer's own name is `internal-…elb.amazonaws.com`, and ACM will not
issue a certificate for a domain you don't own. If a client connects on the raw
ALB hostname, the certificate cannot match it, TLS verification fails, and Claude
Desktop refuses the connection. So **every deployment needs a DNS record** for a
hostname the certificate covers. Three ways to get there:

| Your DNS | What the stack does | Certificate |
|---|---|---|
| **Route 53 private zone** (recommended for `internal`) | Set `DomainName` + `HostedZoneId`; the stack creates the alias. Resolvable in-VPC, and from on-prem via a Resolver inbound endpoint. | A public ACM cert still works — validate with a CNAME in the **public** zone of a domain you own, even though the name itself resolves only privately. Or use ACM Private CA if that CA is already trusted on your devices. |
| **Route 53 public zone** | Same, but the record is public and returns your **private** IPs. | Simplest validation. ⚠️ Publishes internal hostnames/IPs to anyone querying DNS. Not reachable from the internet, but some security teams treat it as information disclosure. |
| **DNS outside Route 53** (Infoblox, BIND, AD DNS) | Leave `DomainName` and `HostedZoneId` empty; point your own CNAME at the `AlbDnsName` stack output. | Your own cert / internal CA. |

### Certificates

Two options, chosen by whether you set `CertificateArn`:

**Supply your own** (`CertificateArn` set) — required for ACM Private CA, imported
certificates, or a domain not in Route 53.

**Let the stack request one** (`CertificateArn` empty) — it requests a
DNS-validated public ACM certificate for `DomainName` and CloudFormation publishes
the validation record itself. Needs `DomainName` plus a hosted zone.

⚠️ **The validation zone must be PUBLIC.** ACM's validators query public DNS, so a
private hosted zone cannot prove domain control — even though it's perfectly fine
for the record clients resolve. For an internal deployment that usually means two
zones:

| Purpose | Zone |
|---|---|
| The record clients resolve (`HostedZoneId`) | private — resolves in-VPC only |
| The ACM validation record (`CertificateValidationZoneId`) | **public** zone for the same domain |

`CertificateValidationZoneId` defaults to `HostedZoneId`, which is correct when
that zone is already public. Set it explicitly only when the record zone is private.

⚠️ **Deploys wait for issuance.** CloudFormation blocks until ACM issues, normally
a few minutes. If the validation zone doesn't actually host `DomainName`, the
deploy **waits** rather than failing — so verify the zone before deploying. `ccwb
init` only offers this option when it can find a public zone, to reduce the chance
of that.

The `CertificateArnUsed` output reports whichever certificate ended up on the
listener.

### Stack outputs

| Output | Use |
|---|---|
| `BootstrapUrl` | Value for the MDM `bootstrapUrl` key. Falls back to the raw ALB hostname when no DNS was configured — that form **fails TLS verification**, so treat it as an in-VPC smoke-test URL only. |
| `AlbDnsName` | Target for your own CNAME when DNS lives outside Route 53. |
| `AlbCanonicalHostedZoneId` | Needed if you create the alias record yourself. |
| `AlbScheme` | Confirms whether the endpoint ended up private or public. |

### Verifying it is actually private

```bash
# From OFF the network — must TIME OUT (not 401, not 403)
curl -m 10 https://<your-domain>/config

# From ON the network, no token — must return 401
curl -s -o /dev/null -w '%{http_code}\n' https://<your-domain>/config
```

A timeout from outside is the test that proves the requirement is met; a 401 from
outside means the endpoint is still publicly reachable.

### Migrating from the API Gateway version

The API Gateway resources were removed from the template, so the next
`ccwb deploy bootstrap` **deletes the HTTP API**. `BootstrapUrl` changes as a
result, so you must re-run `ccwb claude-desktop generate` and re-push the MDM
trust anchor to devices. Run `ccwb init` first to supply the new VPC, subnet,
certificate and DNS inputs — `ccwb deploy bootstrap` refuses to run without them.

### Response Format

```json
{
  "inferenceProvider": "bedrock",
  "inferenceRegion": "us-east-1",
  "inferenceModels": ["us.anthropic.claude-sonnet-4-20250514-v1:0"],
  "inferenceSessionLifetimeSec": 28800,
  "otlpEndpoint": "https://otel.example.com",
  "otlpHeaders": {
    "x-user-id": "user-sub-claim",
    "x-user-email": "user@example.com"
  },
  "expiresAt": 1719352800,
  "user": {
    "sub": "user-sub-claim",
    "email": "user@example.com"
  }
}
```

## Security Considerations

- **Token validation**: every request must carry a valid JWT Bearer token. STS
  `AssumeRoleWithWebIdentity` is the authoritative validator — it verifies the
  signature against the IdP's JWKS and checks `iss`, `aud` and `exp` before any
  credential is issued (see [Where the JWT validation happens](#where-the-jwt-validation-happens)).
  The Lambda's own `iss`/`aud`/`exp` pre-check is a fail-fast guard, not the
  security boundary.
- **Network exposure**: with `AlbScheme: internal` the endpoint has no public IP
  at all, which is the strongest control available here. Prefer it over
  `internet-facing` unless you have a reason not to.
- **Least-privilege Lambda role**: the execution role holds CloudWatch Logs
  permissions only. It deliberately has no `sts:AssumeRole` or `bedrock:*` grants
  — `AssumeRoleWithWebIdentity` is authorized by the *target role's trust policy*
  and the user's token, not by the caller's identity. Do not add them.
- **No caching**: responses include `Cache-Control: no-store` to prevent stale configuration.
- **HTTPS only**: the listener is HTTPS-only (TLS 1.2+ via
  `ELBSecurityPolicy-TLS13-1-2-2021-06`). There is no HTTP listener to redirect from.
- **Minimal surface**: the listener's default action is a 404; only `/config`
  reaches the Lambda.
- **Error opacity**: brokering failures return a generic 403. STS error text is
  logged to CloudWatch but never returned, so role ARNs and policy details don't leak.
- **Short-lived credentials**: the response carries a Bedrock bearer token bounded
  by the STS session (≤12h), and `expiresAt` tells clients when to re-fetch.
- **Response does contain a credential**: unlike the static-config model, this
  response includes `inferenceBedrockBearerToken`. That is why the endpoint
  authenticates every request and sets `no-store` — and a further argument for
  `AlbScheme: internal`.

## How Clients Connect (MDM Anchor Profile)

When using dynamic configuration, deploy a minimal MDM "anchor" profile that only contains the bootstrap URL. The client fetches full configuration from the server at sign-in:

```json
{
  "coworkOAuthClientId": "your-oidc-client-id",
  "coworkOAuthIssuer": "https://your-idp.example.com/oauth2/default",
  "bootstrapUrl": "https://abc123.execute-api.us-east-1.amazonaws.com/config"
}
```

This replaces the need for a full static MDM profile with all inference settings inlined. The client authenticates, receives its token, calls the bootstrap URL, and receives its full configuration.

## Deployment

```bash
# Initialize with dynamic config mode
poetry run ccwb init
# Select "Dynamic" when prompted for CoWork configuration delivery

# Deploy the bootstrap server stack
poetry run ccwb deploy bootstrap

# Or deploy all stacks (bootstrap is included when dynamic mode is configured)
poetry run ccwb deploy
```

## Supported Identity Providers

The bootstrap server works with any OIDC-compatible IdP:

- **Okta** — JWKS at `{issuer}/v1/keys`
- **Azure AD / Entra ID** — JWKS at `login.microsoftonline.com/{tenant}/discovery/v2.0/keys`
- **Google Workspace** — JWKS at `googleapis.com/oauth2/v3/certs`
- **Amazon Cognito** — JWKS at `{user-pool-url}/.well-known/jwks.json`
- **Auth0** — JWKS at `{issuer}/.well-known/jwks.json`
- **Generic OIDC** — Any provider with a standard JWKS endpoint

---

## Per-user credential broker (Amazon Bedrock)

For Amazon Bedrock with direct STS federation, the bootstrap Lambda acts as a
**per-user credential broker**. Instead of returning IAM Identity Center
sign-in config, it:

1. Validates the user's OIDC token (signature, issuer, audience, expiry).
2. Forwards that **same token** to STS `AssumeRoleWithWebIdentity` against your
   existing federated role. Session tags (`Zone`, `Project`/cost key) ride in
   the token's `https://aws.amazon.com/tags` claim, so STS applies them
   automatically — every existing GDPR Deny and cost-attribution IAM policy
   fires unchanged.
3. Mints a short-term Amazon Bedrock bearer token (SigV4 presign of
   `CallWithBearerToken`) from those credentials, scoped to the user's zone
   region, and returns it as `inferenceBedrockBearerToken`.

This means **no end-user binary** — devices only need the MDM trust anchor, and
users double-click Claude Desktop and sign in with their corporate identity.
The broker is not in the inference data path; it only issues credentials at
sign-in. Prompts flow directly from Claude Desktop to Bedrock.

The Lambda resolves the user's Bedrock **region**, **model list**, **MCP
servers**, **spend caps**, and **feature toggles** from their OIDC `groups`
claim, enabling GDPR-style region isolation and role-based access without one
MDM profile per (zone × role) combination.

### How resolution works

The Lambda matches the `groups` claim against two maps configured on the
ccwb profile:

```
groups = ["ccwb-europe-beta", "ccwb-consulting"]
                 │                     │
                 ▼                     ▼
       claude_desktop_zone_config   claude_desktop_role_config
       │
       └─► {"europe": {"region": "eu-west-3", "model_prefix": "eu"}}
                              │
                              ▼
                inferenceBedrockRegion = "eu-west-3"
                bearer token minted for eu-west-3
```

- **Zone match**: any group whose suffix (after `okta_group_prefix`, default
  `ccwb-`) starts with a zone name in `claude_desktop_zone_config` → determines
  `inferenceBedrockRegion` and the region the bearer token is signed for.
- **Role match**: any group whose suffix equals or starts with a role name +
  `-` in `claude_desktop_role_config` → determines `inferenceModels`,
  `inferenceMaxTokensPerWindow`, `managedMcpServers`, `coworkEgressAllowedHosts`.

Both matches are independent — a user can have zero, one, or both. The zone
match also drives a `model_prefix` (e.g. `eu` vs `us`) prepended to role model
IDs to form full Bedrock model IDs (`eu.anthropic.claude-opus-4-6-v1:0`).

### Profile schema

```json
{
  "cowork_config_mode": "dynamic",

  "claude_desktop_zone_config": {
    "usa":    {"region": "us-east-1", "model_prefix": "us"},
    "europe": {"region": "eu-west-3", "model_prefix": "eu"}
  },

  "claude_desktop_role_config": {
    "consulting": {
      "models": ["claude-opus-4-6-v1:0", "claude-sonnet-4-6-v1:0"],
      "max_tokens_per_window": "5000000",
      "mcp_servers": [
        {"name": "knowledge-base", "url": "https://mcp.company.com/kb"}
      ]
    },
    "engineering": {
      "models": ["claude-opus-4-6-v1:0", "claude-sonnet-4-6-v1:0", "claude-haiku-4-5-v1:0"],
      "max_tokens_per_window": "10000000",
      "mcp_servers": [
        {"name": "github", "url": "https://mcp.company.com/github"}
      ],
      "egress_allowed_hosts": ["github.com", "registry.npmjs.org"]
    }
  },

  "claude_desktop_feature_defaults": {
    "chatTabEnabled": "true",
    "coworkTabEnabled": "true",
    "isClaudeCodeForDesktopEnabled": "true"
  }
}
```

The broker reuses `federated_role_arn`, `client_id`, `zones`, and
`okta_group_prefix` from the profile — no dedicated SSO/IDC fields are needed.

### Prerequisites

**Identity**

- **Direct STS federation** (`federation_type: "direct"`) with a
  `federated_role_arn`. `ccwb deploy bootstrap` refuses to deploy for Cognito
  federation. The role's trust policy must already allow
  `sts:AssumeRoleWithWebIdentity` (the ccwb Okta auth stack configures this).
- **Reuse the existing OIDC app** — the token audience (`client_id`) is already
  in the IAM OIDC provider's client-id list, so no new IAM OIDC config is needed.

**Networking — must exist BEFORE you deploy**

This stack creates the load balancer, its security group and (optionally) one DNS
record. It creates nothing else. Have these ready first, because `ccwb init`
prompts for them and `ccwb deploy bootstrap` fails fast without them:

| # | Prerequisite | Notes |
|---|---|---|
| 1 | **A VPC** | Any VPC in the deploy region. Don't reuse the ccwb monitoring VPC — it has only public subnets, and adding to it causes CloudFormation drift on a ccwb-managed stack. |
| 2 | **≥2 subnets in different AZs** | An ALB requirement. Use **private** subnets for `AlbScheme: internal`. **No NAT gateway needed** — the ALB needs no outbound access and the Lambda is invoked through the Lambda API, not from inside the subnet. |
| 3 | **An ACM certificate in the same region** — or a public Route 53 zone so one can be requested for you | Must cover the hostname clients will use. Leave `CertificateArn` empty and the stack requests a DNS-validated certificate for `DomainName`. Supply your own for ACM Private CA, an imported certificate, or a domain outside Route 53. See [Certificates](#certificates). |
| 4 | **A DNS record** | Either give `DomainName` + `HostedZoneId` and the stack creates the alias (private **or** public zone), or manage it yourself and CNAME to the `AlbDnsName` output. Not optional in effect — see [DNS is required](#dns-is-required--but-it-does-not-have-to-be-public). |
| 5 | **Network reachability from devices** | For `AlbScheme: internal`, devices need existing access to the VPC — VPN, Direct Connect, or being in-VPC. **This solution provisions none of it.** Without it, sign-in fails. |
| 6 | **Deploy-time IAM permissions** | To create an ALB, target group, listener, security group, and the Route 53 record if used. |

Not required: a NAT gateway, a public subnet, putting the Lambda in the VPC, or
any change to the IAM OIDC provider.

### Auto-populated values

`ccwb init` derives sensible defaults from your existing profile:

| Field | Source |
|-------|--------|
| `FederatedRoleArn` (stack param) | `federated_role_arn` |
| `MaxSessionDuration` (stack param) | `max_session_duration` (default 43200) |
| `claude_desktop_zone_config` | built from `zones[]` when `enforce_project_isolation` is true, using a built-in `usa→us-east-1` / `europe→eu-west-3` / `apac→ap-northeast-1` table |
| `claude_desktop_feature_defaults` | `{chatTab, coworkTab, code} = "true"` |

Role config is not collected interactively — admins edit the profile JSON
directly (see schema above) before `ccwb deploy bootstrap`.

### Backward compatibility

If `claude_desktop_zone_config` is empty, the broker mints a token for the
single `DEFAULT_INFERENCE_REGION` and returns `DEFAULT_INFERENCE_MODELS` for
every user. Zone/role maps are opt-in and only take effect once populated.

### Token lifetime & refresh

The bearer token inherits the STS session lifetime (up to
`MaxSessionDuration`, default 12h). `expiresAt` in the response is set just
under that so Claude Desktop re-fetches before expiry. There is no mid-session
silent refresh (that would require an end-user helper binary); when the session
expires the user re-authenticates through the normal launch flow — the same
cadence as the existing Claude Code deployment.

### Generating MDM trust-anchor profiles

After `ccwb deploy bootstrap` succeeds, generate the MDM profile that points
end-user devices at your bootstrap endpoint:

```bash
ccwb claude-desktop generate
```

Writes three files to `dist/<profile>/claude-desktop/`:

- `claude-desktop-trust-anchor.json` — raw config for debugging
- `claude-desktop-trust-anchor.mobileconfig` — push via Jamf / Kandji / etc.
- `claude-desktop-trust-anchor.reg` — push via Group Policy / Intune

The trust-anchor profile is identical for every user — only the bootstrap URL
and OIDC settings (issuer + `client_id` + `groups` scope) are baked in. Per-user
credentials and config are fetched at sign-in.

See `customer-upgrade-guides/UPGRADE_TO_CLAUDE_DESKTOP_BOOTSTRAP.md` for a full
deployment walkthrough.

> **Note**: For organizations that use AWS IAM Identity Center as their primary
> access model, Claude Desktop's built-in "in-app AWS sign-in" is an alternative
> that needs no broker. The broker path documented here is for direct
> Okta→STS federation (the ccwb default), where it preserves the existing
> session-tag / GDPR / cost-attribution design end to end.
