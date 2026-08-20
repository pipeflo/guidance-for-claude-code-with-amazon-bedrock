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
│             │        Authorization:       │  PRIVATE     │
│             │        Bearer <token>       │  REST API    │
│             │ ──────────────────────────► │  (via VPCe)  │
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

Earlier versions used an API Gateway **HTTP** API whose native JWT authorizer
validated the token at the edge. That endpoint **could not be made private** — per
AWS, *"you can only configure REST APIs as private"*. Moving to a **REST** API made
the endpoint private but gave up the JWT authorizer, which REST APIs do not offer.

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
| `VpcEndpointId` | Existing execute-api VPC endpoint; empty = create one | `""` |
| `VpcId` | VPC to create the endpoint in (only if creating) | `""` |
| `SubnetIds` | Subnets for the endpoint (only if creating) | `""` |
| `EndpointIngressCidr` | CIDR allowed on 443 for a created endpoint | `10.0.0.0/8` |
| `StageName` | REST API stage; appears in the invoke URL | `prod` |

## Endpoint: a private REST API

The bootstrap server is served from a **private API Gateway REST API**, reachable
only through an `execute-api` interface VPC endpoint.

**Why this shape.** Of the options AWS offers, only a REST API can be `PRIVATE` —
an HTTP API cannot ("you can only configure REST APIs as private"). And because
the invoke hostname sits under `execute-api.<region>.amazonaws.com`, **AWS supplies
the TLS certificate**. That is the decisive advantage over an internal Application
Load Balancer, which requires a certificate you provide — AWS will not issue one
for `*.elb.amazonaws.com`.

So this endpoint needs:

- ❌ no ACM certificate
- ❌ no public hosted zone
- ❌ no DNS record
- ❌ no NAT gateway, no VPC creation, no VPC-attached Lambda
- ✅ one `execute-api` VPC endpoint — yours, or created here
- ✅ device→VPC connectivity that **you already have** (VPN / Direct Connect)

### The VPC endpoint

Supply `VpcEndpointId` to use an endpoint your organisation already runs, or leave
it empty and give `VpcId` + `SubnetIds` to have one created.

**The stack never creates a VPC.** A brand-new VPC would have no path from any
device, so the endpoint inside it would be unreachable. The VPC must be one your
devices can already reach.

⚠️ **Private DNS is deliberately left OFF** on any endpoint this stack creates.
Enabling it hijacks `execute-api.<region>.amazonaws.com` for the **entire VPC**,
which breaks anything there that calls a public or regional API Gateway. Instead
the API is *associated* with the endpoint, giving a dedicated hostname:

```
https://{api-id}-{vpce-id}.execute-api.{region}.amazonaws.com/{stage}/config
```

That form needs no `Host` or `x-apigw-api-id` header — which matters, because
**Claude Desktop cannot send a custom header** when fetching its bootstrap config.
It is the `BootstrapUrl` output, and it works whether or not private DNS is on.

If you already run an endpoint **with** private DNS enabled, the standard hostname
also works and is emitted as `BootstrapUrlPrivateDns`.

### Centralised endpoints in a networking account

If your organisation keeps all interface endpoints in a central networking account,
you do **not** need a VPC endpoint — or even a VPC — in the account running this
stack. PrivateLink supports this directly:

> *"PrivateLink allows access to private API Gateway endpoints in different AWS
> accounts, without VPC peering, VPN connections, or AWS Transit Gateway. A single
> `execute-api` endpoint is used to connect to any API Gateway, regardless of which
> AWS account the destination API Gateway is in. Resource policies control which VPC
> endpoints have access."*

Supply the central endpoint's ID as `VpcEndpointId` and set
`AssociateVpcEndpoint: false`. In `ccwb init`, choose **"Enter an endpoint ID
manually"** and answer *no* to "is that endpoint in THIS AWS account?" — the wizard
cannot discover endpoints in other accounts, so this is the only way to name one.

Two consequences:

- **The resource policy is the access control**, and it names that endpoint. Nothing
  else changes.
- **Association is same-account only**, so the dedicated `{api-id}-{vpce-id}`
  hostname is unavailable. Clients use the standard
  `{api-id}.execute-api.{region}.amazonaws.com` hostname instead, which **requires
  private DNS enabled** on the central endpoint. That is normal in a centralised
  setup — sharing the private hosted zone to spoke VPCs is the point of it — but
  confirm it with your networking team rather than assuming.

### Devices must resolve that hostname

The invoke hostname is public DNS, but it resolves to the endpoint's **private**
IPs — and only from inside the VPC, or from a network whose DNS forwards to the VPC
resolver. From a laptop on VPN that means either a **Route 53 Resolver inbound
endpoint** in the VPC, or conditional forwarding from your corporate DNS.

Without that, deploy succeeds and every user sign-in fails. It is the single most
common way this goes wrong.

### Access control

A `PRIVATE` REST API is inaccessible to every VPC until a resource policy grants
access, so the policy is not optional. This stack writes one scoped to the single
VPC endpoint — an `Allow` on `aws:SourceVpce` plus an explicit `Deny` for anything
else — so a VPC endpoint in another account cannot invoke it. Enforced at the API
Gateway edge, before the Lambda runs.

### Stack outputs

| Output | Use |
|---|---|
| `BootstrapUrl` | Value for the MDM `bootstrapUrl` key. Endpoint-associated hostname; needs no extra header. |
| `BootstrapUrlPrivateDns` | Alternative, valid only if private DNS is enabled on the endpoint. |
| `VpcEndpointIdUsed` | The endpoint serving the API — created here, or the one you supplied. |
| `RestApiId` | The private REST API's ID. |

### Verifying it is actually private

Run these from a machine **on** the network and one **off** it.

```bash
# ON the network, no token -> 401 (reachable, TLS valid, auth required)
curl -s -i --max-time 20 https://{api-id}-{vpce-id}.execute-api.{region}.amazonaws.com/{stage}/config

# OFF the network -> must NOT get an HTTP response
curl -s -o /dev/null --max-time 20 https://.../{stage}/config; echo "exit=$?"
```

Expected results:

| From | Expected | Meaning |
|---|---|---|
| On-network, no token | `401` | reachable, certificate valid, authentication required |
| On-network, bad/expired token | `401` | pre-check rejected it without an STS call |
| On-network, wrong path or stage | `403` | only `/config` on the deployed stage exists |
| On-network, `OPTIONS` | `204` | CORS preflight |
| **Off-network** | **`curl` exit 28 (timeout)** | ✅ **private** |
| Off-network | `401` or `200` | ❌ not private — investigate immediately |

The hostname resolves publicly to the endpoint's **private** IPs, so `nslookup` succeeds
from anywhere while only in-network clients can connect. A timeout off-network is
therefore the expected pass, not a DNS failure.

> ⚠️ **On Windows, use `curl` — not PowerShell's `Invoke-WebRequest`.**
> `Invoke-WebRequest` performs WPAD proxy auto-discovery, which stalls inside a VPC
> with no WPAD server. Every request appears to time out even when the endpoint is
> working perfectly, which looks exactly like a broken deployment. `curl` ships with
> Windows Server 2022 and does not do WPAD.

### Migrating from an earlier version

Earlier releases used an API Gateway **HTTP API** (public, no private option) and
then briefly an internal **ALB** (private, but certificate required). Both are
gone. The next `ccwb deploy bootstrap` replaces the endpoint, so `BootstrapUrl`
changes and you must re-run `ccwb claude-desktop generate` and re-push the MDM
trust anchor. Run `ccwb init` first to supply the VPC endpoint details — deploy
refuses without them. Certificate, hosted-zone and DNS settings are no longer used
and can be removed from the profile.

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
- **Network exposure**: the API is `PRIVATE`, so it has no internet-facing path at
  all. On top of that, a resource policy restricts invocation to a single
  `execute-api` VPC endpoint, enforced at the edge before the Lambda runs — so even
  another VPC endpoint in another account cannot reach it.
- **Least-privilege Lambda role**: the execution role holds CloudWatch Logs
  permissions only. It deliberately has no `sts:AssumeRole` or `bedrock:*` grants
  — `AssumeRoleWithWebIdentity` is authorized by the *target role's trust policy*
  and the user's token, not by the caller's identity. Do not add them.
- **No caching**: responses include `Cache-Control: no-store` to prevent stale configuration.
- **HTTPS only**: API Gateway serves HTTPS exclusively, with an AWS-managed
  certificate for the `execute-api` hostname.
- **Minimal surface**: only the `/config` resource exists; every other path is
  rejected by API Gateway before the Lambda runs.
- **Error opacity**: brokering failures return a generic 403. STS error text is
  logged to CloudWatch but never returned, so role ARNs and policy details don't leak.
- **Short-lived credentials**: the response carries a Bedrock bearer token bounded
  by the STS session (≤12h), and `expiresAt` tells clients when to re-fetch.
- **Response does contain a credential**: unlike the static-config model, this
  response includes `inferenceBedrockBearerToken`. That is why the endpoint
  authenticates every request, sets `no-store`, and is private.

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

This stack creates the private REST API and, optionally, one `execute-api` VPC
endpoint. Nothing else. Have these ready first:

| # | Prerequisite | Notes |
|---|---|---|
| 1 | **A VPC your devices can already reach** | The stack never creates one — a fresh VPC would be unreachable. |
| 2 | **One or more subnets in it** | For the `execute-api` endpoint, ideally one per AZ you serve. Skip if you supply `VpcEndpointId`. |
| 3 | **Device→VPC connectivity** | VPN, Direct Connect, or clients inside the VPC. **This solution provisions none of it.** Without it, sign-in fails. |
| 4 | **DNS resolution for the endpoint hostname** | Route 53 Resolver inbound endpoint, or corporate DNS forwarding to the VPC resolver. |
| 5 | **Deploy-time IAM permissions** | REST API, VPC endpoint, security group, Lambda, IAM role, S3 for Lambda packaging. |

**No certificate. No hosted zone. No DNS record.** AWS provides TLS for the
`execute-api` hostname.

Not required: a certificate, a hosted zone, a NAT gateway, a public subnet,
putting the Lambda in the VPC, or any change to the IAM OIDC provider.

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
