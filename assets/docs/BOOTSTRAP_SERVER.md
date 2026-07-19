# Bootstrap Server

The CoWork Bootstrap Server delivers per-user configuration to Claude Desktop (CoWork) clients dynamically at sign-in. Instead of baking full configuration into static MDM profiles, administrators deploy a lightweight API endpoint that validates the user's OIDC token and returns their personalized settings — inference region, allowed models, OTEL endpoint, and session lifetime.

This enables organizations to change configuration centrally without re-deploying MDM profiles, support different config per user/group (future v2), and ensure configuration is only delivered to authenticated users with valid OIDC tokens.

## How It Works

```
┌─────────────┐     1. Sign in (OIDC)      ┌──────────────┐
│  CoWork     │ ──────────────────────────► │  OIDC IdP    │
│  (Client)   │ ◄────────────────────────── │  (Okta/Azure)│
│             │     2. Receive token        └──────────────┘
│             │
│             │     3. GET /config           ┌──────────────┐
│             │        Authorization:        │  Bootstrap   │
│             │        Bearer <token>        │  Server      │
│             │ ──────────────────────────► │  (Lambda)    │
│             │                              │              │
│             │     4. Validate JWT          │  - Verify    │
│             │        against JWKS          │    signature │
│             │                              │  - Check iss │
│             │     5. Return config JSON    │  - Check aud │
│             │ ◄────────────────────────── │  - Check exp │
└─────────────┘                              └──────────────┘
```

1. User signs into CoWork via OIDC (standard flow)
2. CoWork receives an access/ID token from the IdP
3. CoWork calls the bootstrap URL with the Bearer token
4. Lambda validates the JWT signature against the IdP's JWKS
5. Lambda returns per-user configuration JSON

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
| `OidcIssuerUrl` | OIDC issuer URL for token validation | (from profile) |
| `OidcClientId` | Client ID for audience validation | (from profile) |
| `OidcJwksEndpoint` | JWKS endpoint for signature verification | (auto-derived) |
| `DefaultInferenceRegion` | AWS region for Bedrock inference | `us-east-1` |
| `DefaultInferenceModels` | Comma-separated allowed model IDs | Sonnet |
| `OtlpEndpoint` | OpenTelemetry collector endpoint | (optional) |
| `InferenceSessionLifetimeSec` | Session lifetime before re-auth | `28800` (8h) |

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

- **Token validation**: Every request must include a valid JWT Bearer token. The Lambda validates the signature against the IdP's JWKS, checks issuer (`iss`), audience (`aud`), and expiration (`exp`) claims.
- **No caching**: Responses include `Cache-Control: no-store` to prevent stale configuration.
- **HTTPS only**: API Gateway enforces HTTPS. The JWKS endpoint must also be HTTPS.
- **Short-lived config**: The `expiresAt` field (1 hour) tells clients when to re-fetch. This limits exposure if a config response is somehow captured.
- **No secrets in response**: The config response contains no credentials — only configuration directives. Authentication for Bedrock remains handled by the credential helper.

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

- **Direct STS federation** (`federation_type: "direct"`) with a
  `federated_role_arn`. `ccwb deploy bootstrap` refuses to deploy for Cognito
  federation. The role's trust policy must already allow
  `sts:AssumeRoleWithWebIdentity` (the ccwb Okta auth stack configures this).
- **Reuse the existing OIDC app** — the token audience (`client_id`) is already
  in the IAM OIDC provider's client-id list, so no new IAM OIDC config is needed.

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
