# ABOUTME: Lambda handler for the Claude Desktop Bootstrap Server (credential broker)
# ABOUTME: The API Gateway JWT authorizer validates the token; this function reads the
# ABOUTME: authorizer claims, exchanges the raw token for STS credentials via
# ABOUTME: AssumeRoleWithWebIdentity (session tags intact), and mints a Bedrock bearer token.

"""Claude Desktop Bootstrap Server — per-user Bedrock bearer-token broker.

Flow per request:
  1. Claude Desktop signs the user into the org OIDC provider (Okta) via PKCE and
     sends the resulting token as `Authorization: Bearer <token>` to GET /config.
  2. The API Gateway JWT authorizer validates the token's signature (against the
     issuer's JWKS via OIDC discovery), issuer, audience, and expiry BEFORE this
     function runs, and passes the decoded claims in
     event.requestContext.authorizer.jwt.claims. No PyJWT dependency here.
  3. This function forwards that SAME raw token to STS AssumeRoleWithWebIdentity.
     Session tags (Zone, Project/CostCenter) ride in the token's
     https://aws.amazon.com/tags claim and STS applies them automatically — so
     every existing GDPR Deny and cost-attribution IAM policy fires unchanged.
  4. It mints a short-term Amazon Bedrock bearer token (SigV4 presign of
     CallWithBearerToken) from those credentials and returns it as
     `inferenceBedrockBearerToken`, scoped to the user's zone region.

The bootstrap server is NOT in the inference data path — it only issues
credentials at sign-in. Prompts go directly from Claude Desktop to Bedrock.
"""

import base64
import json
import os
import re
import time

# boto3 + botocore ship in the Lambda Python runtime.
import boto3
from botocore import UNSIGNED
from botocore.auth import SigV4QueryAuth
from botocore.awsrequest import AWSRequest
from botocore.config import Config as BotoConfig
from botocore.credentials import Credentials

# Configuration from environment variables
DEFAULT_INFERENCE_REGION = os.environ.get("DEFAULT_INFERENCE_REGION", "us-east-1")
DEFAULT_INFERENCE_MODELS = os.environ.get("DEFAULT_INFERENCE_MODELS", "")
OTLP_ENDPOINT = os.environ.get("OTLP_ENDPOINT", "")
INFERENCE_SESSION_LIFETIME_SEC = int(os.environ.get("INFERENCE_SESSION_LIFETIME_SEC", "28800"))

# Zone/role-based dynamic routing + broker config — read at invocation time
# (not module load) so Lambda env var updates take effect without a cold start.
def _get_zone_config():
    return os.environ.get("ZONE_CONFIG", "")

def _get_role_config():
    return os.environ.get("ROLE_CONFIG", "")

def _get_feature_defaults():
    return os.environ.get("FEATURE_DEFAULTS", "")

def _get_group_prefix():
    return os.environ.get("GROUP_PREFIX", "ccwb-")

def _get_federated_role_arn():
    return os.environ.get("FEDERATED_ROLE_ARN", "")

def _get_max_session_duration():
    try:
        return int(os.environ.get("MAX_SESSION_DURATION", "43200"))
    except ValueError:
        return 43200


def _extract_claims(event: dict) -> dict:
    """Read the JWT claims the API Gateway authorizer attached to the request.

    HTTP API JWT authorizers place decoded claims at
    event.requestContext.authorizer.jwt.claims. The `groups` claim may arrive as
    a real list or as a stringified list (e.g. "[a, b]") depending on the
    provider; normalize it to a list.
    """
    claims = (
        event.get("requestContext", {})
        .get("authorizer", {})
        .get("jwt", {})
        .get("claims", {})
    ) or {}

    groups = claims.get("groups", [])
    if isinstance(groups, str):
        # API Gateway may serialize a multi-valued claim as "[a, b, c]".
        stripped = groups.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            stripped = stripped[1:-1]
        groups = [g.strip().strip('"') for g in stripped.split(",") if g.strip()]
    claims = dict(claims)
    claims["groups"] = groups
    return claims


def _extract_bearer_token(event: dict) -> str:
    """Return the raw bearer token from the Authorization header.

    The authorizer has already validated it; we forward it verbatim to STS as the
    WebIdentityToken so the session-tag claim is applied.
    """
    headers = event.get("headers", {}) or {}
    auth_header = headers.get("authorization", headers.get("Authorization", "")) or ""
    if auth_header.startswith("Bearer "):
        return auth_header[7:]
    return ""


def _group_suffix(group: str, prefix: str) -> str | None:
    """Return the part of `group` after `prefix`, tolerant of the trailing hyphen.

    Group names follow <prefix>-<zone>-<project> (e.g. ccwb-us-alpha). The
    configured prefix may be written with or without the trailing '-'
    ('ccwb' or 'ccwb-'); normalize both so matching is robust. Returns the
    zone/role remainder ('us-alpha') or None if the group doesn't match.
    """
    base = prefix.rstrip("-")
    if not group.startswith(base):
        return None
    rest = group[len(base):]
    return rest.lstrip("-")  # drop the separator so remainder starts at the zone/role


def _resolve_zone(groups: list[str], zone_config: dict, prefix: str) -> dict | None:
    """Resolve user's zone from their group memberships.

    Matches the first group whose <prefix>-stripped remainder begins with a zone
    name. E.g. groups=["ccwb-us-alpha"], zones={"us": {...}} → returns us config.
    """
    for group in groups:
        suffix = _group_suffix(group, prefix)
        if suffix is None:
            continue
        for zone_name in zone_config:
            # match "<zone>" exactly or "<zone>-<project>"
            if suffix == zone_name or suffix.startswith(zone_name + "-"):
                return {"name": zone_name, **zone_config[zone_name]}
    return None


def _resolve_role(groups: list[str], role_config: dict, prefix: str) -> dict | None:
    """Resolve user's role from their group memberships.

    Matches groups where the suffix after prefix equals or starts with a role name.
    E.g., groups=["ccwb-consulting"], roles={"consulting": {...}} → returns consulting config.
    """
    for group in groups:
        suffix = _group_suffix(group, prefix)
        if suffix is None:
            continue
        for role_name in role_config:
            if suffix == role_name or suffix.startswith(role_name + "-"):
                return {"name": role_name, **role_config[role_name]}
    return None


def _derive_session_name(claims: dict) -> str:
    """Derive an STS RoleSessionName from token claims.

    Uses the full email when present (so it lands in CUR line_item_iam_principal
    for per-user cost visibility), else falls back to a sanitized sub. Matches
    the logic in the credential-process binary so CloudTrail/CUR look identical
    whether the user authenticates via Claude Code or Claude Desktop.

    AWS RoleSessionName allows [\\w+=,.@-], max 64 chars.
    """
    if claims.get("email"):
        return re.sub(r"[^\w+=,.@-]", "-", str(claims["email"]))[:64]
    if claims.get("sub"):
        sub_sanitized = re.sub(r"[^\w+=,.@-]", "-", str(claims["sub"])[:32])
        return f"claude-desktop-{sub_sanitized}"[:64]
    return "claude-desktop"


def _mint_bedrock_bearer_token(user_token: str, region: str, role_arn: str, claims: dict):
    """Exchange the user's OIDC token for a short-term Bedrock bearer token.

    Forwards the user's token to STS AssumeRoleWithWebIdentity (NOT the Lambda's
    own identity) so the token's https://aws.amazon.com/tags claim delivers the
    Zone/Project session tags. Then SigV4-presigns a CallWithBearerToken request
    to produce the `bedrock-api-key-<base64>` token Claude Desktop expects.

    Returns (token_string, expiration_epoch_seconds).
    Raises on any STS or signing failure (caller maps to 403).
    """
    duration = _get_max_session_duration()

    # AssumeRoleWithWebIdentity is authorized by the target role's trust policy
    # plus the web-identity token — it needs no caller credentials. We use an
    # UNSIGNED STS client so the Lambda's own execution-role credentials are not
    # attached (mirrors the credential-process binary clearing AWS_* env vars).
    # Session tags are NOT passed as a parameter; they ride in the token's
    # https://aws.amazon.com/tags claim and STS applies them automatically.
    sts = boto3.client(
        "sts",
        region_name=region,
        config=BotoConfig(signature_version=UNSIGNED),
    )
    resp = sts.assume_role_with_web_identity(
        RoleArn=role_arn,
        RoleSessionName=_derive_session_name(claims),
        WebIdentityToken=user_token,
        DurationSeconds=duration,
    )
    creds = resp["Credentials"]
    expiration = creds["Expiration"]
    expiration_epoch = int(expiration.timestamp()) if hasattr(expiration, "timestamp") else int(time.time()) + duration

    # Mint the Bedrock bearer token, byte-for-byte matching the official
    # aws-bedrock-token-generator algorithm (any deviation => Bedrock rejects with
    # "Invalid API Key format: Must start with pre-defined prefix"):
    #   1. SigV4-PRESIGN a GET on https://bedrock.<region>.amazonaws.com/
    #      ?Action=CallWithBearerToken  (service "bedrock", regional host)
    #   2. take the presigned URL, drop the "https://" scheme, append "&Version=1"
    #   3. URL-SAFE base64, strip "=" padding
    #   4. prepend the literal prefix "bedrock-api-key-"
    botocore_creds = Credentials(creds["AccessKeyId"], creds["SecretAccessKey"], creds["SessionToken"])
    host = f"bedrock.{region}.amazonaws.com"
    request = AWSRequest(
        method="GET",
        url=f"https://{host}/?Action=CallWithBearerToken",
        headers={"host": host},
    )
    SigV4QueryAuth(botocore_creds, "bedrock", region, expires=duration).add_auth(request)
    presigned = request.url[len("https://"):] + "&Version=1"
    encoded = base64.urlsafe_b64encode(presigned.encode("utf-8")).decode("utf-8").rstrip("=")
    token = "bedrock-api-key-" + encoded

    return token, expiration_epoch


def _build_config_response(claims: dict, user_token: str) -> dict:
    """Build the per-user configuration response.

    Resolves the user's zone from their group claims to pick the Bedrock region,
    brokers a per-user Bedrock bearer token scoped to that region, and layers on
    role-based models / MCP / spend caps and feature toggles.

    Raises RuntimeError if credential brokering fails (caller maps to 403).
    """
    user_sub = claims.get("sub", "unknown")
    user_email = claims.get("email", claims.get("preferred_username", user_sub))
    groups = claims.get("groups", [])

    # Read dynamic config from environment at invocation time
    zone_config_raw = _get_zone_config()
    role_config_raw = _get_role_config()
    feature_defaults_raw = _get_feature_defaults()
    prefix = _get_group_prefix()
    role_arn = _get_federated_role_arn()

    zone_config = json.loads(zone_config_raw) if zone_config_raw else {}
    role_config = json.loads(role_config_raw) if role_config_raw else {}
    feature_defaults = json.loads(feature_defaults_raw) if feature_defaults_raw else {}

    # Resolve zone → determines region and (under GDPR isolation) the exact
    # application-inference-profile ARNs the user is allowed to invoke.
    resolved_zone = _resolve_zone(groups, zone_config, prefix) if zone_config else None
    inference_region = resolved_zone["region"] if resolved_zone else DEFAULT_INFERENCE_REGION

    # Resolve role → spend caps, MCP servers (and models when no zone ARNs apply).
    resolved_role = _resolve_role(groups, role_config, prefix) if role_config else None

    # When zone routing is configured (GDPR isolation) but the user's groups match
    # no zone, do NOT fall back to a CRIS default — under isolation that model has
    # no Zone tag and Bedrock would AccessDeny it, masking the real cause. Fail
    # loudly so the operator sees "user's groups map to no configured zone".
    if zone_config and not resolved_zone:
        raise RuntimeError(
            f"User groups {groups!r} match no configured zone "
            f"(zones: {list(zone_config)}). Check the user's IdP group vs "
            f"claude_desktop_zone_config / okta_group_prefix."
        )

    # Model precedence:
    #   1. Zone application-inference-profile ARNs (GDPR isolation) — authoritative,
    #      they carry the Zone resource tag the IAM AllowBedrockInvokeInZone policy
    #      requires. A CRIS model ID would be denied under isolation.
    #   2. Role model list, prefixed with the zone's model_prefix (non-isolated
    #      zone routing).
    #   3. DEFAULT_INFERENCE_MODELS (only when no zone routing is configured at all).
    if resolved_zone and resolved_zone.get("models"):
        models = list(resolved_zone["models"])
    elif resolved_role and "models" in resolved_role:
        model_prefix = resolved_zone.get("model_prefix", "us") if resolved_zone else "us"
        models = [f"{model_prefix}.anthropic.{m}" if not m.startswith(model_prefix) else m
                  for m in resolved_role["models"]]
    else:
        models = [m.strip() for m in DEFAULT_INFERENCE_MODELS.split(",") if m.strip()]

    # Broker a per-user Bedrock bearer token for the resolved region.
    if not role_arn:
        raise RuntimeError("FEDERATED_ROLE_ARN is not configured on the bootstrap Lambda")
    bearer_token, token_expiry = _mint_bedrock_bearer_token(user_token, inference_region, role_arn, claims)

    # Re-fetch slightly before the STS session expires so the client always has
    # a live token. 5-minute skew.
    expires_at = max(int(time.time()) + 60, token_expiry - 300)

    config = {
        "inferenceProvider": "bedrock",
        "inferenceCredentialKind": "static",  # bearer-token credential
        "inferenceBedrockRegion": inference_region,
        "inferenceBedrockBearerToken": bearer_token,
        # Array values are JSON-encoded strings per the config reference.
        "inferenceModels": json.dumps(models),
        # We supply the exact model list/ARNs, so the client must NOT probe the
        # Bedrock control plane (ListFoundationModels/ListInferenceProfiles) — the
        # federated role has no control-plane list permission and it would 403.
        "modelDiscoveryEnabled": "false",
        "inferenceSessionLifetimeSec": INFERENCE_SESSION_LIFETIME_SEC,
        "expiresAt": expires_at,
        "user": {
            "sub": user_sub,
            "email": user_email,
        },
    }

    # Feature toggles (from defaults, overridable by role)
    for key, value in feature_defaults.items():
        config[key] = value
    if resolved_role:
        _cap_keys = {
            "max_tokens_per_window": "inferenceMaxTokensPerWindow",
            "token_window_hours": "inferenceTokenWindowHours",
        }
        for key, camel_key in _cap_keys.items():
            if key in resolved_role:
                config[camel_key] = str(resolved_role[key])
        if "mcp_servers" in resolved_role:
            config["managedMcpServers"] = json.dumps(resolved_role["mcp_servers"])
        if "egress_allowed_hosts" in resolved_role:
            config["coworkEgressAllowedHosts"] = json.dumps(resolved_role["egress_allowed_hosts"])

    # OTel configuration
    if OTLP_ENDPOINT:
        config["otlpEndpoint"] = OTLP_ENDPOINT
        config["otlpProtocol"] = "http/protobuf"
        config["otlpHeaders"] = {
            "x-user-id": user_sub,
            "x-user-email": user_email,
        }

    # Zone banner (visual indicator for the user)
    if resolved_zone:
        zone_display = resolved_zone["name"].upper()
        config["banner"] = json.dumps({
            "text": f"Claude Desktop — {zone_display} Zone",
            "backgroundColor": "#1565c0",
            "textColor": "#ffffff",
        })

    return config


def _response(status_code: int, body: dict, extra_headers: dict = None) -> dict:
    """Build a standard API Gateway v2 response.

    Args:
        status_code: HTTP status code
        body: Response body dict
        extra_headers: Additional headers to include

    Returns:
        API Gateway v2 response dict
    """
    headers = {
        "Content-Type": "application/json",
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
    }
    if extra_headers:
        headers.update(extra_headers)

    return {
        "statusCode": status_code,
        "headers": headers,
        "body": json.dumps(body),
    }


def lambda_handler(event, context):
    """Main Lambda handler for the Bootstrap Server.

    The API Gateway JWT authorizer has already validated the token
    (signature/iss/aud/exp) before this runs, so we trust the claims it attached
    and only need to read them + the raw token, then broker credentials.

    Returns:
        - 200: Configuration JSON on success
        - 401: No authorizer claims / token on the request (defense in depth)
        - 403: Credential brokering failed (STS deny / misconfig)
        - 500: Internal server error
    """
    try:
        claims = _extract_claims(event)
        token = _extract_bearer_token(event)

        # Defense in depth: the authorizer should guarantee both, but never try
        # to broker without a subject or the raw token.
        if not claims.get("sub") or not token:
            return _response(401, {
                "error": "unauthorized",
                "message": "Missing authenticated identity",
            })

        # Broker credentials and build configuration. Credential-brokering
        # failures (STS deny, misconfigured role, signing error) are logged in
        # full to CloudWatch but returned to the client as a generic 403 — never
        # leak STS error text, which can reveal role ARNs or policy details.
        try:
            config = _build_config_response(claims, token)
        except Exception as broker_error:
            print(f"ERROR: Credential brokering failed: {str(broker_error)}")
            return _response(403, {
                "error": "forbidden",
                "message": "Unable to issue Bedrock credentials for this user",
            })

        return _response(200, config)

    except Exception as e:
        # Log the error for CloudWatch but don't leak details to client
        print(f"ERROR: Unhandled exception in bootstrap handler: {str(e)}")
        return _response(500, {
            "error": "internal_error",
            "message": "An internal error occurred",
        })
