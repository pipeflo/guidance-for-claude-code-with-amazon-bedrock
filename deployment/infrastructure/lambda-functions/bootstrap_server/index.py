# ABOUTME: Lambda handler for the Claude Desktop Bootstrap Server (credential broker)
# ABOUTME: Validates the user's OIDC token, exchanges it for STS credentials via
# ABOUTME: AssumeRoleWithWebIdentity (session tags intact), mints a short-term Bedrock
# ABOUTME: bearer token, and returns per-user config. No end-user binary required.

"""Claude Desktop Bootstrap Server — per-user Bedrock bearer-token broker.

Flow per request:
  1. Claude Desktop signs the user into the org OIDC provider (Okta) via PKCE and
     sends the resulting token as `Authorization: Bearer <token>` to GET /config.
  2. This Lambda validates the token's signature/claims against the provider JWKS.
  3. It forwards that SAME token to STS AssumeRoleWithWebIdentity. Session tags
     (Zone, Project/CostCenter) ride in the token's https://aws.amazon.com/tags
     claim and STS applies them automatically — so every existing GDPR Deny and
     cost-attribution IAM policy fires unchanged.
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
import urllib.request

# boto3 + botocore ship in the Lambda Python runtime.
import boto3
from botocore import UNSIGNED
from botocore.auth import SigV4QueryAuth
from botocore.awsrequest import AWSRequest
from botocore.config import Config as BotoConfig
from botocore.credentials import Credentials

# Optional: PyJWT with cryptography for RS256 verification
# Falls back to manual verification if not available in Lambda layer
try:
    import jwt
    from jwt import PyJWKClient

    HAS_PYJWT = True
except ImportError:
    HAS_PYJWT = False

# Configuration from environment variables
OIDC_ISSUER_URL = os.environ.get("OIDC_ISSUER_URL", "")
OIDC_CLIENT_ID = os.environ.get("OIDC_CLIENT_ID", "")
OIDC_JWKS_ENDPOINT = os.environ.get("OIDC_JWKS_ENDPOINT", "")
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

# JWKS cache (module-level for Lambda container reuse)
_jwks_client = None
_jwks_cache = None
_jwks_cache_time = 0
JWKS_CACHE_TTL = 3600  # Cache JWKS for 1 hour


def _get_jwks_client():
    """Get or create a cached PyJWKClient instance."""
    global _jwks_client
    if _jwks_client is None and HAS_PYJWT:
        _jwks_client = PyJWKClient(OIDC_JWKS_ENDPOINT, cache_keys=True)
    return _jwks_client


def _fetch_jwks():
    """Fetch JWKS from the configured endpoint with caching."""
    global _jwks_cache, _jwks_cache_time

    now = time.time()
    if _jwks_cache and (now - _jwks_cache_time) < JWKS_CACHE_TTL:
        return _jwks_cache

    try:
        req = urllib.request.Request(OIDC_JWKS_ENDPOINT)
        with urllib.request.urlopen(req, timeout=5) as resp:
            _jwks_cache = json.loads(resp.read())
            _jwks_cache_time = now
            return _jwks_cache
    except Exception as e:
        raise ValueError(f"Failed to fetch JWKS: {str(e)}")


def _validate_token(token: str) -> dict:
    """Validate JWT token and return decoded claims.

    Args:
        token: Raw JWT Bearer token string

    Returns:
        Decoded token claims dict

    Raises:
        ValueError: If token is invalid, expired, or signature verification fails
    """
    if not token:
        raise ValueError("No token provided")

    if not HAS_PYJWT:
        raise ValueError("PyJWT library not available — cannot validate tokens")

    try:
        # Get the signing key from JWKS
        jwks_client = _get_jwks_client()
        signing_key = jwks_client.get_signing_key_from_jwt(token)

        # Decode and validate the token
        decoded = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"],
            issuer=OIDC_ISSUER_URL,
            audience=OIDC_CLIENT_ID,
            options={
                "verify_exp": True,
                "verify_iss": True,
                "verify_aud": True,
                "require": ["exp", "iss", "sub"],
            },
        )
        return decoded

    except jwt.ExpiredSignatureError:
        raise ValueError("Token has expired")
    except jwt.InvalidIssuerError:
        raise ValueError("Invalid token issuer")
    except jwt.InvalidAudienceError:
        raise ValueError("Invalid token audience")
    except jwt.InvalidSignatureError:
        raise ValueError("Invalid token signature")
    except jwt.DecodeError as e:
        raise ValueError(f"Token decode error: {str(e)}")
    except Exception as e:
        raise ValueError(f"Token validation failed: {str(e)}")


def _resolve_zone(groups: list[str], zone_config: dict, prefix: str) -> dict | None:
    """Resolve user's zone from their group memberships.

    Matches the first group starting with prefix followed by a zone name.
    E.g., groups=["ccwb-europe-beta"], zones={"europe": {...}} → returns europe config.
    """
    for group in groups:
        if not group.startswith(prefix):
            continue
        suffix = group[len(prefix):]
        for zone_name in zone_config:
            if suffix.startswith(zone_name):
                return {"name": zone_name, **zone_config[zone_name]}
    return None


def _resolve_role(groups: list[str], role_config: dict, prefix: str) -> dict | None:
    """Resolve user's role from their group memberships.

    Matches groups where the suffix after prefix equals or starts with a role name.
    E.g., groups=["ccwb-consulting"], roles={"consulting": {...}} → returns consulting config.
    """
    for group in groups:
        if not group.startswith(prefix):
            continue
        suffix = group[len(prefix):]
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

    # Mint the Bedrock bearer token by SigV4-presigning CallWithBearerToken.
    # The token inherits the STS session (and therefore the session tags), so it
    # is a per-user credential scoped to the user's zone.
    botocore_creds = Credentials(creds["AccessKeyId"], creds["SecretAccessKey"], creds["SessionToken"])
    request = AWSRequest(
        method="POST",
        url="https://bedrock.amazonaws.com/",
        headers={"host": "bedrock.amazonaws.com"},
        params={"Action": "CallWithBearerToken"},
    )
    SigV4QueryAuth(botocore_creds, "bedrock", region, expires=duration).add_auth(request)
    presigned = request.url.replace("https://", "") + "&Version=1"
    token = "bedrock-api-key-" + base64.b64encode(presigned.encode()).decode()

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

    # Resolve zone → determines region
    resolved_zone = _resolve_zone(groups, zone_config, prefix) if zone_config else None
    inference_region = resolved_zone["region"] if resolved_zone else DEFAULT_INFERENCE_REGION

    # Resolve role → determines models, spend caps, MCP servers
    resolved_role = _resolve_role(groups, role_config, prefix) if role_config else None

    # Determine models: role-specific (with zone prefix) > default list
    if resolved_role and "models" in resolved_role:
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
        "inferenceModels": models,
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

    Expects:
        - GET /config with Authorization: Bearer <token> header

    Returns:
        - 200: Configuration JSON on success
        - 401: Invalid or missing token
        - 403: User not authorized
        - 500: Internal server error
    """
    try:
        # Extract Authorization header
        headers = event.get("headers", {})
        auth_header = headers.get("authorization", headers.get("Authorization", ""))

        if not auth_header:
            return _response(401, {
                "error": "unauthorized",
                "message": "Missing Authorization header",
            })

        # Extract Bearer token
        if not auth_header.startswith("Bearer "):
            return _response(401, {
                "error": "unauthorized",
                "message": "Invalid authorization scheme — expected Bearer token",
            })

        token = auth_header[7:]  # Strip "Bearer " prefix

        # Validate token
        try:
            claims = _validate_token(token)
        except ValueError as e:
            error_msg = str(e)
            # Distinguish between auth errors
            if "expired" in error_msg.lower():
                return _response(401, {
                    "error": "token_expired",
                    "message": "Token has expired — please re-authenticate",
                })
            elif "issuer" in error_msg.lower() or "audience" in error_msg.lower():
                return _response(403, {
                    "error": "forbidden",
                    "message": f"Token validation failed: {error_msg}",
                })
            else:
                return _response(401, {
                    "error": "unauthorized",
                    "message": f"Token validation failed: {error_msg}",
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
