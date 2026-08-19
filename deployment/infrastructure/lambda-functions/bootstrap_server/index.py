# ABOUTME: Lambda handler for the Claude Desktop Bootstrap Server (credential broker)
# ABOUTME: Runs behind an ALB (internal or public). Decodes the user's OIDC token,
# ABOUTME: exchanges it for STS credentials via AssumeRoleWithWebIdentity (session tags
# ABOUTME: intact) — which is what authoritatively validates it — and mints a Bedrock token.

"""Claude Desktop Bootstrap Server — per-user Bedrock bearer-token broker.

Flow per request:
  1. Claude Desktop signs the user into the org OIDC provider (Okta) via PKCE and
     sends the resulting token as `Authorization: Bearer <token>` to GET /config.
  2. This function decodes the token's claims WITHOUT verifying the signature and
     runs a cheap pre-check (issuer / audience / expiry) to fail fast.
  3. It forwards that SAME raw token to STS AssumeRoleWithWebIdentity. Session
     tags (Zone, Project/CostCenter) ride in the token's
     https://aws.amazon.com/tags claim and STS applies them automatically — so
     every existing GDPR Deny and cost-attribution IAM policy fires unchanged.
  4. It mints a short-term Amazon Bedrock bearer token (SigV4 presign of
     CallWithBearerToken) from those credentials and returns it as
     `inferenceBedrockBearerToken`, scoped to the user's zone region.

WHERE IS THE JWT VALIDATION?  (the obvious review question)

This used to sit behind an API Gateway HTTP API whose native JWT authorizer
verified the token before the function ran. That endpoint could not be made
private, so it was replaced by an ALB — and an ALB cannot validate JWTs (its
authenticate-oidc action is a browser-redirect flow, wrong for a bearer-token
API call).

**STS is the authoritative validator.** `AssumeRoleWithWebIdentity` verifies the
token's signature against the IdP's published JWKS, checks `iss` against the IAM
OIDC provider, checks `aud` against that provider's ClientIdList, and enforces
`exp`. A forged, tampered, or expired token is rejected there, so the function
returns 403 and **no credential is ever issued**. Critically, the STS call
happens in `_build_config_response` BEFORE profile discovery and before any
bearer token is minted; the only use of claims prior to that point is local,
side-effect-free computation (zone name, role, session name). A forged claim
therefore buys an attacker nothing — the request dies at STS.

`_precheck_token` is defense in depth and a DoS guard ONLY: it returns a clean
401 and avoids burning an STS call on junk traffic. **Do not treat it as the
security boundary, and do not remove the STS call on the assumption that it is.**

Consequence: no PyJWT/cryptography dependency and no Lambda layer — the function
still runs on nothing but the boto3/botocore that ship in the runtime.

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

def _get_discovery_regions():
    """Regions to scan for zone-tagged application inference profiles.
    Sourced from the profile's allowed_bedrock_regions (comma-separated env),
    falling back to the default region."""
    raw = os.environ.get("DISCOVERY_REGIONS", "")
    regions = [r.strip() for r in raw.split(",") if r.strip()]
    return regions or [DEFAULT_INFERENCE_REGION]

def _get_zone_tag_key():
    return os.environ.get("ZONE_TAG_KEY", "Zone")

def _get_oidc_issuer():
    return os.environ.get("OIDC_ISSUER", "")

def _get_oidc_audience():
    return os.environ.get("OIDC_AUDIENCE", "")

# Tolerance for clock drift between the IdP and Lambda when pre-checking exp/nbf.
_CLOCK_SKEW_SEC = 60


# Zone-discovery cache: {zone_lower: (region, [arns], epoch_seconds)}. Module scope
# so warm Lambda containers reuse it; refreshed when older than _DISCOVERY_TTL.
_DISCOVERY_CACHE = {}
_DISCOVERY_TTL = 300  # 5 minutes


def _discover_zone_profiles(zone, assumed_creds):
    """Discover a zone's application-inference-profiles LIVE, by tag.

    Scans each configured region for APPLICATION inference profiles whose
    `<ZONE_TAG_KEY>` tag equals `zone`, using the user's assumed-role credentials
    (the federated role already grants ListInferenceProfiles/GetInferenceProfile/
    ListTagsForResource). This replaces any static ARN snapshot, so recreated or
    renamed profiles are picked up automatically.

    Returns (region, [profiles]) for the first region that has matching profiles,
    or (None, []) if none found. Each profile is a dict:
      {"arn", "name", "model" (ccwb:Model tag, may be ""), "description"}
    from a single ListInferenceProfiles + ListTagsForResource pass (no extra
    calls). Result cached per-zone for _DISCOVERY_TTL seconds.
    """
    zkey = (zone or "").lower()
    cached = _DISCOVERY_CACHE.get(zkey)
    if cached and (time.time() - cached[2]) < _DISCOVERY_TTL:
        return cached[0], cached[1]

    zone_tag_key = _get_zone_tag_key()
    found_region, found_profiles = None, []
    for region in _get_discovery_regions():
        client = boto3.client(
            "bedrock",
            region_name=region,
            aws_access_key_id=assumed_creds["AccessKeyId"],
            aws_secret_access_key=assumed_creds["SecretAccessKey"],
            aws_session_token=assumed_creds["SessionToken"],
        )
        profiles = []
        try:
            paginator = client.get_paginator("list_inference_profiles")
            pages = paginator.paginate(typeEquals="APPLICATION")
        except Exception:
            # Fall back to a single call if pagination isn't supported
            pages = [client.list_inference_profiles(typeEquals="APPLICATION")]
        for page in pages:
            for prof in page.get("inferenceProfileSummaries", []):
                arn = prof.get("inferenceProfileArn")
                if not arn:
                    continue
                try:
                    tags = client.list_tags_for_resource(resourceARN=arn).get("tags", [])
                except Exception:
                    continue
                tag_map = {t["key"]: t["value"] for t in tags}
                if tag_map.get(zone_tag_key, "").lower() == zkey and prof.get("status", "ACTIVE") == "ACTIVE":
                    profiles.append({
                        "arn": arn,
                        "name": prof.get("inferenceProfileName", "") or "",
                        # ccwb:Model tag is the short model name (e.g. "opus-4-1")
                        # set by `ccwb inference-zone create`; may be absent for
                        # profiles created another way.
                        "model": tag_map.get("ccwb:Model", "") or "",
                        "description": prof.get("description", "") or "",
                    })
        if profiles:
            found_region, found_profiles = region, profiles
            break

    _DISCOVERY_CACHE[zkey] = (found_region, found_profiles, time.time())
    return found_region, found_profiles


# Map a short model name / profile name to the schema's anthropicFamilyTier enum.
_FAMILY_TIERS = ("opus", "sonnet", "haiku", "fable", "mythos")
# Extract "opus" + version from strings like "opus-4-1", "usa-sonnet-4-5",
# "sonnet-5" (major only), "claude-opus-4-1". The minor is OPTIONAL so major-only
# ids (sonnet-5, fable-5) parse. Version parts drive newest-per-family selection.
_MODEL_HINT_RE = re.compile(
    r"(?P<family>opus|sonnet|haiku|fable|mythos)(?:[-.]?(?P<major>\d+))?(?:[-.](?P<minor>\d+))?"
)


def _model_label_and_tier(profile: dict):
    """Derive a friendly label, family tier, and version sort key for a profile.

    Prefers the ccwb:Model tag (e.g. "opus-4-1"), then the profile name
    (e.g. "usa-opus-4-1"). Returns (label, tier_or_None, (major, minor)).
    label falls back to the profile name so the picker never shows a bare ARN.
    Major-only ids render without a trailing ".0" (e.g. "Claude Sonnet 5").
    """
    hint = profile.get("model") or profile.get("name") or ""
    m = _MODEL_HINT_RE.search(hint.lower())
    if not m:
        # No family recognized — use the profile name as the label, no tier.
        return (profile.get("name") or hint or "Model"), None, (0, 0)

    family = m.group("family")
    major = int(m.group("major")) if m.group("major") else 0
    has_minor = m.group("minor") is not None
    minor = int(m.group("minor")) if has_minor else 0
    if not major:
        version = ""
    elif has_minor:
        version = f"{major}.{minor}"
    else:
        version = f"{major}"
    label = f"Claude {family.capitalize()}{(' ' + version) if version else ''}".strip()
    return label, family, (major, minor)


def _supports_1m(tier, ver) -> bool:
    """Whether a model has a native 1M-token context window (per AWS model cards).

    Confirmed native-1M (no beta header): Sonnet 4.6 and Sonnet 5. Sonnet 4.5 and
    earlier are 200K. Opus/Haiku/Fable/Mythos are left unflagged until each is
    verified against its model card — a wrong `supports1m` would misadvertise the
    picker, so this errs on the side of NOT claiming 1M. `ver` is (major, minor);
    a major-only id (e.g. sonnet-5) has minor 0.
    """
    if tier == "sonnet":
        major, minor = ver
        return major > 4 or (major == 4 and minor >= 6)
    return False


def _build_inference_models(profiles: list) -> list:
    """Turn discovered zone profiles into schema-compliant inferenceModels entries.

    Each entry is an object: {name: <ARN>, labelOverride: <friendly>,
    anthropicFamilyTier: <tier>, isFamilyDefault: <newest in family>} so the
    Claude Desktop model picker shows "Claude Opus 4.1" instead of the raw ARN
    (bootstrap-config-v2 schema). The newest version per family tier is marked
    isFamilyDefault. Profiles with an unrecognized family still appear, labeled
    by their profile name.
    """
    enriched = []
    for p in profiles:
        label, tier, ver = _model_label_and_tier(p)
        enriched.append({"arn": p["arn"], "label": label, "tier": tier, "ver": ver})

    # Pick the newest (major, minor) per tier as that family's default.
    newest_by_tier = {}
    for e in enriched:
        if e["tier"] is None:
            continue
        cur = newest_by_tier.get(e["tier"])
        if cur is None or e["ver"] > cur["ver"]:
            newest_by_tier[e["tier"]] = e

    models = []
    for e in enriched:
        entry = {"name": e["arn"], "labelOverride": e["label"]}
        if e["tier"] in _FAMILY_TIERS:
            entry["anthropicFamilyTier"] = e["tier"]
            if newest_by_tier.get(e["tier"]) is e:
                entry["isFamilyDefault"] = True
        # Advertise a native 1M context window where the model card confirms it,
        # so the Claude Desktop picker can surface / prefer the 1M mode.
        if _supports_1m(e["tier"], e["ver"]):
            entry["supports1m"] = True
        models.append(entry)
    return models


def _decode_jwt_claims_unverified(token: str) -> dict:
    """Base64url-decode a JWT's payload WITHOUT verifying its signature.

    Safe here only because STS re-validates the very same token before any
    credential is issued (see the module docstring). Never use the result to make
    an authorization decision that isn't downstream of the STS call.

    Returns {} for anything that isn't a decodable three-part JWT.
    """
    if not token:
        return {}
    parts = token.split(".")
    if len(parts) != 3:
        return {}
    payload = parts[1]
    # base64url, padding stripped by the spec — restore it before decoding.
    payload += "=" * (-len(payload) % 4)
    try:
        decoded = base64.urlsafe_b64decode(payload.encode("ascii"))
        claims = json.loads(decoded)
    except Exception:
        return {}
    if not isinstance(claims, dict):
        return {}
    return claims


def _extract_claims(event: dict) -> dict:
    """Decode the caller's JWT claims from the Authorization header.

    Behind an ALB there is no authorizer to attach pre-validated claims, so we
    decode them ourselves. The `groups` claim may arrive as a real list or as a
    stringified list depending on the provider; normalize it to a list.
    """
    claims = _decode_jwt_claims_unverified(_extract_bearer_token(event))
    claims = dict(claims)
    claims["groups"] = _normalize_groups(claims.get("groups", []))
    return claims


def _precheck_token(claims: dict) -> str | None:
    """Cheap signature-free sanity check on the token. NOT the security boundary.

    Purpose: return a clean 401 and avoid spending an STS call (and its latency)
    on obviously junk or replayed traffic. STS remains the authoritative
    validator — it checks the signature, issuer, audience and expiry itself, so
    passing this function does NOT mean the token is genuine.

    Returns None when the token looks plausible, else a short reason string
    (logged, never returned to the client).
    """
    # `_extract_claims` always injects a normalized "groups" key, so a payload
    # carrying nothing else means the token could not be decoded at all.
    if not claims or set(claims.keys()) <= {"groups"}:
        return "token not decodable"

    if not claims.get("sub"):
        return "no sub claim"

    expected_issuer = _get_oidc_issuer()
    if expected_issuer:
        # Tolerate a trailing slash difference (Auth0 issuers carry one).
        if str(claims.get("iss", "")).rstrip("/") != expected_issuer.rstrip("/"):
            return "issuer mismatch"

    expected_audience = _get_oidc_audience()
    if expected_audience:
        aud = claims.get("aud", "")
        aud_values = aud if isinstance(aud, list) else [aud]
        if expected_audience not in [str(a) for a in aud_values]:
            return "audience mismatch"

    now = int(time.time())
    exp = claims.get("exp")
    if exp is not None:
        try:
            if int(exp) + _CLOCK_SKEW_SEC < now:
                return "token expired"
        except (TypeError, ValueError):
            return "malformed exp claim"

    nbf = claims.get("nbf")
    if nbf is not None:
        try:
            if int(nbf) - _CLOCK_SKEW_SEC > now:
                return "token not yet valid"
        except (TypeError, ValueError):
            return "malformed nbf claim"

    return None


def _normalize_groups(groups):
    """Normalize the multi-valued `groups` claim to a list of strings.

    API Gateway's JWT authorizer flattens a multi-valued claim into a single
    string, and different setups serialize it differently. Observed forms:
      - a real JSON list: ["a", "b"]
      - a bracketed string: "[a, b]"
      - a SPACE-separated string: "Everyone ccwb-usa-Alpha ..."  (Okta access token)
      - a comma-separated string: "a, b"
    Handle all of them; split on commas if present, else on whitespace.
    """
    if isinstance(groups, list):
        return [str(g).strip() for g in groups if str(g).strip()]
    if isinstance(groups, str):
        s = groups.strip()
        if s.startswith("[") and s.endswith("]"):
            s = s[1:-1]
        parts = s.split(",") if "," in s else s.split()
        return [p.strip().strip('"').strip("'") for p in parts if p.strip()]
    return []


def _extract_bearer_token(event: dict) -> str:
    """Return the raw bearer token from the Authorization header.

    Forwarded verbatim to STS as the WebIdentityToken so the session-tag claim is
    applied — and so STS can validate the signature we deliberately don't.

    An ALB lowercases header names (unless multi-value headers are enabled), so
    check both spellings.
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


def _resolve_zone_name(claims: dict, prefix: str) -> str | None:
    """Determine the user's zone name — the SAME value STS uses as the Zone
    session tag, so routing and IAM enforcement always agree.

    Primary source: the token's Zone tag claim
    (https://aws.amazon.com/tags/principal_tags/<ZoneTagKey>) — this is what Okta
    computed and what STS applies. Fallback: parse it from the group name
    (<prefix>-<zone>-<project>) when the tag claim isn't present.

    There is NO configured zone allow-list: the set of valid zones is defined by
    which application inference profiles exist (created via `ccwb inference-zone
    create`, discovered here by tag). Returns the zone name or None.
    """
    zone_tag_key = _get_zone_tag_key()
    # 1. Flat tag claim (Okta access token): https://aws.amazon.com/tags/principal_tags/<key>
    flat = claims.get(f"https://aws.amazon.com/tags/principal_tags/{zone_tag_key}")
    if isinstance(flat, str) and flat.strip():
        return flat.strip()
    # 2. Nested tag claim: {"principal_tags": {"<key>": ["<zone>"]}}
    nested = claims.get("https://aws.amazon.com/tags")
    if isinstance(nested, dict):
        vals = (nested.get("principal_tags") or {}).get(zone_tag_key)
        if isinstance(vals, list) and vals:
            return str(vals[0]).strip()
        if isinstance(vals, str) and vals.strip():
            return vals.strip()
    # 3. Fallback: derive from the group name <prefix>-<zone>-<project>
    for group in claims.get("groups", []) or []:
        suffix = _group_suffix(group, prefix)
        if suffix:
            zone = suffix.split("-")[0]
            if zone:
                return zone
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


def _assume_role_with_token(user_token: str, role_arn: str, claims: dict):
    """Exchange the user's OIDC token for STS credentials via
    AssumeRoleWithWebIdentity. Session tags (Zone/Project) ride in the token's
    https://aws.amazon.com/tags claim and STS applies them automatically.

    Returns the STS Credentials dict (AccessKeyId/SecretAccessKey/SessionToken/
    Expiration). Raises on failure (caller maps to 403).
    """
    duration = _get_max_session_duration()
    # UNSIGNED STS client so the Lambda's own execution-role credentials aren't
    # attached — AssumeRoleWithWebIdentity is authorized by the target role's
    # trust policy + the web-identity token, not the caller.
    sts = boto3.client("sts", config=BotoConfig(signature_version=UNSIGNED))
    resp = sts.assume_role_with_web_identity(
        RoleArn=role_arn,
        RoleSessionName=_derive_session_name(claims),
        WebIdentityToken=user_token,
        DurationSeconds=duration,
    )
    return resp["Credentials"]


def _mint_bedrock_bearer_token_from_creds(creds: dict, region: str):
    """Mint a short-term Bedrock bearer token from STS credentials, byte-for-byte
    matching the official aws-bedrock-token-generator:
      - SigV4-PRESIGN a POST on the GLOBAL host https://bedrock.amazonaws.com/
        with params Action=CallWithBearerToken (service "bedrock", signed for `region`)
      - drop the "https://" scheme, append "&Version=1"
      - STANDARD base64 (WITH "=" padding — url-safe/stripped padding => Bedrock
        "Base64 decoding failed")
      - prepend the literal prefix "bedrock-api-key-"

    Returns (token_string, expiration_epoch_seconds).
    """
    duration = _get_max_session_duration()
    expiration = creds.get("Expiration")
    expiration_epoch = int(expiration.timestamp()) if hasattr(expiration, "timestamp") else int(time.time()) + duration

    botocore_creds = Credentials(creds["AccessKeyId"], creds["SecretAccessKey"], creds["SessionToken"])
    request = AWSRequest(
        method="POST",
        url="https://bedrock.amazonaws.com/",
        headers={"host": "bedrock.amazonaws.com"},
        params={"Action": "CallWithBearerToken"},
    )
    SigV4QueryAuth(botocore_creds, "bedrock", region, expires=duration).add_auth(request)
    presigned_url = request.url.replace("https://", "") + "&Version=1"
    encoded = base64.b64encode(presigned_url.encode("utf-8")).decode("utf-8")
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

    # Read dynamic config from environment at invocation time
    role_config_raw = _get_role_config()
    feature_defaults_raw = _get_feature_defaults()
    prefix = _get_group_prefix()
    role_arn = _get_federated_role_arn()

    role_config = json.loads(role_config_raw) if role_config_raw else {}
    feature_defaults = json.loads(feature_defaults_raw) if feature_defaults_raw else {}

    if not role_arn:
        raise RuntimeError("FEDERATED_ROLE_ARN is not configured on the bootstrap Lambda")

    # The user's zone comes from the token's Zone tag claim (what STS uses as the
    # session tag) — falling back to the group name. There is NO configured zone
    # allow-list: valid zones are exactly the ones with inference profiles created
    # via `ccwb inference-zone create`, discovered below by tag.
    zone_name = _resolve_zone_name(claims, prefix)
    resolved_role = _resolve_role(claims.get("groups", []) or [], role_config, prefix) if role_config else None

    # Exchange the user's token for STS credentials ONCE. Same creds discover the
    # zone's inference profiles and mint the bearer token, so discovery runs as the
    # user (respecting their zone-scoped permissions).
    creds = _assume_role_with_token(user_token, role_arn, claims)

    if zone_name:
        # Discover the zone's application-inference-profiles LIVE by Zone tag,
        # across the configured regions. Region for inference = where they live.
        # No static snapshot => created/recreated/renamed profiles just work.
        discovered_region, discovered_profiles = _discover_zone_profiles(zone_name, creds)
        if not discovered_profiles:
            raise RuntimeError(
                f"No ACTIVE application inference profiles tagged {_get_zone_tag_key()}="
                f"{zone_name!r} found in regions {_get_discovery_regions()}. "
                f"Create it with 'ccwb inference-zone create --zone {zone_name}'."
            )
        inference_region = discovered_region
        # Model entries are objects with a friendly labelOverride + family tier so
        # the picker shows "Claude Opus 4.1", not the raw profile ARN. The ARN is
        # still the invocation identity (entry.name), preserving zone isolation.
        models = _build_inference_models(discovered_profiles)
    elif resolved_role and "models" in resolved_role:
        # Non-isolated role routing: prefix CRIS model ids.
        model_prefix = "us"
        models = [f"{model_prefix}.anthropic.{m}" if not m.startswith(model_prefix) else m
                  for m in resolved_role["models"]]
        inference_region = DEFAULT_INFERENCE_REGION
    else:
        models = [m.strip() for m in DEFAULT_INFERENCE_MODELS.split(",") if m.strip()]
        inference_region = DEFAULT_INFERENCE_REGION

    bearer_token, token_expiry = _mint_bedrock_bearer_token_from_creds(creds, inference_region)

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
    if zone_name:
        config["banner"] = json.dumps({
            "text": f"Claude Desktop — {zone_name.upper()} Zone",
            "backgroundColor": "#1565c0",
            "textColor": "#ffffff",
        })

    return config


def _response(status_code: int, body: dict, extra_headers: dict = None) -> dict:
    """Build an ALB-compatible response.

    An ALB requires `isBase64Encoded`, `statusCode` and `headers`; the body is
    optional. The CORS headers replace the API Gateway CorsConfiguration that
    existed before the switch to an ALB, which has no built-in CORS handling.
    Allow-Origin `*` is safe for this endpoint: it authenticates with a bearer
    token rather than a cookie, so there are no ambient credentials for a
    malicious page to ride on.

    Args:
        status_code: HTTP status code
        body: Response body dict
        extra_headers: Additional headers to include

    Returns:
        ALB target response dict
    """
    headers = {
        "Content-Type": "application/json",
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Headers": "Authorization, Content-Type",
        "Access-Control-Allow-Methods": "GET, OPTIONS",
    }
    if extra_headers:
        headers.update(extra_headers)

    return {
        "isBase64Encoded": False,
        "statusCode": status_code,
        "headers": headers,
        "body": json.dumps(body),
    }


def lambda_handler(event, context):
    """Main Lambda handler for the Bootstrap Server, invoked as an ALB target.

    Token handling: claims are decoded WITHOUT signature verification and screened
    by `_precheck_token` to fail fast, then the raw token is handed to STS, which
    is what actually validates it. See the module docstring — do not mistake the
    pre-check for authentication.

    Returns:
        - 200: Configuration JSON on success
        - 204: CORS preflight
        - 401: Missing or implausible token (pre-check failed)
        - 403: Credential brokering failed (STS deny / misconfig)
        - 500: Internal server error
    """
    try:
        # CORS preflight — the ALB has no built-in CORS handling.
        method = (event.get("httpMethod") or "").upper()
        if method == "OPTIONS":
            return _response(204, {})

        claims = _extract_claims(event)
        token = _extract_bearer_token(event)

        if not token:
            return _response(401, {
                "error": "unauthorized",
                "message": "Missing authenticated identity",
            })

        # Fail fast on junk before spending an STS call. Log the specific reason
        # for operators; return an opaque message so we don't help an attacker
        # tune a token.
        precheck_error = _precheck_token(claims)
        if precheck_error:
            print(f"WARN: Rejecting request in pre-check: {precheck_error}")
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
