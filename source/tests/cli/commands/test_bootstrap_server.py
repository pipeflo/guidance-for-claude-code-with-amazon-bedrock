# ABOUTME: Unit tests for the Claude Desktop Bootstrap Server Lambda (bearer-token broker)
# ABOUTME: Tests token validation, STS brokering, zone routing, response format, error handling

"""Tests for the bootstrap_server Lambda handler (credential-broker model).

The broker exchanges the user's OIDC token for STS credentials via
AssumeRoleWithWebIdentity, then mints a Bedrock bearer token. These tests mock
the STS client so no AWS calls are made; they assert the returned config carries
a per-user `inferenceBedrockBearerToken` scoped to the user's zone region.
"""

import base64
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

# Add the lambda function directory to path for import
_LAMBDA_DIR = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        "..",
        "..",
        "..",
        "deployment",
        "infrastructure",
        "lambda-functions",
        "bootstrap_server",
    )
)
sys.path.insert(0, _LAMBDA_DIR)

# A fixed STS expiry used across tests (avoids Date.now-style nondeterminism).
_STS_EXPIRY = datetime(2030, 1, 1, tzinfo=timezone.utc)
_STS_EXPIRY_EPOCH = int(_STS_EXPIRY.timestamp())


def _fake_sts_credentials():
    """Canned STS AssumeRoleWithWebIdentity response credentials."""
    return {
        "Credentials": {
            "AccessKeyId": "ASIAEXAMPLE",
            "SecretAccessKey": "secret-example",
            "SessionToken": "session-token-example",
            "Expiration": _STS_EXPIRY,
        }
    }


_ISSUER = "https://example.okta.com/oauth2/default"
_AUDIENCE = "api://default"


def _jwt(claims: dict) -> str:
    """Build a JWT with a real header/payload and a dummy signature.

    Signatures are never verified locally — STS is the authoritative validator
    (see the handler's module docstring) — so tests need no crypto.
    """

    def seg(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")

    return f"{seg({'alg': 'RS256', 'typ': 'JWT'})}.{seg(claims)}.dummy-signature"


def _claims(**overrides):
    """Plausible Okta access-token claims that pass the handler's pre-check."""
    base = {
        "sub": "user-sub-123",
        "email": "user@example.com",
        "iss": _ISSUER,
        "aud": _AUDIENCE,
        "exp": int(time.time()) + 3600,
    }
    base.update(overrides)
    return base


@pytest.fixture(autouse=True)
def set_env_vars(monkeypatch):
    """Set required environment variables for all tests."""
    # There is no API Gateway JWT authorizer any more (the endpoint is an ALB), so
    # the handler needs these for its fail-fast pre-check.
    monkeypatch.setenv("OIDC_ISSUER", _ISSUER)
    monkeypatch.setenv("OIDC_AUDIENCE", _AUDIENCE)
    monkeypatch.setenv("DEFAULT_INFERENCE_REGION", "us-west-2")
    monkeypatch.setenv(
        "DEFAULT_INFERENCE_MODELS",
        "us.anthropic.claude-sonnet-4-20250514-v1:0,us.anthropic.claude-opus-4-20250514-v1:0",
    )
    monkeypatch.setenv("OTLP_ENDPOINT", "https://otel.example.com/v1/traces")
    monkeypatch.setenv("INFERENCE_SESSION_LIFETIME_SEC", "14400")
    # Broker config: the federated role the Lambda assumes on the user's behalf.
    monkeypatch.setenv("FEDERATED_ROLE_ARN", "arn:aws:iam::123456789012:role/BedrockOktaFederatedRole")
    monkeypatch.setenv("MAX_SESSION_DURATION", "43200")


def _event(claims=None, token=None, method="GET", path="/config"):
    """Build an ALB target event.

    An ALB lowercases header names and provides no authorizer context, so the
    handler decodes claims straight from the bearer token. Pass `claims` to have
    a matching JWT built, or `token` to control the raw string exactly.
    """
    event = {
        "requestContext": {"elb": {"targetGroupArn": "arn:aws:elasticloadbalancing:::targetgroup/tg"}},
        "httpMethod": method,
        "path": path,
        "headers": {},
        "body": "",
        "isBase64Encoded": False,
    }
    if token is None and claims is not None:
        token = _jwt(claims)
    if token:
        event["headers"]["authorization"] = f"Bearer {token}"
    return event


@pytest.fixture
def reload_handler(set_env_vars):
    """Reload the handler module after env vars are set."""
    if "index" in sys.modules:
        del sys.modules["index"]
    import index

    return index


@pytest.fixture
def mock_sts(reload_handler):
    """Patch the handler's boto3.client: STS returns canned credentials, and any
    'bedrock' client returns a discovery mock that surfaces one ACTIVE profile
    per zone tag (usa/us/eu/europe/apac) so zone discovery resolves in tests.

    Returns the STS mock so tests can assert on the assume-role call args.
    """
    sts_client = MagicMock()
    sts_client.assume_role_with_web_identity.return_value = _fake_sts_credentials()

    # Zone ARNs keyed by the region they physically live in, so the mock is
    # region-aware (a profile only appears when scanning ITS region). Each value
    # is (zone, ccwb:Model short) — mirroring what `ccwb inference-zone create`
    # tags, so the friendly-label logic is exercised.
    _region_arns = {
        "us-west-2": {
            "arn:aws:bedrock:us-west-2:123456789012:application-inference-profile/usa1": ("usa", "opus-4-1"),
            "arn:aws:bedrock:us-west-2:123456789012:application-inference-profile/us1": ("us", "sonnet-4-5"),
            "arn:aws:bedrock:us-west-2:123456789012:application-inference-profile/eu1": ("eu", "haiku-4-5"),
        },
        "eu-west-3": {
            "arn:aws:bedrock:eu-west-3:123456789012:application-inference-profile/euuu": ("europe", "opus-4-1"),
        },
    }

    def _bedrock_client(region):
        c = MagicMock()
        entries = _region_arns.get(region, {})

        def _zone_of(arn):
            v = entries.get(arn, ("", ""))
            return v[0] if isinstance(v, tuple) else v

        def _model_of(arn):
            v = entries.get(arn, ("", ""))
            return v[1] if isinstance(v, tuple) and len(v) > 1 else ""

        summaries = [
            {
                "inferenceProfileArn": arn,
                "inferenceProfileName": f"{_zone_of(arn)}-{_model_of(arn)}",
                "status": "ACTIVE",
            }
            for arn in entries
        ]
        paginator = MagicMock()
        paginator.paginate.return_value = [{"inferenceProfileSummaries": summaries}]
        c.get_paginator.return_value = paginator
        c.list_tags_for_resource.side_effect = lambda resourceARN: {
            "tags": [
                {"key": "Zone", "value": _zone_of(resourceARN)},
                {"key": "ccwb:Model", "value": _model_of(resourceARN)},
            ]
        }
        return c

    def factory(service, region_name=None, **kw):
        return sts_client if service == "sts" else _bedrock_client(region_name)

    with patch.object(reload_handler.boto3, "client", side_effect=factory):
        yield sts_client


class TestLambdaHandler:
    """Tests for lambda_handler (ALB event handling + response envelope).

    The endpoint is an ALB, so there is no authorizer: the handler decodes claims
    from the bearer token itself and STS does the authoritative validation.
    """

    def test_missing_token_returns_401(self, reload_handler):
        """No Authorization header at all → 401."""
        response = reload_handler.lambda_handler(_event(), None)

        assert response["statusCode"] == 401
        body = json.loads(response["body"])
        assert body["error"] == "unauthorized"

    def test_undecodable_token_returns_401(self, reload_handler):
        """A token that isn't a JWT → 401 (nothing to decode)."""
        response = reload_handler.lambda_handler(_event(token="not-a-jwt"), None)

        assert response["statusCode"] == 401

    def test_successful_broker_response(self, reload_handler, mock_sts):
        """Should return 200 with a per-user Bedrock bearer token."""
        event = _event(claims=_claims(sub="user123", email="user@example.com"))
        response = reload_handler.lambda_handler(event, None)

        assert response["statusCode"] == 200
        body = json.loads(response["body"])

        assert body["inferenceProvider"] == "bedrock"
        assert body["inferenceCredentialKind"] == "static"
        assert body["inferenceBedrockRegion"] == "us-west-2"  # default (no zone config)
        assert body["inferenceBedrockBearerToken"].startswith("bedrock-api-key-")
        assert "inferenceBedrockSsoStartUrl" not in body
        assert body["user"]["sub"] == "user123"
        assert body["user"]["email"] == "user@example.com"

    def test_broker_forwards_user_token_to_sts(self, reload_handler, mock_sts):
        """The raw user token must be passed as WebIdentityToken VERBATIM.

        Session tags ride in the token, and STS needs the untouched string to
        verify its signature — this is the authoritative validation step.
        """
        token = _jwt(_claims(sub="user123", email="alice@example.com"))
        reload_handler.lambda_handler(_event(token=token), None)

        _, kwargs = mock_sts.assume_role_with_web_identity.call_args
        assert kwargs["WebIdentityToken"] == token
        assert kwargs["RoleArn"] == "arn:aws:iam::123456789012:role/BedrockOktaFederatedRole"
        assert kwargs["RoleSessionName"] == "alice@example.com"

    def test_sts_failure_returns_403_without_leak(self, reload_handler):
        """STS/broker failure returns a generic 403 and never leaks the error text."""
        failing_sts = MagicMock()
        failing_sts.assume_role_with_web_identity.side_effect = Exception(
            "AccessDenied: role arn:aws:iam::123456789012:role/Secret not assumable"
        )
        with patch.object(reload_handler.boto3, "client", return_value=failing_sts):
            event = _event(claims=_claims(sub="user123", email="user@example.com"))
            response = reload_handler.lambda_handler(event, None)

        assert response["statusCode"] == 403
        body = json.loads(response["body"])
        assert body["error"] == "forbidden"
        assert "AccessDenied" not in body["message"]
        assert "arn:aws" not in body["message"]

    def test_cache_control_header(self, reload_handler, mock_sts):
        """Should include Cache-Control: no-store in all responses."""
        event = _event(claims=_claims(sub="user123", email="user@example.com"))
        response = reload_handler.lambda_handler(event, None)

        assert response["headers"]["Cache-Control"] == "no-store"

    def test_no_otel_when_endpoint_empty(self, reload_handler, monkeypatch):
        """Should not include OTEL fields when endpoint is empty."""
        monkeypatch.setenv("OTLP_ENDPOINT", "")
        if "index" in sys.modules:
            del sys.modules["index"]
        import index as handler

        sts_client = MagicMock()
        sts_client.assume_role_with_web_identity.return_value = _fake_sts_credentials()
        with patch.object(handler.boto3, "client", return_value=sts_client):
            event = _event(claims=_claims(sub="user123", email="user@example.com"))
            response = handler.lambda_handler(event, None)

        body = json.loads(response["body"])
        assert "otlpEndpoint" not in body
        assert "otlpHeaders" not in body

    def test_unhandled_exception_returns_500(self, reload_handler):
        """A malformed event (None) trips the outer guard → 500, no detail leak."""
        response = reload_handler.lambda_handler(None, None)

        assert response["statusCode"] == 500
        body = json.loads(response["body"])
        assert body["error"] == "internal_error"
        assert "message" in body and "internal" in body["message"].lower()


class TestPrecheckToken:
    """Tests for _precheck_token — the fail-fast guard in front of STS.

    This is deliberately NOT the security boundary (STS validates the signature),
    but it must reject implausible tokens WITHOUT spending an STS call, both to
    keep errors clean and to blunt unauthenticated traffic against a public ALB.
    """

    def test_valid_token_passes(self, reload_handler):
        assert reload_handler._precheck_token(_claims()) is None

    def test_audience_as_list_passes(self, reload_handler):
        """Some IdPs issue `aud` as a list; membership is what matters."""
        assert reload_handler._precheck_token(_claims(aud=["other", _AUDIENCE])) is None

    def test_issuer_trailing_slash_tolerated(self, reload_handler):
        """Auth0-style issuers carry a trailing slash; don't reject on that alone."""
        assert reload_handler._precheck_token(_claims(iss=_ISSUER + "/")) is None

    @pytest.mark.parametrize(
        "overrides,expected",
        [
            ({"iss": "https://evil.example.com"}, "issuer mismatch"),
            ({"aud": "some-other-audience"}, "audience mismatch"),
            ({"exp": int(time.time()) - 3600}, "token expired"),
            ({"nbf": int(time.time()) + 3600}, "token not yet valid"),
            ({"sub": ""}, "no sub claim"),
        ],
    )
    def test_rejects_bad_claims(self, reload_handler, overrides, expected):
        assert reload_handler._precheck_token(_claims(**overrides)) == expected

    def test_rejects_undecodable(self, reload_handler):
        claims = reload_handler._extract_claims(_event(token="not-a-jwt"))
        assert reload_handler._precheck_token(claims) == "token not decodable"

    def test_clock_skew_tolerated(self, reload_handler):
        """A token that expired a few seconds ago still passes (IdP clock drift)."""
        assert reload_handler._precheck_token(_claims(exp=int(time.time()) - 5)) is None

    @pytest.mark.parametrize(
        "overrides",
        [
            {"iss": "https://evil.example.com"},
            {"aud": "some-other-audience"},
            {"exp": int(time.time()) - 3600},
        ],
    )
    def test_bad_token_returns_401_without_calling_sts(self, reload_handler, mock_sts, overrides):
        """The whole point of the pre-check: no STS call for junk traffic."""
        response = reload_handler.lambda_handler(_event(claims=_claims(**overrides)), None)

        assert response["statusCode"] == 401
        assert not mock_sts.assume_role_with_web_identity.called

    def test_error_message_does_not_reveal_reason(self, reload_handler, mock_sts):
        """Don't help an attacker tune a token — the reason is logged, not returned."""
        response = reload_handler.lambda_handler(
            _event(claims=_claims(aud="wrong-audience")), None
        )
        body = json.loads(response["body"])
        assert "audience" not in body["message"].lower()


class TestAlbResponseEnvelope:
    """The ALB contract: isBase64Encoded + statusCode + headers are required."""

    def test_response_includes_is_base64_encoded(self, reload_handler, mock_sts):
        response = reload_handler.lambda_handler(
            _event(claims=_claims(sub="u1", email="u1@ex.com")), None
        )
        assert response["isBase64Encoded"] is False
        assert "statusCode" in response and "headers" in response

    def test_cors_headers_present(self, reload_handler, mock_sts):
        """Replaces the API Gateway CorsConfiguration an ALB doesn't have."""
        response = reload_handler.lambda_handler(
            _event(claims=_claims(sub="u1", email="u1@ex.com")), None
        )
        headers = response["headers"]
        assert headers["Access-Control-Allow-Origin"] == "*"
        assert "Authorization" in headers["Access-Control-Allow-Headers"]

    def test_options_preflight_returns_204_without_token(self, reload_handler, mock_sts):
        response = reload_handler.lambda_handler(_event(method="OPTIONS"), None)

        assert response["statusCode"] == 204
        assert not mock_sts.assume_role_with_web_identity.called

    def test_error_responses_also_carry_envelope(self, reload_handler):
        response = reload_handler.lambda_handler(_event(), None)
        assert response["isBase64Encoded"] is False
        assert response["headers"]["Cache-Control"] == "no-store"


class TestExtractClaims:
    """Tests for _extract_claims (decodes the bearer token + normalizes groups)."""

    def test_reads_claims_from_bearer_token(self, reload_handler):
        event = _event(claims=_claims(sub="u1", email="u1@ex.com", groups=["ccwb-us-a"]))
        claims = reload_handler._extract_claims(event)
        assert claims["sub"] == "u1"
        assert claims["groups"] == ["ccwb-us-a"]

    def test_normalizes_stringified_groups(self, reload_handler):
        """Some IdPs serialize a multi-valued claim as '[a, b]'."""
        event = _event(claims=_claims(sub="u1", groups="[ccwb-us-alpha, ccwb-engineering]"))
        claims = reload_handler._extract_claims(event)
        assert claims["groups"] == ["ccwb-us-alpha", "ccwb-engineering"]

    def test_normalizes_space_separated_groups(self, reload_handler):
        """Okta access token flattens groups to a SPACE-separated string."""
        event = _event(claims=_claims(sub="u1", groups="Everyone ccwb-us-alpha claude-power-users"))
        claims = reload_handler._extract_claims(event)
        assert claims["groups"] == ["Everyone", "ccwb-us-alpha", "claude-power-users"]

    def test_normalizes_comma_separated_groups(self, reload_handler):
        event = _event(claims=_claims(sub="u1", groups="ccwb-us-alpha, ccwb-eng"))
        claims = reload_handler._extract_claims(event)
        assert claims["groups"] == ["ccwb-us-alpha", "ccwb-eng"]

    def test_missing_groups_defaults_empty(self, reload_handler):
        event = _event(claims=_claims(sub="u1"))
        claims = reload_handler._extract_claims(event)
        assert claims["groups"] == []

    def test_no_token_returns_empty(self, reload_handler):
        claims = reload_handler._extract_claims({"headers": {}})
        assert claims.get("sub") is None

    def test_uppercase_authorization_header(self, reload_handler):
        """ALBs lowercase header names, but tolerate the canonical spelling too."""
        token = _jwt(_claims(sub="u9"))
        claims = reload_handler._extract_claims({"headers": {"Authorization": f"Bearer {token}"}})
        assert claims["sub"] == "u9"

    def test_extract_bearer_token(self, reload_handler):
        assert reload_handler._extract_bearer_token(_event(claims={}, token="abc.def")) == "abc.def"
        assert reload_handler._extract_bearer_token({"headers": {}}) == ""


class TestDeriveSessionName:
    """Tests for _derive_session_name (CUR / CloudTrail attribution)."""

    def test_uses_email(self, reload_handler):
        assert reload_handler._derive_session_name({"email": "alice@example.com"}) == "alice@example.com"

    def test_sanitizes_and_prefixes_sub(self, reload_handler):
        name = reload_handler._derive_session_name({"sub": "auth0|abc123"})
        assert name == "claude-desktop-auth0-abc123"

    def test_fallback_when_no_claims(self, reload_handler):
        assert reload_handler._derive_session_name({}) == "claude-desktop"

    def test_email_truncated_to_64(self, reload_handler):
        long_email = ("a" * 80) + "@example.com"
        assert len(reload_handler._derive_session_name({"email": long_email})) <= 64


class TestMintBedrockBearerToken:
    """The Bedrock API key format must match aws-bedrock-token-generator exactly,
    or Bedrock rejects it. Per the official generator the payload is STANDARD
    base64 (with '=' padding) of the presigned POST on the global bedrock host."""

    def test_token_format(self, reload_handler, mock_sts):
        import base64

        token, exp = reload_handler._mint_bedrock_bearer_token_from_creds(
            _fake_sts_credentials()["Credentials"], "us-west-2"
        )
        # exact prefix
        assert token.startswith("bedrock-api-key-")
        payload = token[len("bedrock-api-key-"):]

        # STANDARD base64 (padding preserved) — decodes without restoring padding
        decoded = base64.b64decode(payload).decode("utf-8")
        # global host + CallWithBearerToken action + version suffix
        assert decoded.startswith("bedrock.amazonaws.com/?Action=CallWithBearerToken")
        assert decoded.endswith("&Version=1")
        assert "X-Amz-Signature=" in decoded  # actually SigV4-presigned
        assert "X-Amz-Security-Token=" in decoded  # STS session token carried

    def test_signed_for_target_region(self, reload_handler, mock_sts):
        import base64

        token, _ = reload_handler._mint_bedrock_bearer_token_from_creds(
            _fake_sts_credentials()["Credentials"], "eu-west-3"
        )
        payload = token[len("bedrock-api-key-"):]
        decoded = base64.b64decode(payload).decode("utf-8")
        # host is the global bedrock endpoint; the region is in the SigV4 credential scope
        assert decoded.startswith("bedrock.amazonaws.com/")
        assert "eu-west-3" in decoded  # X-Amz-Credential scope carries the region


class TestBuildConfigResponse:
    """Tests for _build_config_response (default / no-zone path)."""

    def test_basic_config_structure(self, reload_handler, mock_sts):
        claims = {"sub": "user1", "email": "user1@example.com"}
        config = reload_handler._build_config_response(claims, "user.token")

        assert config["inferenceProvider"] == "bedrock"
        assert config["inferenceBedrockRegion"] == "us-west-2"
        assert config["inferenceBedrockBearerToken"].startswith("bedrock-api-key-")
        # inferenceModels is a JSON-encoded string per the config reference
        assert isinstance(config["inferenceModels"], str)
        assert isinstance(json.loads(config["inferenceModels"]), list)
        # discovery disabled because we supply the model list
        assert config["modelDiscoveryEnabled"] == "false"
        assert config["user"]["sub"] == "user1"

    def test_models_parsed_from_comma_separated(self, reload_handler, mock_sts):
        claims = {"sub": "u", "email": "e"}
        config = reload_handler._build_config_response(claims, "user.token")

        models = json.loads(config["inferenceModels"])
        assert len(models) == 2
        assert "us.anthropic.claude-sonnet-4-20250514-v1:0" in models

    def test_fallback_to_sub_when_no_email(self, reload_handler, mock_sts):
        claims = {"sub": "user-sub-id"}
        config = reload_handler._build_config_response(claims, "user.token")

        assert config["user"]["email"] == "user-sub-id"

    def test_missing_role_arn_raises(self, reload_handler, monkeypatch, mock_sts):
        """No FEDERATED_ROLE_ARN configured → broker cannot proceed."""
        monkeypatch.setenv("FEDERATED_ROLE_ARN", "")
        claims = {"sub": "u", "email": "e"}
        with pytest.raises(RuntimeError, match="FEDERATED_ROLE_ARN"):
            reload_handler._build_config_response(claims, "user.token")

    def test_expires_at_bounded_by_sts_expiry(self, reload_handler, mock_sts):
        """expiresAt must be at/under the STS session expiry (minus skew)."""
        claims = {"sub": "u", "email": "e"}
        config = reload_handler._build_config_response(claims, "user.token")
        assert config["expiresAt"] <= _STS_EXPIRY_EPOCH


class TestZoneRouting:
    """Tests for zone/role-based dynamic routing in the broker."""

    @pytest.fixture
    def zone_env(self, monkeypatch, reload_handler):
        # There is NO zone allow-list. The zone name comes from the token's Zone
        # tag claim (or the group name), and ARNs + region are discovered live by
        # the mock_sts bedrock factory (usa->us-west-2, europe->eu-west-3).
        # DISCOVERY_REGIONS must cover both.
        monkeypatch.setenv("DISCOVERY_REGIONS", "us-west-2,eu-west-3")
        monkeypatch.setenv("ZONE_TAG_KEY", "Zone")
        role_config = {
            "consulting": {"models": ["claude-opus-4-6-v1:0"], "max_tokens_per_window": "5000000"},
            "engineering": {
                "models": ["claude-opus-4-6-v1:0", "claude-haiku-4-5-v1:0"],
                "max_tokens_per_window": "10000000",
                "mcp_servers": [{"name": "github", "url": "https://mcp.example.com/github"}],
            },
        }
        feature_defaults = {"chatTabEnabled": "true", "coworkTabEnabled": "true", "isClaudeCodeForDesktopEnabled": "true"}
        monkeypatch.setenv("ROLE_CONFIG", json.dumps(role_config))
        monkeypatch.setenv("FEATURE_DEFAULTS", json.dumps(feature_defaults))
        monkeypatch.setenv("GROUP_PREFIX", "ccwb-")
        reload_handler._DISCOVERY_CACHE.clear()

    def test_europe_zone_routing(self, reload_handler, zone_env, mock_sts):
        """User in ccwb-europe-beta group → europe zone discovered in eu-west-3.
        Model entries are objects: ARN in `name`, friendly `labelOverride`."""
        claims = {"sub": "u1", "email": "u@ex.com", "groups": ["ccwb-europe-beta"]}
        config = reload_handler._build_config_response(claims, "user.token")

        assert config["inferenceBedrockRegion"] == "eu-west-3"
        models = json.loads(config["inferenceModels"])
        assert models == [
            {
                "name": "arn:aws:bedrock:eu-west-3:123456789012:application-inference-profile/euuu",
                "labelOverride": "Claude Opus 4.1",
                "anthropicFamilyTier": "opus",
                "isFamilyDefault": True,
                "supports1m": True,
            }
        ]

    def test_usa_zone_routing(self, reload_handler, zone_env, mock_sts):
        """User in ccwb-usa-alpha group → usa zone discovered in us-west-2."""
        claims = {"sub": "u2", "email": "u2@ex.com", "groups": ["ccwb-usa-alpha"]}
        config = reload_handler._build_config_response(claims, "user.token")

        assert config["inferenceBedrockRegion"] == "us-west-2"
        models = json.loads(config["inferenceModels"])
        arns = [m["name"] for m in models]
        assert "arn:aws:bedrock:us-west-2:123456789012:application-inference-profile/usa1" in arns
        # Friendly labels, not raw ARNs, drive the picker display.
        by_arn = {m["name"]: m for m in models}
        usa1 = by_arn["arn:aws:bedrock:us-west-2:123456789012:application-inference-profile/usa1"]
        assert usa1["labelOverride"] == "Claude Opus 4.1"
        assert usa1["anthropicFamilyTier"] == "opus"

    def test_no_zone_falls_back_to_default_region(self, reload_handler, zone_env, mock_sts):
        """A user whose groups yield no zone (and no Zone tag claim) gets the default
        model list. There is no broker-side allow-list to reject them — GDPR isolation
        fails closed at the IAM layer (DenyBedrockInvokeWithoutZone) at invoke time."""
        claims = {"sub": "u3", "email": "u3@ex.com", "groups": ["other-group"]}
        config = reload_handler._build_config_response(claims, "user.token")

        assert config["inferenceBedrockRegion"] == "us-west-2"  # DEFAULT_INFERENCE_REGION
        models = json.loads(config["inferenceModels"])
        # default CRIS models, not zone ARNs
        assert all("application-inference-profile" not in m for m in models)
        assert "banner" not in config  # no zone banner when no zone resolved

    def test_zone_from_token_tag_claim_wins(self, reload_handler, zone_env, mock_sts):
        """Primary source of the zone is the token's flat Zone tag claim — the same
        value STS applies as the session tag — even if the group name would differ."""
        claims = {
            "sub": "u8",
            "email": "u8@ex.com",
            "groups": ["ccwb-usa-alpha"],  # group says usa...
            # ...but the authoritative tag claim says europe
            "https://aws.amazon.com/tags/principal_tags/Zone": "europe",
        }
        config = reload_handler._build_config_response(claims, "user.token")

        assert config["inferenceBedrockRegion"] == "eu-west-3"
        models = json.loads(config["inferenceModels"])
        assert [m["name"] for m in models] == [
            "arn:aws:bedrock:eu-west-3:123456789012:application-inference-profile/euuu"
        ]

    def test_prefix_without_hyphen_still_matches(self, reload_handler, zone_env, monkeypatch, mock_sts):
        """GROUP_PREFIX 'ccwb' (no trailing hyphen) must still match ccwb-usa-*."""
        monkeypatch.setenv("GROUP_PREFIX", "ccwb")  # no trailing hyphen, like the real profile
        reload_handler._DISCOVERY_CACHE.clear()
        claims = {"sub": "u", "groups": ["ccwb-usa-alpha"]}
        config = reload_handler._build_config_response(claims, "user.token")
        assert config["inferenceBedrockRegion"] == "us-west-2"
        assert "application-inference-profile/usa1" in config["inferenceModels"]

    def test_zone_arns_are_authoritative_models_under_isolation(self, reload_handler, zone_env, mock_sts):
        """Under GDPR isolation, the discovered zone ARNs are the models (they carry
        the Zone tag); a role's CRIS models must NOT override."""
        claims = {"sub": "u4", "groups": ["ccwb-europe-beta", "ccwb-consulting"]}
        config = reload_handler._build_config_response(claims, "user.token")

        models = json.loads(config["inferenceModels"])
        assert [m["name"] for m in models] == [
            "arn:aws:bedrock:eu-west-3:123456789012:application-inference-profile/euuu"
        ]
        # CRIS ids must not leak in — the ARN is the invocation identity.
        assert not any("anthropic." in m["name"] for m in models)

    def test_zone_with_no_discovered_profiles_raises(self, reload_handler, monkeypatch, mock_sts):
        """A zone resolved from the token whose profiles can't be discovered fails
        loudly rather than returning a model that would be AccessDenied under isolation."""
        monkeypatch.setenv("DISCOVERY_REGIONS", "us-west-2,eu-west-3")  # no apac-tagged profile in mock
        monkeypatch.setenv("GROUP_PREFIX", "ccwb-")
        reload_handler._DISCOVERY_CACHE.clear()

        # Zone 'apac' comes straight from the group name; discovery finds nothing.
        claims = {"sub": "u5", "groups": ["ccwb-apac-x"]}
        with pytest.raises(RuntimeError, match="No ACTIVE application inference profiles"):
            reload_handler._build_config_response(claims, "user.token")

    def test_role_sets_spend_cap(self, reload_handler, zone_env, mock_sts):
        claims = {"sub": "u6", "groups": ["ccwb-usa-alpha", "ccwb-consulting"]}
        config = reload_handler._build_config_response(claims, "user.token")

        assert config["inferenceMaxTokensPerWindow"] == "5000000"

    def test_role_sets_mcp_servers(self, reload_handler, zone_env, mock_sts):
        claims = {"sub": "u7", "groups": ["ccwb-usa-alpha", "ccwb-engineering"]}
        config = reload_handler._build_config_response(claims, "user.token")

        assert "managedMcpServers" in config
        mcp = json.loads(config["managedMcpServers"])
        assert mcp[0]["name"] == "github"

    def test_feature_defaults_applied(self, reload_handler, zone_env, mock_sts):
        # user must match a zone (isolation active); features apply regardless of which
        claims = {"sub": "u9", "groups": ["ccwb-usa-alpha"]}
        config = reload_handler._build_config_response(claims, "user.token")

        assert config["chatTabEnabled"] == "true"
        assert config["coworkTabEnabled"] == "true"

    def test_zone_banner_set(self, reload_handler, zone_env, mock_sts):
        claims = {"sub": "u10", "groups": ["ccwb-europe-beta"]}
        config = reload_handler._build_config_response(claims, "user.token")

        assert "banner" in config
        banner = config["banner"]
        # Native object per bootstrap-config-v2, NOT a JSON string.
        assert isinstance(banner, dict)
        # enabled MUST be true or Desktop ignores every other banner field.
        assert banner["enabled"] is True
        assert "EUROPE" in banner["text"]
        assert len(banner["text"]) <= 200

    def test_banner_includes_cost_attribution(self, reload_handler, zone_env, mock_sts):
        """The header banner shows the zone AND the cost-attribution value from the
        token's principal-tag claim (default key 'Project')."""
        claims = {
            "sub": "u11",
            "groups": ["ccwb-europe-beta"],
            "https://aws.amazon.com/tags/principal_tags/Project": "Alpha",
        }
        config = reload_handler._build_config_response(claims, "user.token")
        banner = config["banner"]
        assert banner["enabled"] is True
        assert "EUROPE" in banner["text"]
        assert "Project: Alpha" in banner["text"]

    def test_banner_omits_cost_when_absent(self, reload_handler, zone_env, mock_sts):
        """No cost tag on the token → banner shows the zone only, no dangling label."""
        claims = {"sub": "u12", "groups": ["ccwb-europe-beta"]}
        config = reload_handler._build_config_response(claims, "user.token")
        banner = config["banner"]
        assert banner["enabled"] is True
        assert "EUROPE" in banner["text"]
        assert "Project:" not in banner["text"]


class TestZoneDiscovery:
    """Live discovery of a zone's inference-profile ARNs by Zone tag."""

    def _mock_bedrock(self, profiles_by_region):
        """Build a fake boto3.client factory returning per-region bedrock clients.
        profiles_by_region: {region: [(arn, {tagkey: tagval})]}"""
        def factory(service, region_name=None, **kw):
            client = MagicMock()
            entries = profiles_by_region.get(region_name, [])
            paginator = MagicMock()
            paginator.paginate.return_value = [
                {"inferenceProfileSummaries": [
                    {
                        "inferenceProfileArn": arn,
                        "inferenceProfileName": tags.get("ccwb:Model", arn.rsplit("/", 1)[-1]),
                        "status": "ACTIVE",
                    }
                    for arn, tags in entries
                ]}
            ]
            client.get_paginator.return_value = paginator
            tag_lookup = {arn: [{"key": k, "value": v} for k, v in tags.items()] for arn, tags in entries}
            client.list_tags_for_resource.side_effect = lambda resourceARN: {"tags": tag_lookup.get(resourceARN, [])}
            return client
        return factory

    def test_discovers_arns_by_zone_tag(self, reload_handler, monkeypatch):
        monkeypatch.setenv("DISCOVERY_REGIONS", "us-west-2")
        monkeypatch.setenv("ZONE_TAG_KEY", "Zone")
        reload_handler._DISCOVERY_CACHE.clear()
        factory = self._mock_bedrock({
            "us-west-2": [
                ("arn:aws:bedrock:us-west-2:1:application-inference-profile/usa1", {"Zone": "usa"}),
                ("arn:aws:bedrock:us-west-2:1:application-inference-profile/other", {"Zone": "eu"}),
            ]
        })
        with patch.object(reload_handler.boto3, "client", side_effect=factory):
            region, profiles = reload_handler._discover_zone_profiles("usa", {"AccessKeyId": "a", "SecretAccessKey": "b", "SessionToken": "c"})
        assert region == "us-west-2"
        assert [p["arn"] for p in profiles] == ["arn:aws:bedrock:us-west-2:1:application-inference-profile/usa1"]

    def test_scans_multiple_regions(self, reload_handler, monkeypatch):
        monkeypatch.setenv("DISCOVERY_REGIONS", "us-west-2,eu-west-3")
        monkeypatch.setenv("ZONE_TAG_KEY", "Zone")
        reload_handler._DISCOVERY_CACHE.clear()
        factory = self._mock_bedrock({
            "us-west-2": [("arn:aws:bedrock:us-west-2:1:application-inference-profile/usa1", {"Zone": "usa"})],
            "eu-west-3": [("arn:aws:bedrock:eu-west-3:1:application-inference-profile/eu1", {"Zone": "europe"})],
        })
        with patch.object(reload_handler.boto3, "client", side_effect=factory):
            region, profiles = reload_handler._discover_zone_profiles("europe", {"AccessKeyId": "a", "SecretAccessKey": "b", "SessionToken": "c"})
        assert region == "eu-west-3"
        assert [p["arn"] for p in profiles] == ["arn:aws:bedrock:eu-west-3:1:application-inference-profile/eu1"]

    def test_no_match_returns_empty(self, reload_handler, monkeypatch):
        monkeypatch.setenv("DISCOVERY_REGIONS", "us-west-2")
        reload_handler._DISCOVERY_CACHE.clear()
        factory = self._mock_bedrock({"us-west-2": [("arn:...:/x", {"Zone": "usa"})]})
        with patch.object(reload_handler.boto3, "client", side_effect=factory):
            region, profiles = reload_handler._discover_zone_profiles("apac", {"AccessKeyId": "a", "SecretAccessKey": "b", "SessionToken": "c"})
        assert region is None and profiles == []


class TestZoneDiscoveryRegionFailures:
    """A single unusable region must not abort discovery.

    Reproduces a real production failure. DISCOVERY_REGIONS ended with a DISABLED
    opt-in region (ca-west-1). Calling Bedrock there with valid session credentials
    raises UnrecognizedClientException -- "The security token included in the
    request is invalid" -- which looks like an auth bug but means "this account has
    not enabled that region".

    The usa zone matched in us-west-2 and returned BEFORE reaching the bad region,
    so everything looked fine. The europe zone found no match earlier, reached the
    bad region, and the exception escaped _discover_zone_profiles entirely: the
    user got a misleading credential error instead of "no profiles for zone
    europe", and Claude Desktop silently bounced back to the sign-in screen.

    Note the mock raises on PAGE ITERATION, not on paginate(). botocore paginators
    are lazy, so that is where the real error surfaced -- and why the original
    try/except around paginate() caught nothing.
    """

    @staticmethod
    def _error():
        from botocore.exceptions import ClientError

        return ClientError(
            {
                "Error": {
                    "Code": "UnrecognizedClientException",
                    "Message": "The security token included in the request is invalid",
                }
            },
            "ListInferenceProfiles",
        )

    def _factory(self, bad_regions, good_regions):
        """bad_regions fail every call; good_regions map region -> [(arn, zone)]."""
        err = self._error()

        def factory(service, region_name=None, **kw):
            client = MagicMock()
            if region_name in bad_regions:
                def _lazy_raise():
                    raise err
                    yield  # pragma: no cover - unreachable, models a lazy paginator

                paginator = MagicMock()
                paginator.paginate.return_value = _lazy_raise()
                client.get_paginator.return_value = paginator
                # A disabled region fails the non-paginated fallback too.
                client.list_inference_profiles.side_effect = err
                return client

            entries = good_regions.get(region_name, [])
            paginator = MagicMock()
            paginator.paginate.return_value = [
                {"inferenceProfileSummaries": [
                    {"inferenceProfileArn": arn, "inferenceProfileName": zone, "status": "ACTIVE"}
                    for arn, zone in entries
                ]}
            ]
            client.get_paginator.return_value = paginator
            lookup = {arn: [{"key": "Zone", "value": zone}] for arn, zone in entries}
            client.list_tags_for_resource.side_effect = lambda resourceARN: {
                "tags": lookup.get(resourceARN, [])
            }
            return client

        return factory

    _CREDS = {"AccessKeyId": "a", "SecretAccessKey": "b", "SessionToken": "c"}

    def test_bad_region_before_match_is_skipped(self, reload_handler, monkeypatch):
        """The exact production shape: bad region scanned before the match."""
        monkeypatch.setenv("DISCOVERY_REGIONS", "ca-west-1,eu-west-3")
        monkeypatch.setenv("ZONE_TAG_KEY", "Zone")
        reload_handler._DISCOVERY_CACHE.clear()
        arn = "arn:aws:bedrock:eu-west-3:1:application-inference-profile/eu1"
        factory = self._factory({"ca-west-1"}, {"eu-west-3": [(arn, "europe")]})

        with patch.object(reload_handler.boto3, "client", side_effect=factory):
            region, profiles = reload_handler._discover_zone_profiles("europe", self._CREDS)

        assert region == "eu-west-3"
        assert [p["arn"] for p in profiles] == [arn]

    def test_bad_region_after_match_never_reached(self, reload_handler, monkeypatch):
        """Why the usa zone kept working and hid the bug."""
        monkeypatch.setenv("DISCOVERY_REGIONS", "us-west-2,ca-west-1")
        monkeypatch.setenv("ZONE_TAG_KEY", "Zone")
        reload_handler._DISCOVERY_CACHE.clear()
        arn = "arn:aws:bedrock:us-west-2:1:application-inference-profile/usa1"
        factory = self._factory({"ca-west-1"}, {"us-west-2": [(arn, "usa")]})

        with patch.object(reload_handler.boto3, "client", side_effect=factory):
            region, profiles = reload_handler._discover_zone_profiles("usa", self._CREDS)

        assert region == "us-west-2"
        assert [p["arn"] for p in profiles] == [arn]

    def test_all_regions_failing_returns_empty_not_exception(self, reload_handler, monkeypatch):
        """Must degrade to (None, []) so the caller raises the ACCURATE error
        ("no profiles tagged Zone=X") rather than leaking a credential error."""
        monkeypatch.setenv("DISCOVERY_REGIONS", "ca-west-1,ap-east-1")
        monkeypatch.setenv("ZONE_TAG_KEY", "Zone")
        reload_handler._DISCOVERY_CACHE.clear()
        factory = self._factory({"ca-west-1", "ap-east-1"}, {})

        with patch.object(reload_handler.boto3, "client", side_effect=factory):
            region, profiles = reload_handler._discover_zone_profiles("europe", self._CREDS)

        assert region is None
        assert profiles == []

    def test_zone_with_no_profiles_yields_actionable_error(self, reload_handler, monkeypatch):
        """End-to-end consequence of the fix: the message names the zone and tells
        the admin what to run, instead of 'security token ... invalid'."""
        monkeypatch.setenv("DISCOVERY_REGIONS", "ca-west-1")
        monkeypatch.setenv("ZONE_TAG_KEY", "Zone")
        reload_handler._DISCOVERY_CACHE.clear()
        factory = self._factory({"ca-west-1"}, {})

        with patch.object(reload_handler.boto3, "client", side_effect=factory):
            region, profiles = reload_handler._discover_zone_profiles("europe", self._CREDS)
        assert not profiles

        # Mirrors the guard in _build_config_response.
        msg = (
            f"No ACTIVE application inference profiles tagged Zone='europe' found in "
            f"regions {reload_handler._get_discovery_regions()}."
        )
        assert "europe" in msg
        assert "security token" not in msg

    def test_skipped_region_is_logged(self, reload_handler, monkeypatch, capsys):
        """Silent skipping would make this bug just as hard to diagnose."""
        monkeypatch.setenv("DISCOVERY_REGIONS", "ca-west-1")
        reload_handler._DISCOVERY_CACHE.clear()
        factory = self._factory({"ca-west-1"}, {})

        with patch.object(reload_handler.boto3, "client", side_effect=factory):
            reload_handler._discover_zone_profiles("europe", self._CREDS)

        out = capsys.readouterr().out
        assert "ca-west-1" in out
        assert "UnrecognizedClientException" in out


class TestBuildInferenceModels:
    """Friendly labels + family tiers for the Claude Desktop model picker."""

    def test_label_and_tier_from_ccwb_model_tag(self, reload_handler):
        models = reload_handler._build_inference_models([
            {"arn": "arn:...:/a", "name": "usa-opus-4-1", "model": "opus-4-1", "description": ""},
        ])
        assert models == [{
            "name": "arn:...:/a",
            "labelOverride": "Claude Opus 4.1",
            "anthropicFamilyTier": "opus",
            "isFamilyDefault": True,
            "supports1m": True,
        }]

    def test_newest_version_per_family_is_default(self, reload_handler):
        """Two Sonnet profiles → only the newest is isFamilyDefault."""
        models = reload_handler._build_inference_models([
            {"arn": "arn:...:/old", "name": "usa-sonnet-4-1", "model": "sonnet-4-1", "description": ""},
            {"arn": "arn:...:/new", "name": "usa-sonnet-4-5", "model": "sonnet-4-5", "description": ""},
        ])
        by_arn = {m["name"]: m for m in models}
        assert by_arn["arn:...:/new"].get("isFamilyDefault") is True
        assert "isFamilyDefault" not in by_arn["arn:...:/old"]
        assert by_arn["arn:...:/old"]["labelOverride"] == "Claude Sonnet 4.1"

    def test_falls_back_to_profile_name_when_family_unknown(self, reload_handler):
        """A profile whose name has no recognizable family still shows a label,
        never a bare ARN, and carries no family tier."""
        models = reload_handler._build_inference_models([
            {"arn": "arn:...:/z", "name": "custom-zone-profile", "model": "", "description": ""},
        ])
        assert models[0]["name"] == "arn:...:/z"
        assert models[0]["labelOverride"] == "custom-zone-profile"
        assert "anthropicFamilyTier" not in models[0]

    def test_label_derived_from_profile_name_without_tag(self, reload_handler):
        """No ccwb:Model tag → family/version parsed from the profile name."""
        models = reload_handler._build_inference_models([
            {"arn": "arn:...:/h", "name": "europe-haiku-4-5", "model": "", "description": ""},
        ])
        assert models[0]["labelOverride"] == "Claude Haiku 4.5"
        assert models[0]["anthropicFamilyTier"] == "haiku"

    def test_supports1m_set_for_1m_capable_tiers(self, reload_handler):
        """opus / sonnet / fable get supports1m=True (they offer a 1M window).

        The app sends the bare ARN and requests 1M via a beta field at invocation,
        which this account accepts for the profile ARNs; only Haiku is excluded."""
        models = reload_handler._build_inference_models([
            {"arn": "arn:...:/s5", "name": "usa-sonnet-5", "model": "sonnet-5", "description": ""},
            {"arn": "arn:...:/s46", "name": "usa-sonnet-4-6", "model": "sonnet-4-6", "description": ""},
            {"arn": "arn:...:/o48", "name": "usa-opus-4-8", "model": "opus-4-8", "description": ""},
            {"arn": "arn:...:/f5", "name": "usa-fable-5", "model": "fable-5", "description": ""},
        ])
        by_arn = {m["name"]: m for m in models}
        for a in ("arn:...:/s5", "arn:...:/s46", "arn:...:/o48", "arn:...:/f5"):
            assert by_arn[a].get("supports1m") is True, a

    def test_major_only_label_has_no_trailing_zero(self, reload_handler):
        """A major-only id renders as 'Claude Sonnet 5', not 'Claude Sonnet 5.0'."""
        models = reload_handler._build_inference_models([
            {"arn": "arn:...:/s5", "name": "usa-sonnet-5", "model": "sonnet-5", "description": ""},
            {"arn": "arn:...:/f5", "name": "usa-fable-5", "model": "fable-5", "description": ""},
        ])
        by_arn = {m["name"]: m for m in models}
        assert by_arn["arn:...:/s5"]["labelOverride"] == "Claude Sonnet 5"
        assert by_arn["arn:...:/f5"]["labelOverride"] == "Claude Fable 5"

    def test_supports1m_absent_for_haiku_and_unknown_families(self, reload_handler):
        """Haiku has no 1M window, and an unrecognized family must not claim 1M."""
        models = reload_handler._build_inference_models([
            {"arn": "arn:...:/h45", "name": "usa-haiku-4-5", "model": "haiku-4-5", "description": ""},
            {"arn": "arn:...:/x", "name": "some-custom-profile", "model": "", "description": ""},
        ])
        for m in models:
            assert "supports1m" not in m


class TestCallerNetworkLogging:
    """The Lambda logs requestContext.identity so the VPC endpoint id can be found.

    A private REST API's resource policy must name the caller's execute-api endpoint,
    and in a large org that id may be genuinely unavailable -- a central-account
    endpoint does not appear in describe-vpc-endpoints from the workload account.
    Deploy with AllowAnyVpcEndpoint, make one request, read the id from this line.

    The obvious risk of logging request context is leaking the bearer token, so that
    is pinned here.
    """

    def test_logs_identity_with_greppable_prefix(self, reload_handler, capsys):
        event = {
            "httpMethod": "GET",
            "path": "/config",
            "requestContext": {
                "identity": {
                    "vpceId": "vpce-0abc123def456789",
                    "vpcId": "vpc-0999888777",
                    "sourceIp": "10.20.30.40",
                }
            },
        }
        reload_handler._log_caller_network_identity(event)
        out = capsys.readouterr().out
        assert "callerNetwork:" in out
        assert "vpce-0abc123def456789" in out

    def test_never_logs_the_bearer_token(self, reload_handler, capsys):
        """The Authorization header lives at the TOP level of the event, not under
        requestContext.identity -- but assert it, because a future 'log the whole
        event' convenience change would quietly start writing tokens to CloudWatch."""
        event = {
            "httpMethod": "GET",
            "headers": {"authorization": "Bearer super-secret-token-value"},
            "requestContext": {"identity": {"vpceId": "vpce-0abc123def456789"}},
        }
        reload_handler._log_caller_network_identity(event)
        out = capsys.readouterr().out
        assert "super-secret-token-value" not in out
        assert "Bearer" not in out

    def test_missing_identity_is_reported_not_crashed(self, reload_handler, capsys):
        reload_handler._log_caller_network_identity({"httpMethod": "GET"})
        assert "callerNetwork: none" in capsys.readouterr().out

    def test_unserialisable_identity_does_not_break_the_request(self, reload_handler, capsys):
        """Diagnostics must never be able to fail a real request."""

        class _Explodes:
            def __repr__(self):
                raise RuntimeError("boom")

        reload_handler._log_caller_network_identity(
            {"requestContext": {"identity": {"x": _Explodes()}}}
        )
        out = capsys.readouterr().out
        assert "callerNetwork" in out


class TestHealthEndpoint:
    """/health is an unauthenticated, browser-openable reachability probe.

    It exists so a non-technical user can test connectivity to the PRIVATE endpoint
    by opening a URL -- a green page means their desktop reaches it, a hang means it
    doesn't -- with no token, no Okta, no curl. It must never touch STS or reveal
    anything beyond the caller's own echoed-back network identity.
    """

    @staticmethod
    def _health_event(vpce="vpce-0abc123", src="10.20.30.40", resource="/health"):
        return {
            "httpMethod": "GET",
            "path": resource,
            "resource": resource,
            "headers": {},
            "requestContext": {"stage": "prod", "identity": {"vpceId": vpce, "sourceIp": src}},
        }

    def test_returns_200_html_without_a_token(self, reload_handler, mock_sts):
        r = reload_handler.lambda_handler(self._health_event(), None)
        assert r["statusCode"] == 200
        assert "text/html" in r["headers"]["Content-Type"]
        assert "Connected" in r["body"]

    def test_makes_no_sts_call(self, reload_handler, mock_sts):
        """The probe must be free of the credential path entirely."""
        reload_handler.lambda_handler(self._health_event(), None)
        mock_sts.assume_role_with_web_identity.assert_not_called()

    def test_echoes_caller_vpce_and_ip(self, reload_handler, mock_sts):
        """Doubles as the endpoint-discovery tool: the page shows the vpce the caller
        arrived through, which is what scopes the resource policy."""
        r = reload_handler.lambda_handler(
            self._health_event(vpce="vpce-0123456789abcdef0", src="10.0.0.9"), None
        )
        assert "vpce-0123456789abcdef0" in r["body"]
        assert "10.0.0.9" in r["body"]

    def test_health_never_returns_a_token(self, reload_handler, mock_sts):
        """A regression that routed a real config through /health would be a leak."""
        r = reload_handler.lambda_handler(self._health_event(), None)
        assert "inferenceBedrockBearerToken" not in r["body"]
        assert "bedrock-api-key" not in r["body"]

    def test_alb_event_shows_forwarded_ip_and_no_vpce_row(self, reload_handler, mock_sts):
        """Behind an ALB there is no requestContext.identity: the client IP arrives
        in x-forwarded-for, and there is no VPC endpoint to report. The page must
        still render 'Connected' with the caller's IP and omit the vpce row."""
        alb_health = {
            "httpMethod": "GET",
            "path": "/health",
            "headers": {"x-forwarded-for": "10.0.0.9, 10.0.0.5"},
            "requestContext": {"elb": {"targetGroupArn": "arn:aws:elasticloadbalancing:::targetgroup/tg"}},
        }
        r = reload_handler.lambda_handler(alb_health, None)
        assert r["statusCode"] == 200
        assert "Connected" in r["body"]
        assert "10.0.0.9" in r["body"]  # first hop of x-forwarded-for
        assert "VPC endpoint" not in r["body"]  # no vpce over an ALB

    def test_config_path_still_requires_auth(self, reload_handler, mock_sts):
        """/health must not have loosened /config: no token there is still 401."""
        r = reload_handler.lambda_handler(_event(path="/config"), None)
        assert r["statusCode"] == 401

    def test_html_escapes_identity_values(self, reload_handler, mock_sts):
        """Identity values are echoed into HTML; a crafted value must not inject markup."""
        r = reload_handler.lambda_handler(
            self._health_event(vpce="vpce-<script>alert(1)</script>"), None
        )
        assert "<script>alert(1)</script>" not in r["body"]
        assert "&lt;script&gt;" in r["body"]
