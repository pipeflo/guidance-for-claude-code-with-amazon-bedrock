# ABOUTME: Unit tests for the Claude Desktop Bootstrap Server Lambda (bearer-token broker)
# ABOUTME: Tests token validation, STS brokering, zone routing, response format, error handling

"""Tests for the bootstrap_server Lambda handler (credential-broker model).

The broker exchanges the user's OIDC token for STS credentials via
AssumeRoleWithWebIdentity, then mints a Bedrock bearer token. These tests mock
the STS client so no AWS calls are made; they assert the returned config carries
a per-user `inferenceBedrockBearerToken` scoped to the user's zone region.
"""

import json
import os
import sys
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


@pytest.fixture(autouse=True)
def set_env_vars(monkeypatch):
    """Set required environment variables for all tests."""
    # No OIDC validation env vars — the API Gateway JWT authorizer handles that.
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


def _event(claims=None, token="the.user.token"):
    """Build an API Gateway v2 event as the JWT authorizer delivers it:
    validated claims in requestContext.authorizer.jwt.claims, raw token in the
    Authorization header (for the STS broker step)."""
    event = {"headers": {}, "requestContext": {}}
    if token is not None:
        event["headers"]["authorization"] = f"Bearer {token}"
    if claims is not None:
        event["requestContext"]["authorizer"] = {"jwt": {"claims": claims}}
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
    """Patch the handler's boto3.client so STS returns canned credentials.

    Returns the mock STS client so tests can assert on the assume-role call args.
    """
    sts_client = MagicMock()
    sts_client.assume_role_with_web_identity.return_value = _fake_sts_credentials()
    with patch.object(reload_handler.boto3, "client", return_value=sts_client):
        yield sts_client


class TestLambdaHandler:
    """Tests for lambda_handler (authorizer-based auth + response envelope).

    The API Gateway JWT authorizer validates the token before the Lambda runs,
    so these tests deliver claims via requestContext.authorizer.jwt.claims.
    """

    def test_missing_claims_returns_401(self, reload_handler):
        """No authorizer claims on the request → 401 (defense in depth)."""
        response = reload_handler.lambda_handler(_event(claims=None), None)

        assert response["statusCode"] == 401
        body = json.loads(response["body"])
        assert body["error"] == "unauthorized"

    def test_missing_token_returns_401(self, reload_handler):
        """Claims present but no raw token → 401 (can't broker without it)."""
        response = reload_handler.lambda_handler(
            _event(claims={"sub": "user123", "email": "u@ex.com"}, token=None), None
        )

        assert response["statusCode"] == 401

    def test_successful_broker_response(self, reload_handler, mock_sts):
        """Should return 200 with a per-user Bedrock bearer token."""
        event = _event(claims={"sub": "user123", "email": "user@example.com"})
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
        """The raw user token must be passed as WebIdentityToken (session tags ride in it)."""
        event = _event(claims={"sub": "user123", "email": "alice@example.com"}, token="the.user.token")
        reload_handler.lambda_handler(event, None)

        _, kwargs = mock_sts.assume_role_with_web_identity.call_args
        assert kwargs["WebIdentityToken"] == "the.user.token"
        assert kwargs["RoleArn"] == "arn:aws:iam::123456789012:role/BedrockOktaFederatedRole"
        assert kwargs["RoleSessionName"] == "alice@example.com"

    def test_sts_failure_returns_403_without_leak(self, reload_handler):
        """STS/broker failure returns a generic 403 and never leaks the error text."""
        failing_sts = MagicMock()
        failing_sts.assume_role_with_web_identity.side_effect = Exception(
            "AccessDenied: role arn:aws:iam::123456789012:role/Secret not assumable"
        )
        with patch.object(reload_handler.boto3, "client", return_value=failing_sts):
            event = _event(claims={"sub": "user123", "email": "user@example.com"})
            response = reload_handler.lambda_handler(event, None)

        assert response["statusCode"] == 403
        body = json.loads(response["body"])
        assert body["error"] == "forbidden"
        assert "AccessDenied" not in body["message"]
        assert "arn:aws" not in body["message"]

    def test_cache_control_header(self, reload_handler, mock_sts):
        """Should include Cache-Control: no-store in all responses."""
        event = _event(claims={"sub": "user123", "email": "user@example.com"})
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
            event = _event(claims={"sub": "user123", "email": "user@example.com"})
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


class TestExtractClaims:
    """Tests for _extract_claims (reads + normalizes authorizer claims)."""

    def test_reads_claims_from_authorizer_context(self, reload_handler):
        event = _event(claims={"sub": "u1", "email": "u1@ex.com", "groups": ["ccwb-us-a"]})
        claims = reload_handler._extract_claims(event)
        assert claims["sub"] == "u1"
        assert claims["groups"] == ["ccwb-us-a"]

    def test_normalizes_stringified_groups(self, reload_handler):
        """API Gateway may serialize a multi-valued claim as '[a, b]'."""
        event = _event(claims={"sub": "u1", "groups": "[ccwb-us-alpha, ccwb-engineering]"})
        claims = reload_handler._extract_claims(event)
        assert claims["groups"] == ["ccwb-us-alpha", "ccwb-engineering"]

    def test_missing_groups_defaults_empty(self, reload_handler):
        event = _event(claims={"sub": "u1"})
        claims = reload_handler._extract_claims(event)
        assert claims["groups"] == []

    def test_no_authorizer_returns_empty(self, reload_handler):
        claims = reload_handler._extract_claims({"requestContext": {}})
        assert claims.get("sub") is None

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


class TestBuildConfigResponse:
    """Tests for _build_config_response (default / no-zone path)."""

    def test_basic_config_structure(self, reload_handler, mock_sts):
        claims = {"sub": "user1", "email": "user1@example.com"}
        config = reload_handler._build_config_response(claims, "user.token")

        assert config["inferenceProvider"] == "bedrock"
        assert config["inferenceBedrockRegion"] == "us-west-2"
        assert config["inferenceBedrockBearerToken"].startswith("bedrock-api-key-")
        assert isinstance(config["inferenceModels"], list)
        assert config["user"]["sub"] == "user1"

    def test_models_parsed_from_comma_separated(self, reload_handler, mock_sts):
        claims = {"sub": "u", "email": "e"}
        config = reload_handler._build_config_response(claims, "user.token")

        assert len(config["inferenceModels"]) == 2
        assert "us.anthropic.claude-sonnet-4-20250514-v1:0" in config["inferenceModels"]

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
    def zone_env(self, monkeypatch):
        # GDPR shape: each zone carries the real application-inference-profile
        # ARN(s) + the region parsed from the ARN. model_prefix is only used for
        # non-isolated zones that route by CRIS prefix (see test below).
        zone_config = {
            "usa": {
                "region": "us-west-2",
                "models": ["arn:aws:bedrock:us-west-2:123456789012:application-inference-profile/usaaa"],
                "model_prefix": "us",
            },
            "europe": {
                "region": "eu-west-3",
                "models": ["arn:aws:bedrock:eu-west-3:123456789012:application-inference-profile/euuu"],
                "model_prefix": "eu",
            },
        }
        role_config = {
            "consulting": {
                "models": ["claude-opus-4-6-v1:0", "claude-sonnet-4-6-v1:0"],
                "max_tokens_per_window": "5000000",
            },
            "engineering": {
                "models": ["claude-opus-4-6-v1:0", "claude-sonnet-4-6-v1:0", "claude-haiku-4-5-v1:0"],
                "max_tokens_per_window": "10000000",
                "mcp_servers": [{"name": "github", "url": "https://mcp.example.com/github"}],
            },
        }
        feature_defaults = {
            "chatTabEnabled": "true",
            "coworkTabEnabled": "true",
            "isClaudeCodeForDesktopEnabled": "true",
        }
        monkeypatch.setenv("ZONE_CONFIG", json.dumps(zone_config))
        monkeypatch.setenv("ROLE_CONFIG", json.dumps(role_config))
        monkeypatch.setenv("FEATURE_DEFAULTS", json.dumps(feature_defaults))
        monkeypatch.setenv("GROUP_PREFIX", "ccwb-")

    def test_europe_zone_routing(self, reload_handler, zone_env, mock_sts):
        """User in ccwb-europe-beta group gets eu-west-3 region and token signed for it."""
        claims = {"sub": "u1", "email": "u@ex.com", "groups": ["ccwb-europe-beta"]}
        config = reload_handler._build_config_response(claims, "user.token")

        assert config["inferenceBedrockRegion"] == "eu-west-3"
        # boto3.client called with region_name=eu-west-3 for the STS/broker step
        _, kwargs = reload_handler.boto3.client.call_args
        assert kwargs.get("region_name") == "eu-west-3"

    def test_usa_zone_routing(self, reload_handler, zone_env, mock_sts):
        """User in ccwb-usa-alpha group gets the zone's ARN region (us-west-2)."""
        claims = {"sub": "u2", "email": "u2@ex.com", "groups": ["ccwb-usa-alpha"]}
        config = reload_handler._build_config_response(claims, "user.token")

        assert config["inferenceBedrockRegion"] == "us-west-2"

    def test_no_zone_uses_default(self, reload_handler, zone_env, mock_sts):
        """User with no matching zone group gets default region."""
        claims = {"sub": "u3", "email": "u3@ex.com", "groups": ["other-group"]}
        config = reload_handler._build_config_response(claims, "user.token")

        assert config["inferenceBedrockRegion"] == "us-west-2"

    def test_zone_arns_are_authoritative_models_under_isolation(self, reload_handler, zone_env, mock_sts):
        """Under GDPR isolation, zone application-inference-profile ARNs are the
        models — they carry the Zone tag; a role's CRIS models must NOT override."""
        claims = {"sub": "u4", "groups": ["ccwb-europe-beta", "ccwb-consulting"]}
        config = reload_handler._build_config_response(claims, "user.token")

        assert config["inferenceModels"] == [
            "arn:aws:bedrock:eu-west-3:123456789012:application-inference-profile/euuu"
        ]
        # CRIS ids must not leak in
        assert not any("anthropic." in m for m in config["inferenceModels"])

    def test_role_prefix_models_when_zone_has_no_arns(self, reload_handler, monkeypatch, mock_sts):
        """A zone with only model_prefix (no ARNs) falls back to prefixed role models."""
        zone_config = {"apac": {"region": "ap-northeast-1", "model_prefix": "apac"}}
        role_config = {"engineering": {"models": ["claude-opus-4-6-v1:0"]}}
        monkeypatch.setenv("ZONE_CONFIG", json.dumps(zone_config))
        monkeypatch.setenv("ROLE_CONFIG", json.dumps(role_config))
        monkeypatch.setenv("GROUP_PREFIX", "ccwb-")

        claims = {"sub": "u5", "groups": ["ccwb-apac-x", "ccwb-engineering"]}
        config = reload_handler._build_config_response(claims, "user.token")

        assert config["inferenceBedrockRegion"] == "ap-northeast-1"
        assert "apac.anthropic.claude-opus-4-6-v1:0" in config["inferenceModels"]

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
        claims = {"sub": "u9", "groups": []}
        config = reload_handler._build_config_response(claims, "user.token")

        assert config["chatTabEnabled"] == "true"
        assert config["coworkTabEnabled"] == "true"

    def test_zone_banner_set(self, reload_handler, zone_env, mock_sts):
        claims = {"sub": "u10", "groups": ["ccwb-europe-beta"]}
        config = reload_handler._build_config_response(claims, "user.token")

        assert "banner" in config
        banner = json.loads(config["banner"])
        assert "EUROPE" in banner["text"]

    def test_no_banner_without_zone(self, reload_handler, zone_env, mock_sts):
        claims = {"sub": "u11", "groups": ["unrelated"]}
        config = reload_handler._build_config_response(claims, "user.token")

        assert "banner" not in config


class TestBuildClaudeDesktopZoneConfig:
    """Tests for deploy-side derivation of zone_config from inference profiles."""

    def _fn(self):
        from claude_code_with_bedrock.cli.commands.deploy import build_claude_desktop_zone_config

        return build_claude_desktop_zone_config

    def test_derives_region_and_arns_from_profiles(self):
        """Region is parsed from the ARN; models are the actual ARNs."""
        zones = ["us", "eu"]
        zip_map = {
            "us": {"opus-4-6": "arn:aws:bedrock:us-west-2:123456789012:application-inference-profile/uuu"},
            "eu": {"opus-4-6": "arn:aws:bedrock:eu-west-3:123456789012:application-inference-profile/eee"},
        }
        zone_config, skipped = self._fn()(zones, zip_map, "us-east-1")

        assert zone_config["us"]["region"] == "us-west-2"
        assert zone_config["us"]["models"] == [
            "arn:aws:bedrock:us-west-2:123456789012:application-inference-profile/uuu"
        ]
        assert zone_config["eu"]["region"] == "eu-west-3"
        assert skipped == []

    def test_zone_without_profile_is_skipped(self):
        """A declared zone with no inference profile is reported, not silently dropped."""
        zones = ["us", "eu", "ap"]
        zip_map = {
            "us": {"opus-4-6": "arn:aws:bedrock:us-west-2:123456789012:application-inference-profile/uuu"},
            "eu": {"opus-4-6": "arn:aws:bedrock:eu-west-3:123456789012:application-inference-profile/eee"},
        }
        zone_config, skipped = self._fn()(zones, zip_map, "us-east-1")

        assert "ap" not in zone_config
        assert skipped == ["ap"]

    def test_multiple_arns_per_zone_all_included(self):
        """A zone with several model profiles surfaces all of them."""
        zones = ["us"]
        zip_map = {
            "us": {
                "opus-4-6": "arn:aws:bedrock:us-west-2:123456789012:application-inference-profile/a",
                "sonnet-4-5": "arn:aws:bedrock:us-west-2:123456789012:application-inference-profile/b",
            }
        }
        zone_config, _ = self._fn()(zones, zip_map, "us-east-1")

        assert len(zone_config["us"]["models"]) == 2

    def test_empty_inputs(self):
        zone_config, skipped = self._fn()([], {}, "us-east-1")
        assert zone_config == {}
        assert skipped == []
