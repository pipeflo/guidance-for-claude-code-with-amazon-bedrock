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
    monkeypatch.setenv("OIDC_ISSUER_URL", "https://example.okta.com/oauth2/default")
    monkeypatch.setenv("OIDC_CLIENT_ID", "test-client-id")
    monkeypatch.setenv("OIDC_JWKS_ENDPOINT", "https://example.okta.com/oauth2/default/v1/keys")
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
    """Tests for lambda_handler function (auth + response envelope)."""

    def test_missing_authorization_header(self, reload_handler):
        """Should return 401 when Authorization header is missing."""
        event = {"headers": {}}
        response = reload_handler.lambda_handler(event, None)

        assert response["statusCode"] == 401
        body = json.loads(response["body"])
        assert body["error"] == "unauthorized"
        assert "Missing Authorization header" in body["message"]

    def test_invalid_auth_scheme(self, reload_handler):
        """Should return 401 when auth scheme is not Bearer."""
        event = {"headers": {"authorization": "Basic dXNlcjpwYXNz"}}
        response = reload_handler.lambda_handler(event, None)

        assert response["statusCode"] == 401
        body = json.loads(response["body"])
        assert body["error"] == "unauthorized"
        assert "Bearer" in body["message"]

    @patch("index._validate_token")
    def test_expired_token(self, mock_validate, reload_handler):
        """Should return 401 with token_expired error for expired tokens."""
        mock_validate.side_effect = ValueError("Token has expired")

        event = {"headers": {"authorization": "Bearer expired.token.here"}}
        response = reload_handler.lambda_handler(event, None)

        assert response["statusCode"] == 401
        body = json.loads(response["body"])
        assert body["error"] == "token_expired"

    @patch("index._validate_token")
    def test_invalid_issuer(self, mock_validate, reload_handler):
        """Should return 403 for invalid issuer."""
        mock_validate.side_effect = ValueError("Invalid token issuer")

        event = {"headers": {"authorization": "Bearer bad.issuer.token"}}
        response = reload_handler.lambda_handler(event, None)

        assert response["statusCode"] == 403
        body = json.loads(response["body"])
        assert body["error"] == "forbidden"

    @patch("index._validate_token")
    def test_invalid_audience(self, mock_validate, reload_handler):
        """Should return 403 for invalid audience."""
        mock_validate.side_effect = ValueError("Invalid token audience")

        event = {"headers": {"authorization": "Bearer bad.audience.token"}}
        response = reload_handler.lambda_handler(event, None)

        assert response["statusCode"] == 403
        body = json.loads(response["body"])
        assert body["error"] == "forbidden"

    @patch("index._validate_token")
    def test_invalid_signature(self, mock_validate, reload_handler):
        """Should return 401 for invalid signature."""
        mock_validate.side_effect = ValueError("Invalid token signature")

        event = {"headers": {"authorization": "Bearer bad.sig.token"}}
        response = reload_handler.lambda_handler(event, None)

        assert response["statusCode"] == 401
        body = json.loads(response["body"])
        assert body["error"] == "unauthorized"

    @patch("index._validate_token")
    def test_successful_broker_response(self, mock_validate, reload_handler, mock_sts):
        """Should return 200 with a per-user Bedrock bearer token for a valid token."""
        mock_validate.return_value = {
            "sub": "user123",
            "email": "user@example.com",
            "iss": "https://example.okta.com/oauth2/default",
            "aud": "test-client-id",
        }

        event = {"headers": {"authorization": "Bearer valid.token.here"}}
        response = reload_handler.lambda_handler(event, None)

        assert response["statusCode"] == 200
        body = json.loads(response["body"])

        assert body["inferenceProvider"] == "bedrock"
        assert body["inferenceCredentialKind"] == "static"
        assert body["inferenceBedrockRegion"] == "us-west-2"  # default (no zone config)
        assert body["inferenceBedrockBearerToken"].startswith("bedrock-api-key-")
        # No IAM Identity Center fields in the broker model
        assert "inferenceBedrockSsoStartUrl" not in body
        assert body["user"]["sub"] == "user123"
        assert body["user"]["email"] == "user@example.com"

    @patch("index._validate_token")
    def test_broker_forwards_user_token_to_sts(self, mock_validate, reload_handler, mock_sts):
        """The raw user token must be passed as WebIdentityToken (session tags ride in it)."""
        mock_validate.return_value = {"sub": "user123", "email": "alice@example.com"}

        event = {"headers": {"authorization": "Bearer the.user.token"}}
        reload_handler.lambda_handler(event, None)

        _, kwargs = mock_sts.assume_role_with_web_identity.call_args
        assert kwargs["WebIdentityToken"] == "the.user.token"
        assert kwargs["RoleArn"] == "arn:aws:iam::123456789012:role/BedrockOktaFederatedRole"
        # RoleSessionName derived from email for CUR attribution
        assert kwargs["RoleSessionName"] == "alice@example.com"

    @patch("index._validate_token")
    def test_sts_failure_returns_403_without_leak(self, mock_validate, reload_handler):
        """STS/broker failure returns a generic 403 and never leaks the error text."""
        mock_validate.return_value = {"sub": "user123", "email": "user@example.com"}

        failing_sts = MagicMock()
        failing_sts.assume_role_with_web_identity.side_effect = Exception(
            "AccessDenied: role arn:aws:iam::123456789012:role/Secret not assumable"
        )
        with patch.object(reload_handler.boto3, "client", return_value=failing_sts):
            event = {"headers": {"authorization": "Bearer valid.token.here"}}
            response = reload_handler.lambda_handler(event, None)

        assert response["statusCode"] == 403
        body = json.loads(response["body"])
        assert body["error"] == "forbidden"
        assert "AccessDenied" not in body["message"]
        assert "arn:aws" not in body["message"]

    @patch("index._validate_token")
    def test_cache_control_header(self, mock_validate, reload_handler, mock_sts):
        """Should include Cache-Control: no-store in all responses."""
        mock_validate.return_value = {"sub": "user123", "email": "user@example.com"}

        event = {"headers": {"authorization": "Bearer valid.token.here"}}
        response = reload_handler.lambda_handler(event, None)

        assert response["headers"]["Cache-Control"] == "no-store"

    @patch("index._validate_token")
    def test_content_type_header(self, mock_validate, reload_handler, mock_sts):
        """Should return application/json content type."""
        mock_validate.return_value = {"sub": "user123", "email": "user@example.com"}

        event = {"headers": {"authorization": "Bearer valid.token.here"}}
        response = reload_handler.lambda_handler(event, None)

        assert response["headers"]["Content-Type"] == "application/json"

    @patch("index._validate_token")
    def test_no_otel_when_endpoint_empty(self, mock_validate, reload_handler, monkeypatch):
        """Should not include OTEL fields when endpoint is empty."""
        monkeypatch.setenv("OTLP_ENDPOINT", "")
        if "index" in sys.modules:
            del sys.modules["index"]
        import index as handler

        sts_client = MagicMock()
        sts_client.assume_role_with_web_identity.return_value = _fake_sts_credentials()

        mock_validate_new = MagicMock(return_value={"sub": "user123", "email": "user@example.com"})
        with patch.object(handler, "_validate_token", mock_validate_new), patch.object(
            handler.boto3, "client", return_value=sts_client
        ):
            event = {"headers": {"authorization": "Bearer valid.token.here"}}
            response = handler.lambda_handler(event, None)

        body = json.loads(response["body"])
        assert "otlpEndpoint" not in body
        assert "otlpHeaders" not in body

    def test_unhandled_exception_returns_500(self, reload_handler):
        """Should return 500 for unhandled exceptions without leaking details."""
        with patch.object(reload_handler, "_validate_token", side_effect=RuntimeError("unexpected")):
            event = {"headers": {"authorization": "Bearer valid.token.here"}}
            response = reload_handler.lambda_handler(event, None)

            assert response["statusCode"] == 500
            body = json.loads(response["body"])
            assert body["error"] == "internal_error"
            assert "unexpected" not in body["message"]

    def test_authorization_header_case_insensitive(self, reload_handler):
        """Should handle Authorization header in different cases."""
        event = {"headers": {"Authorization": ""}}
        response = reload_handler.lambda_handler(event, None)

        assert response["statusCode"] == 401


class TestValidateToken:
    """Tests for _validate_token function."""

    def test_empty_token_raises(self, reload_handler):
        """Should raise ValueError for empty token."""
        with pytest.raises(ValueError, match="No token provided"):
            reload_handler._validate_token("")

    def test_none_token_raises(self, reload_handler):
        """Should raise ValueError for None token."""
        with pytest.raises(ValueError, match="No token provided"):
            reload_handler._validate_token(None)

    def test_no_pyjwt_raises(self, reload_handler):
        """Should raise ValueError when PyJWT is not available."""
        reload_handler.HAS_PYJWT = False
        with pytest.raises(ValueError, match="PyJWT library not available"):
            reload_handler._validate_token("some.token.here")
        reload_handler.HAS_PYJWT = True  # restore


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
        zone_config = {
            "usa": {"region": "us-east-1", "model_prefix": "us"},
            "europe": {"region": "eu-west-3", "model_prefix": "eu"},
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
        """User in ccwb-usa-alpha group gets us-east-1 region."""
        claims = {"sub": "u2", "email": "u2@ex.com", "groups": ["ccwb-usa-alpha"]}
        config = reload_handler._build_config_response(claims, "user.token")

        assert config["inferenceBedrockRegion"] == "us-east-1"

    def test_no_zone_uses_default(self, reload_handler, zone_env, mock_sts):
        """User with no matching zone group gets default region."""
        claims = {"sub": "u3", "email": "u3@ex.com", "groups": ["other-group"]}
        config = reload_handler._build_config_response(claims, "user.token")

        assert config["inferenceBedrockRegion"] == "us-west-2"

    def test_role_sets_models_with_zone_prefix(self, reload_handler, zone_env, mock_sts):
        """Consulting role in Europe zone gets eu-prefixed models."""
        claims = {"sub": "u4", "groups": ["ccwb-europe-beta", "ccwb-consulting"]}
        config = reload_handler._build_config_response(claims, "user.token")

        assert "eu.anthropic.claude-opus-4-6-v1:0" in config["inferenceModels"]

    def test_role_sets_models_with_us_prefix(self, reload_handler, zone_env, mock_sts):
        """Engineering role in USA zone gets us-prefixed models."""
        claims = {"sub": "u5", "groups": ["ccwb-usa-alpha", "ccwb-engineering"]}
        config = reload_handler._build_config_response(claims, "user.token")

        assert "us.anthropic.claude-haiku-4-5-v1:0" in config["inferenceModels"]

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
