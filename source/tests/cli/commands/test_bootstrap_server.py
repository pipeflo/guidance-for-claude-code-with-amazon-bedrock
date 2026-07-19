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
    """Patch the handler's boto3.client: STS returns canned credentials, and any
    'bedrock' client returns a discovery mock that surfaces one ACTIVE profile
    per zone tag (usa/us/eu/europe/apac) so zone discovery resolves in tests.

    Returns the STS mock so tests can assert on the assume-role call args.
    """
    sts_client = MagicMock()
    sts_client.assume_role_with_web_identity.return_value = _fake_sts_credentials()

    # Zone ARNs keyed by the region they physically live in, so the mock is
    # region-aware (a profile only appears when scanning ITS region).
    _region_arns = {
        "us-west-2": {
            "arn:aws:bedrock:us-west-2:123456789012:application-inference-profile/usa1": "usa",
            "arn:aws:bedrock:us-west-2:123456789012:application-inference-profile/us1": "us",
            "arn:aws:bedrock:us-west-2:123456789012:application-inference-profile/eu1": "eu",
        },
        "eu-west-3": {
            "arn:aws:bedrock:eu-west-3:123456789012:application-inference-profile/euuu": "europe",
        },
    }

    def _bedrock_client(region):
        c = MagicMock()
        entries = _region_arns.get(region, {})
        summaries = [{"inferenceProfileArn": arn, "status": "ACTIVE"} for arn in entries]
        paginator = MagicMock()
        paginator.paginate.return_value = [{"inferenceProfileSummaries": summaries}]
        c.get_paginator.return_value = paginator
        c.list_tags_for_resource.side_effect = lambda resourceARN: {
            "tags": [{"key": "Zone", "value": entries.get(resourceARN, "")}]
        }
        return c

    def factory(service, region_name=None, **kw):
        return sts_client if service == "sts" else _bedrock_client(region_name)

    with patch.object(reload_handler.boto3, "client", side_effect=factory):
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

    def test_normalizes_space_separated_groups(self, reload_handler):
        """Okta access token flattens groups to a SPACE-separated string."""
        event = _event(claims={"sub": "u1", "groups": "Everyone ccwb-us-alpha claude-power-users"})
        claims = reload_handler._extract_claims(event)
        assert claims["groups"] == ["Everyone", "ccwb-us-alpha", "claude-power-users"]

    def test_normalizes_comma_separated_groups(self, reload_handler):
        event = _event(claims={"sub": "u1", "groups": "ccwb-us-alpha, ccwb-eng"})
        claims = reload_handler._extract_claims(event)
        assert claims["groups"] == ["ccwb-us-alpha", "ccwb-eng"]

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
        # ZoneConfig is now just the set of VALID ZONE NAMES; ARNs + region are
        # discovered live by the mock_sts bedrock factory (usa->us-west-2,
        # europe->eu-west-3). DISCOVERY_REGIONS must cover both.
        monkeypatch.setenv("ZONE_CONFIG", json.dumps({"usa": {}, "europe": {}}))
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
        """User in ccwb-europe-beta group → europe zone discovered in eu-west-3."""
        claims = {"sub": "u1", "email": "u@ex.com", "groups": ["ccwb-europe-beta"]}
        config = reload_handler._build_config_response(claims, "user.token")

        assert config["inferenceBedrockRegion"] == "eu-west-3"
        models = json.loads(config["inferenceModels"])
        assert models == ["arn:aws:bedrock:eu-west-3:123456789012:application-inference-profile/euuu"]

    def test_usa_zone_routing(self, reload_handler, zone_env, mock_sts):
        """User in ccwb-usa-alpha group → usa zone discovered in us-west-2."""
        claims = {"sub": "u2", "email": "u2@ex.com", "groups": ["ccwb-usa-alpha"]}
        config = reload_handler._build_config_response(claims, "user.token")

        assert config["inferenceBedrockRegion"] == "us-west-2"
        models = json.loads(config["inferenceModels"])
        assert models == ["arn:aws:bedrock:us-west-2:123456789012:application-inference-profile/usa1"]

    def test_unmatched_zone_under_isolation_fails_loudly(self, reload_handler, zone_env, mock_sts):
        """With zone routing configured, a user matching no zone must NOT silently
        fall back to a CRIS default (which Bedrock would AccessDeny under isolation)."""
        claims = {"sub": "u3", "email": "u3@ex.com", "groups": ["other-group"]}
        with pytest.raises(RuntimeError, match="no configured zone"):
            reload_handler._build_config_response(claims, "user.token")

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
        assert models == [
            "arn:aws:bedrock:eu-west-3:123456789012:application-inference-profile/euuu"
        ]
        # CRIS ids must not leak in
        assert not any("anthropic." in m for m in models)

    def test_zone_with_no_discovered_profiles_raises(self, reload_handler, monkeypatch, mock_sts):
        """A configured zone whose profiles can't be discovered fails loudly rather
        than returning a model that would be AccessDenied under isolation."""
        monkeypatch.setenv("ZONE_CONFIG", json.dumps({"apac": {}}))
        monkeypatch.setenv("DISCOVERY_REGIONS", "us-west-2,eu-west-3")  # no apac-tagged profile in mock
        monkeypatch.setenv("GROUP_PREFIX", "ccwb-")
        reload_handler._DISCOVERY_CACHE.clear()

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
        banner = json.loads(config["banner"])
        assert "EUROPE" in banner["text"]


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
                    {"inferenceProfileArn": arn, "status": "ACTIVE"} for arn, _ in entries
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
            region, arns = reload_handler._discover_zone_profiles("usa", {"AccessKeyId": "a", "SecretAccessKey": "b", "SessionToken": "c"})
        assert region == "us-west-2"
        assert arns == ["arn:aws:bedrock:us-west-2:1:application-inference-profile/usa1"]

    def test_scans_multiple_regions(self, reload_handler, monkeypatch):
        monkeypatch.setenv("DISCOVERY_REGIONS", "us-west-2,eu-west-3")
        monkeypatch.setenv("ZONE_TAG_KEY", "Zone")
        reload_handler._DISCOVERY_CACHE.clear()
        factory = self._mock_bedrock({
            "us-west-2": [("arn:aws:bedrock:us-west-2:1:application-inference-profile/usa1", {"Zone": "usa"})],
            "eu-west-3": [("arn:aws:bedrock:eu-west-3:1:application-inference-profile/eu1", {"Zone": "europe"})],
        })
        with patch.object(reload_handler.boto3, "client", side_effect=factory):
            region, arns = reload_handler._discover_zone_profiles("europe", {"AccessKeyId": "a", "SecretAccessKey": "b", "SessionToken": "c"})
        assert region == "eu-west-3"
        assert arns == ["arn:aws:bedrock:eu-west-3:1:application-inference-profile/eu1"]

    def test_no_match_returns_empty(self, reload_handler, monkeypatch):
        monkeypatch.setenv("DISCOVERY_REGIONS", "us-west-2")
        reload_handler._DISCOVERY_CACHE.clear()
        factory = self._mock_bedrock({"us-west-2": [("arn:...:/x", {"Zone": "usa"})]})
        with patch.object(reload_handler.boto3, "client", side_effect=factory):
            region, arns = reload_handler._discover_zone_profiles("apac", {"AccessKeyId": "a", "SecretAccessKey": "b", "SessionToken": "c"})
        assert region is None and arns == []
