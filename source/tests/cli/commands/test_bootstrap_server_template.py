# ABOUTME: Structural tests for bootstrap-server.yaml (private REST API endpoint)
# ABOUTME: Focus: the API is PRIVATE, scoped to one VPC endpoint, and header-free

"""Structural tests for the bootstrap server template.

The endpoint must be genuinely private and must stay usable by Claude Desktop,
which cannot send a custom request header. These tests pin the properties that
make both true — they are the ones a well-meaning edit is most likely to break.
"""

from pathlib import Path

import pytest
import yaml

_TEMPLATE = (
    Path(__file__).resolve().parents[4]
    / "deployment"
    / "infrastructure"
    / "bootstrap-server.yaml"
)


class _CfnLoader(yaml.SafeLoader):
    """CloudFormation short-form tags (!Ref, !If, ...) aren't plain YAML."""


def _cfn_tag(loader, tag_suffix, node):
    """Construct a CFN short-form tag into {"Fn::<tag>": <value>}, RECURSIVELY.

    The original version returned `node.value` raw, which left every nested tag as
    an unconstructed yaml Node. Assertions then had to match Node repr strings
    (`SequenceNode(tag='!Or', ...)`) rather than the data, so they only ever matched
    by accident -- and a nested `!If` was entirely opaque.

    Dispatch on node type and construct the CHILDREN with deep=True. Calling
    `construct_object(node, deep=True)` on the node itself instead raises
    "found unconstructable recursive node", because PyYAML is already mid-construction
    of that same node.
    """
    if isinstance(node, yaml.ScalarNode):
        value = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node, deep=True)
    elif isinstance(node, yaml.MappingNode):
        value = loader.construct_mapping(node, deep=True)
    else:  # pragma: no cover - yaml has no other node types
        value = None
    return {"Fn::" + tag_suffix: value}


_CfnLoader.add_multi_constructor("!", _cfn_tag)


@pytest.fixture(scope="module")
def tpl():
    return yaml.load(_TEMPLATE.read_text(), Loader=_CfnLoader)


def _deployment_logical_id(tpl):
    """Find the Deployment by TYPE, not name. Its logical id is deliberately bumped
    (…Deployment2, …Deployment3) whenever the API surface changes, so tests must not
    hardcode it."""
    ids = [
        k for k, r in tpl["Resources"].items() if r["Type"] == "AWS::ApiGateway::Deployment"
    ]
    assert len(ids) == 1, f"expected exactly one Deployment, found {ids}"
    return ids[0]


def _deployment(tpl):
    return tpl["Resources"][_deployment_logical_id(tpl)]


class TestPrivateEndpoint:
    def test_api_is_private(self, tpl):
        """The entire point. A REST API is the only kind that can be PRIVATE."""
        cfg = tpl["Resources"]["BootstrapRestApi"]["Properties"]["EndpointConfiguration"]
        assert cfg["Types"] == ["PRIVATE"]

    def test_association_is_conditional(self, tpl):
        """Association yields the {api-id}-{vpce-id} hostname, which needs NO Host or
        x-apigw-api-id header — Claude Desktop cannot send one. But association is
        same-account only, so a central-networking-account endpoint must be able to
        opt out rather than produce an un-deployable stack."""
        cfg = tpl["Resources"]["BootstrapRestApi"]["Properties"]["EndpointConfiguration"]
        assert "VpcEndpointIds" in cfg
        assert "AssociateEndpoint" in str(cfg["VpcEndpointIds"])
        assert "AssociateEndpoint" in tpl["Conditions"]

    def test_created_endpoint_is_always_associated(self, tpl):
        """An endpoint we create is local by definition, so association must follow
        automatically from CreateVpcEndpoint — otherwise the common path would lose
        its header-free hostname.

        Also gated on HasEndpoint: with no endpoint at all there is nothing to
        associate, and emitting VpcEndpointIds would make the stack un-deployable.
        """
        cond = tpl["Conditions"]["AssociateEndpoint"]
        assert "Fn::And" in cond
        rendered = str(cond)
        assert "CreateVpcEndpoint" in rendered
        assert "HasEndpoint" in rendered
        assert "Fn::Or" in rendered

    def test_url_falls_back_when_not_associated(self, tpl):
        """Without association the dedicated hostname does not exist, so BootstrapUrl
        must switch to the standard execute-api hostname."""
        assert "AssociateEndpoint" in str(tpl["Outputs"]["BootstrapUrl"]["Value"])

    def test_created_endpoint_leaves_private_dns_off(self, tpl):
        """Enabling private DNS hijacks execute-api for the WHOLE VPC, breaking any
        workload there that calls a public API Gateway."""
        ep = tpl["Resources"]["ExecuteApiEndpoint"]["Properties"]
        assert ep["PrivateDnsEnabled"] is False
        assert ep["VpcEndpointType"] == "Interface"

    def test_endpoint_creation_is_conditional(self, tpl):
        """Customers who manage endpoints centrally supply their own."""
        for name in ("ExecuteApiEndpoint", "EndpointSecurityGroup"):
            assert tpl["Resources"][name].get("Condition") == "CreateVpcEndpoint", name

    def test_no_vpc_is_ever_created(self, tpl):
        """A brand-new VPC would be unreachable, so the endpoint in it would be
        useless. The VPC must be customer-supplied."""
        types = [r["Type"] for r in tpl["Resources"].values()]
        assert "AWS::EC2::VPC" not in types
        assert "AWS::EC2::NatGateway" not in types
        assert "AWS::EC2::InternetGateway" not in types


class TestUpgradeSafety:
    """CloudFormation cannot change a logical ID's resource type.

    Earlier releases shipped BootstrapApi / BootstrapApiStage as
    AWS::ApiGatewayV2::Api / ::Stage. Reusing those IDs for the REST equivalents
    makes every existing stack fail to update with "Update of resource type is not
    permitted" — which is exactly what happened once. Keep the new names.
    """

    _LEGACY_V2_IDS = ("BootstrapApi", "BootstrapApiStage")

    def test_does_not_reuse_legacy_apigatewayv2_logical_ids(self, tpl):
        for legacy in self._LEGACY_V2_IDS:
            assert legacy not in tpl["Resources"], (
                f"{legacy} was an ApiGatewayV2 resource in earlier releases; reusing "
                f"the logical ID for a different type breaks in-place stack updates"
            )

    def test_rest_resources_use_the_new_ids(self, tpl):
        assert tpl["Resources"]["BootstrapRestApi"]["Type"] == "AWS::ApiGateway::RestApi"
        assert tpl["Resources"]["BootstrapRestApiStage"]["Type"] == "AWS::ApiGateway::Stage"


class TestResourcePolicy:
    def test_policy_exists(self, tpl):
        """A PRIVATE API is inaccessible to every VPC until a policy grants access,
        so a missing policy is a dead endpoint, not an open one."""
        assert "Policy" in tpl["Resources"]["BootstrapRestApi"]["Properties"]

    def test_policy_scopes_to_source_vpce_both_ways(self, tpl):
        """Allow from our endpoint AND explicitly Deny everything else, so another
        VPC endpoint in any account cannot invoke it.

        The statement list is now an Fn::If on HasEndpoint, so reach into the
        wired branch (index 1 of the Fn::If value: [cond, then, else]).
        """
        stmts = tpl["Resources"]["BootstrapRestApi"]["Properties"]["Policy"]["Statement"]
        wired = self._branch(stmts, "then")
        effects = {s["Effect"] for s in wired}
        assert effects == {"Allow", "Deny"}
        rendered = str(wired)
        assert "aws:SourceVpce" in rendered
        assert "StringNotEquals" in rendered

    @staticmethod
    def _branch(stmts, which):
        """Pull the then/else branch out of the Fn::If wrapping Statement.

        Fn::If value is [condition_name, then_value, else_value].
        """
        assert isinstance(stmts, dict) and "Fn::If" in stmts, (
            "Statement should be conditional on HasEndpoint"
        )
        cond_name, then_branch, else_branch = stmts["Fn::If"]
        assert cond_name == "HasEndpoint"
        return then_branch if which == "then" else else_branch

    def test_unwired_policy_denies_everything(self, tpl):
        """With no endpoint the API must be shut, not open.

        Relying on an empty-string aws:SourceVpce match would be fragile -- if an
        empty value ever matched, a PRIVATE API would be invokable from ANY
        execute-api endpoint in ANY AWS account. So the unwired branch is a bare
        Deny with no Condition at all.
        """
        stmts = tpl["Resources"]["BootstrapRestApi"]["Properties"]["Policy"]["Statement"]
        # The else branch is itself an Fn::If on AllowAnyVpce; the deny-all case is
        # ITS else branch.
        fallback = self._branch(stmts, "else")
        inner_cond, _permissive, deny_all = fallback["Fn::If"]
        assert inner_cond == "AllowAnyVpce"

        assert len(deny_all) == 1
        only = deny_all[0]
        assert only["Effect"] == "Deny"
        # No Condition -> unconditional deny, satisfiable by no caller.
        assert "Condition" not in only
        assert "aws:SourceVpce" not in str(only)


class TestUnwiredDeployment:
    """Deploying with no execute-api endpoint is SUPPORTED but UNREACHABLE.

    It was previously a hard abort in deploy.py. That blocked teams whose
    networking sign-off lags the rest of the rollout, for no safety benefit: the
    API is private either way, and the resource policy denies all callers until an
    endpoint exists. Deploying anyway proves out the Lambda, IAM, packaging and
    Okta issuer/audience wiring, all of which are the same work regardless.

    What must NOT happen is a stack that looks usable. These tests pin that.
    """

    def test_has_vpc_inputs_condition_exists(self, tpl):
        cond = str(tpl["Conditions"]["HasVpcInputs"])
        assert "VpcId" in cond
        assert "SubnetIds" in cond

    def test_endpoint_creation_requires_vpc_inputs(self, tpl):
        """Without this, an empty VpcId/SubnetIds still satisfies CreateVpcEndpoint and
        CloudFormation fails mid-create, leaving a ROLLBACK_COMPLETE stack that has to
        be deleted by hand before any retry."""
        cond = str(tpl["Conditions"]["CreateVpcEndpoint"])
        assert "HasVpcInputs" in cond
        assert "Fn::And" in cond

    def test_has_endpoint_condition_covers_both_sources(self, tpl):
        cond = str(tpl["Conditions"]["HasEndpoint"])
        assert "VpcEndpointId" in cond
        assert "HasVpcInputs" in cond

    def test_endpoint_configured_output_exists(self, tpl):
        """The deploy command reads this to decide whether to warn and whether to
        persist the URL. Renaming it silently breaks that branch."""
        assert "EndpointConfigured" in tpl["Outputs"]
        assert "HasEndpoint" in str(tpl["Outputs"]["EndpointConfigured"]["Value"])

    def test_url_reports_not_reachable_when_unwired(self, tpl):
        """Emitting a plausible-looking hostname would get an MDM anchor built against
        an endpoint that can never answer."""
        rendered = str(tpl["Outputs"]["BootstrapUrl"]["Value"])
        assert "HasEndpoint" in rendered
        assert "NOT-REACHABLE" in rendered

    def test_vpc_endpoint_id_used_reports_none(self, tpl):
        rendered = str(tpl["Outputs"]["VpcEndpointIdUsed"]["Value"])
        assert "HasEndpoint" in rendered
        assert "NONE" in rendered


class TestNoCertificateOrDns:
    def test_no_certificate_anywhere(self, tpl):
        """The reason this replaced an ALB: AWS provides TLS for execute-api, so
        there is nothing to import, validate or renew."""
        types = [r["Type"] for r in tpl["Resources"].values()]
        assert "AWS::CertificateManager::Certificate" not in types
        assert not [p for p in tpl["Parameters"] if "Certificate" in p]

    def test_no_dns_record_or_hosted_zone(self, tpl):
        types = [r["Type"] for r in tpl["Resources"].values()]
        assert "AWS::Route53::RecordSet" not in types
        assert not [p for p in tpl["Parameters"] if "HostedZone" in p or p == "DomainName"]

    def test_no_load_balancer_remnants(self, tpl):
        types = [r["Type"] for r in tpl["Resources"].values()]
        assert not any(t.startswith("AWS::ElasticLoadBalancingV2") for t in types)


class TestRouting:
    def test_only_config_and_health_paths_exist(self, tpl):
        """Two paths: /config (the real endpoint) and /health (an unauthenticated
        reachability probe). Any OTHER path is rejected by API Gateway before the
        Lambda runs."""
        parts = sorted(
            r["Properties"]["PathPart"]
            for r in tpl["Resources"].values()
            if r["Type"] == "AWS::ApiGateway::Resource"
        )
        assert parts == ["config", "health"]

    def test_method_is_any_so_lambda_sees_options(self, tpl):
        """ANY lets the Lambda answer CORS preflight itself."""
        for name in ("ConfigMethod", "HealthMethod"):
            m = tpl["Resources"][name]["Properties"]
            assert m["HttpMethod"] == "ANY"
            assert m["Integration"]["Type"] == "AWS_PROXY"

    def test_health_needs_no_auth(self, tpl):
        """The whole point is that a browser with no token gets a page, not a 401."""
        assert tpl["Resources"]["HealthMethod"]["Properties"]["AuthorizationType"] == "NONE"

    def test_deployment_waits_for_both_methods(self, tpl):
        """Without DependsOn, the deployment can be created before a method exists and
        that route 403s on the stage."""
        dep = _deployment(tpl)
        assert set(dep.get("DependsOn")) == {"ConfigMethod", "HealthMethod"}

    def test_stage_points_at_the_current_deployment(self, tpl):
        """The Stage must reference whichever Deployment logical id is current --
        a stale ref would serve an old API snapshot without the new route."""
        dep_id = _deployment_logical_id(tpl)
        stage = tpl["Resources"]["BootstrapRestApiStage"]["Properties"]
        assert stage["DeploymentId"] == {"Fn::Ref": dep_id}

    def test_stage_is_parameterised_and_in_the_url(self, tpl):
        assert "StageName" in tpl["Parameters"]
        assert "StageName" in str(tpl["Outputs"]["BootstrapUrl"]["Value"])


class TestLambdaAndOutputs:
    def test_lambda_role_stays_least_privilege(self, tpl):
        """AssumeRoleWithWebIdentity is authorized by the TARGET role's trust policy,
        not this one. Inline sts/bedrock grants would be a red flag."""
        role = tpl["Resources"]["BootstrapFunctionRole"]["Properties"]
        assert "Policies" not in role
        assert len(role["ManagedPolicyArns"]) == 1

    def test_lambda_not_attached_to_the_vpc(self, tpl):
        """API Gateway invokes the function through the Lambda API, so VPC attachment
        would only add cold starts and a NAT requirement."""
        assert "VpcConfig" not in tpl["Resources"]["BootstrapFunction"]["Properties"]

    def test_outputs_deploy_depends_on(self, tpl):
        for out in ("BootstrapUrl", "VpcEndpointIdUsed", "RestApiId"):
            assert out in tpl["Outputs"], out

    def test_partition_not_hardcoded(self, tpl):
        """GovCloud support: ARNs must use ${AWS::Partition}."""
        rendered = str(tpl["Resources"]["BootstrapRestApiPermission"]["Properties"]["SourceArn"])
        assert "AWS::Partition" in rendered


class TestDiscoveryMode:
    """AllowAnyVpcEndpoint: a transitional policy so the endpoint id can be FOUND.

    A private REST API's policy must name the caller's execute-api endpoint. When
    that endpoint is owned by a central networking team its id may be genuinely
    unavailable -- it does not show up in describe-vpc-endpoints from the workload
    account. Discovery mode allows any source vpce for exactly one round trip, so
    the Lambda can log the caller's identity and reveal the id.

    It is a deliberate widening, so the important properties are that it is
    OFF by default and that an explicit endpoint always overrides it.
    """

    def test_parameter_defaults_to_false(self, tpl):
        """Must be opt-in. A permissive policy by default would be a real regression."""
        p = tpl["Parameters"]["AllowAnyVpcEndpoint"]
        assert p["Default"] == "false"
        assert p["AllowedValues"] == ["true", "false"]

    def test_explicit_endpoint_wins_over_discovery(self, tpl):
        """Setting both must give the TIGHT policy, never the permissive one --
        otherwise a leftover discovery flag would silently keep it wide open."""
        cond = str(tpl["Conditions"]["AllowAnyVpce"])
        assert "AllowAnyVpcEndpoint" in cond
        assert "VpcEndpointId" in cond
        assert "Fn::And" in cond

    def test_policy_has_three_modes_in_precedence_order(self, tpl):
        """HasEndpoint (tight) > AllowAnyVpce (permissive) > bare Deny."""
        stmts = tpl["Resources"]["BootstrapRestApi"]["Properties"]["Policy"]["Statement"]
        outer_cond, tight, fallback = stmts["Fn::If"]
        assert outer_cond == "HasEndpoint"
        assert {s["Effect"] for s in tight} == {"Allow", "Deny"}

        inner_cond, permissive, deny_all = fallback["Fn::If"]
        assert inner_cond == "AllowAnyVpce"
        # Permissive: a single unconditional Allow.
        assert len(permissive) == 1
        assert permissive[0]["Effect"] == "Allow"
        assert "Condition" not in permissive[0]
        # Still-unwired: a single unconditional Deny.
        assert len(deny_all) == 1
        assert deny_all[0]["Effect"] == "Deny"
        assert "Condition" not in deny_all[0]

    def test_endpoint_configured_reports_discovery(self, tpl):
        """deploy.py branches on this to decide whether to save the URL and how loudly
        to warn, so the three states must all be distinguishable."""
        v = str(tpl["Outputs"]["EndpointConfigured"]["Value"])
        assert "discovery" in v
        assert "AllowAnyVpce" in v
        assert "HasEndpoint" in v

    def test_discovery_mode_publishes_the_standard_hostname(self, tpl):
        """With nothing associated only the standard hostname exists -- and it is the
        request through it that produces the log line we need. Reporting NOT-REACHABLE
        here would stop anyone ever making that request."""
        v = str(tpl["Outputs"]["BootstrapUrl"]["Value"])
        assert "AllowAnyVpce" in v
        assert "NOT-REACHABLE" in v  # still the answer when discovery is OFF too
