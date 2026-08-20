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


_CfnLoader.add_multi_constructor(
    "!", lambda loader, tag_suffix, node: {"Fn::" + tag_suffix: getattr(node, "value", None)}
)


@pytest.fixture(scope="module")
def tpl():
    return yaml.load(_TEMPLATE.read_text(), Loader=_CfnLoader)


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
        """An endpoint we create is local by definition, so the condition must be
        true whenever VpcEndpointId is empty — otherwise the common path would lose
        its header-free hostname."""
        cond = str(tpl["Conditions"]["AssociateEndpoint"])
        assert "VpcEndpointId" in cond
        assert "Fn::Or" in cond

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
        VPC endpoint in any account cannot invoke it."""
        stmts = tpl["Resources"]["BootstrapRestApi"]["Properties"]["Policy"]["Statement"]
        effects = {s["Effect"] for s in stmts}
        assert effects == {"Allow", "Deny"}
        rendered = str(stmts)
        assert "aws:SourceVpce" in rendered
        assert "StringNotEquals" in rendered


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
    def test_only_config_path_exists(self, tpl):
        """Any other path is rejected by API Gateway before the Lambda runs."""
        res = [r for r in tpl["Resources"].values() if r["Type"] == "AWS::ApiGateway::Resource"]
        assert len(res) == 1
        assert res[0]["Properties"]["PathPart"] == "config"

    def test_method_is_any_so_lambda_sees_options(self, tpl):
        """ANY lets the Lambda answer CORS preflight itself."""
        m = tpl["Resources"]["ConfigMethod"]["Properties"]
        assert m["HttpMethod"] == "ANY"
        assert m["Integration"]["Type"] == "AWS_PROXY"

    def test_deployment_waits_for_the_method(self, tpl):
        """Without DependsOn, the deployment can be created before the method and
        the stage serves a 403."""
        assert tpl["Resources"]["BootstrapRestApiDeployment"].get("DependsOn") == "ConfigMethod"

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
