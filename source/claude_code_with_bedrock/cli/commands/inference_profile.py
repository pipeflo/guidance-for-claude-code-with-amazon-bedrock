# ABOUTME: ccwb inference-profile CLI commands (create/list/delete).
# ABOUTME: Admin convenience around bedrock:CreateApplicationInferenceProfile.

"""Application inference profile management for GDPR zone isolation.

Admins pre-create one Bedrock application inference profile per compliance
zone (commonly one EU, one US), tagged ``Zone=<zone>``. The tag is the
load-bearing identifier for IAM enforcement under
``enforce_project_isolation=True``; the profile's name is purely
human-readable.

Resulting ARNs are stored in ``Profile.zone_inference_profiles``, which
``ccwb package`` emits into the bundle's ``config.json`` so the installer
can generate the shell-function ``case``/``switch`` arms that route Claude
Code to the right profile based on the user's signed ``Zone`` session tag.
"""

from __future__ import annotations

import json

import boto3
from botocore.exceptions import ClientError
from cleo.commands.command import Command
from cleo.helpers import option
from rich import box
from rich.console import Console
from rich.table import Table

from claude_code_with_bedrock.config import Config, Profile
from claude_code_with_bedrock.models import CLAUDE_MODELS


def _resolve_source_model_arn(
    profile: Profile,
    model_short: str,
    region: str,
) -> str:
    """Resolve the source CRIS ARN to copyFrom when creating the app profile.

    Application inference profiles copy from either a foundation-model ARN or
    a system-defined (cross-region) inference profile. We prefer the latter
    so the application profile inherits CRIS routing across the zone's
    regions, matching what Claude Code uses today via ``ANTHROPIC_MODEL``.
    """
    if model_short not in CLAUDE_MODELS:
        raise ValueError(
            f"Unknown model short-name '{model_short}'. "
            f"Known: {', '.join(sorted(CLAUDE_MODELS.keys()))}"
        )
    model_meta = CLAUDE_MODELS[model_short]
    cris_key = profile.cross_region_profile or "us"
    profiles = model_meta.get("profiles", {})
    if cris_key not in profiles:
        raise ValueError(
            f"Model '{model_short}' has no '{cris_key}' cross-region profile. "
            f"Available: {', '.join(sorted(profiles.keys()))}"
        )
    model_id = profiles[cris_key]["model_id"]
    sts = boto3.client("sts", region_name=region)
    account = sts.get_caller_identity()["Account"]
    return f"arn:aws:bedrock:{region}:{account}:inference-profile/{model_id}"


def _save_profile_mapping(
    config: Config,
    profile: Profile,
    zone: str,
    model_short: str,
    arn: str,
) -> None:
    """Persist the resulting ARN into the active ccwb profile."""
    if not isinstance(profile.zone_inference_profiles, dict):
        profile.zone_inference_profiles = {}
    profile.zone_inference_profiles.setdefault(zone, {})[model_short] = arn
    config.save_profile(profile)


class InferenceProfileCreateCommand(Command):
    """Create a per-zone Bedrock application inference profile."""

    name = "inference-profile create"
    description = "Create a Bedrock application inference profile for a GDPR zone"

    options = [
        option(
            "profile",
            description="ccwb configuration profile to update",
            flag=False,
            default=None,
        ),
        option("zone", description="Zone label, e.g. 'eu' or 'us'", flag=False),
        option(
            "model",
            description="Claude model short-name (default 'opus-4-6')",
            flag=False,
            default=None,
        ),
        option(
            "region",
            description="AWS region to create the profile in (default: profile's aws_region)",
            flag=False,
            default=None,
        ),
        option(
            "dry-run",
            description="Print the API call parameters and exit without creating",
            flag=True,
        ),
    ]

    def handle(self) -> int:  # pragma: no cover - thin CLI glue
        console = Console()
        config = Config.load()
        profile_name = self.option("profile") or config.active_profile
        profile = config.get_profile(profile_name)
        if not profile:
            console.print(f"[red]Profile '{profile_name}' not found.[/red]")
            return 1

        raw_zone = self.option("zone")
        if not raw_zone:
            console.print("[red]--zone is required[/red]")
            return 1
        zone = raw_zone.strip().lower()
        if zone != raw_zone:
            console.print(
                f"[yellow]Note: lowercasing zone '{raw_zone}' -> '{zone}' "
                "(keeps IAM ResourceTag matching case-consistent).[/yellow]"
            )

        model_short = (
            self.option("model") or profile.model_short_name or "opus-4-6"
        ).strip()
        region = self.option("region") or profile.aws_region

        try:
            source_arn = _resolve_source_model_arn(profile, model_short, region)
        except ValueError as e:
            console.print(f"[red]{e}[/red]")
            return 1

        inf_name = f"{zone}-{model_short}"
        params = {
            "inferenceProfileName": inf_name,
            "description": f"ccwb {zone} zone profile for Claude {model_short}",
            "modelSource": {"copyFrom": source_arn},
            "tags": [
                {"key": "Zone", "value": zone},
                {"key": "ccwb:Profile", "value": profile.name},
                {"key": "ccwb:Model", "value": model_short},
            ],
        }

        if self.option("dry-run"):
            console.print("[cyan]bedrock:CreateApplicationInferenceProfile (dry-run)[/cyan]")
            console.print(json.dumps(params, indent=2))
            return 0

        client = boto3.client("bedrock", region_name=region)
        try:
            resp = client.create_inference_profile(**params)
        except ClientError as e:
            console.print(f"[red]AWS error: {e}[/red]")
            return 1

        arn = resp.get("inferenceProfileArn")
        if not arn:
            console.print(f"[red]CreateInferenceProfile returned no ARN: {resp}[/red]")
            return 1

        _save_profile_mapping(config, profile, zone, model_short, arn)

        console.print(
            f"[green]Created[/green] {inf_name} -> {arn}\n"
            f"  Zone tag:   [green]{zone}[/green]\n"
            f"  Stored in:  ~/.ccwb/profiles/{profile.name}.json  "
            f"(zone_inference_profiles['{zone}']['{model_short}'])\n"
            f"\n[bold]Next:[/bold] re-run [cyan]ccwb package[/cyan] to emit the new mapping "
            f"into config.json, then [cyan]ccwb distribute[/cyan]."
        )
        return 0


class InferenceProfileListCommand(Command):
    """List the zone -> inference-profile ARNs recorded in the ccwb profile."""

    name = "inference-profile list"
    description = "List zone -> ARN mappings recorded in the active ccwb profile"

    options = [
        option("profile", description="ccwb configuration profile", flag=False, default=None),
    ]

    def handle(self) -> int:  # pragma: no cover - thin CLI glue
        console = Console()
        config = Config.load()
        profile_name = self.option("profile") or config.active_profile
        profile = config.get_profile(profile_name)
        if not profile:
            console.print(f"[red]Profile '{profile_name}' not found.[/red]")
            return 1

        mapping = getattr(profile, "zone_inference_profiles", {}) or {}
        if not mapping:
            console.print(
                "[yellow]No inference profiles recorded.[/yellow] "
                "Run [cyan]ccwb inference-profile create --zone <z>[/cyan]."
            )
            return 0

        table = Table(title=f"Inference profiles ({profile_name})", box=box.ROUNDED)
        table.add_column("Zone", style="cyan")
        table.add_column("Model", style="magenta")
        table.add_column("ARN")
        for zone in sorted(mapping):
            for model_short, arn in sorted(mapping[zone].items()):
                table.add_row(zone, model_short, arn)
        console.print(table)
        return 0


class InferenceProfileDeleteCommand(Command):
    """Delete an application inference profile and remove it from the ccwb profile."""

    name = "inference-profile delete"
    description = "Delete a Bedrock application inference profile"

    options = [
        option("profile", description="ccwb configuration profile", flag=False, default=None),
        option("zone", description="Zone label to delete", flag=False),
        option("model", description="Claude model short-name (default 'opus-4-6')", flag=False, default=None),
        option("region", description="AWS region", flag=False, default=None),
        option("yes", "y", description="Skip confirmation prompt", flag=True),
    ]

    def handle(self) -> int:  # pragma: no cover - thin CLI glue
        console = Console()
        config = Config.load()
        profile_name = self.option("profile") or config.active_profile
        profile = config.get_profile(profile_name)
        if not profile:
            console.print(f"[red]Profile '{profile_name}' not found.[/red]")
            return 1

        zone = (self.option("zone") or "").strip().lower()
        if not zone:
            console.print("[red]--zone is required[/red]")
            return 1
        model_short = (self.option("model") or profile.model_short_name or "opus-4-6").strip()
        region = self.option("region") or profile.aws_region

        mapping = getattr(profile, "zone_inference_profiles", {}) or {}
        arn = mapping.get(zone, {}).get(model_short)
        if not arn:
            console.print(f"[red]No mapping for zone='{zone}' model='{model_short}' in profile.[/red]")
            return 1

        if not self.option("yes"):
            resp = self.ask(f"Delete {arn}? [y/N] ", default="n")
            if not resp or resp.lower() not in ("y", "yes"):
                console.print("Aborted.")
                return 1

        client = boto3.client("bedrock", region_name=region)
        try:
            client.delete_inference_profile(inferenceProfileIdentifier=arn)
        except ClientError as e:
            console.print(f"[red]AWS error: {e}[/red]")
            return 1

        del mapping[zone][model_short]
        if not mapping[zone]:
            del mapping[zone]
        profile.zone_inference_profiles = mapping
        config.save_profile(profile)

        console.print(f"[green]Deleted[/green] {arn}")
        return 0
