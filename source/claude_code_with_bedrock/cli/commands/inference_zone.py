# ABOUTME: ccwb inference-zone CLI commands (create/list/delete).
# ABOUTME: Interactive wizard for per-zone Bedrock application inference profiles.

"""Per-zone Bedrock application inference profile management (GDPR).

A *zone* is a compliance boundary (e.g. ``france``, ``eu``, ``us``).
Each zone can host one or more Claude models. This command creates
one Bedrock application inference profile per (zone × model) pair,
tagged with ``Zone=<zone>``, ``ccwb:Region=<region>``, and ccwb
ownership metadata.

The ``Zone`` tag is the load-bearing identifier for IAM enforcement
under ``enforce_project_isolation=True``; ``ccwb:Region`` closes the
cross-region data-residency loophole by binding the profile to a
specific region at invocation time.

Admins run ``ccwb inference-zone create`` interactively (wizard with
zone name, region-vs-cross-region backing, multi-select model list).
The command discovers available models live via ``bedrock:ListFoundation
Models`` and falls back to ``claude_code_with_bedrock.models.CLAUDE_MODELS``
when the API is unreachable or returns an unfamiliar naming scheme.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

import boto3
import questionary
from botocore.exceptions import ClientError, NoCredentialsError
from cleo.commands.command import Command
from cleo.helpers import option
from rich import box
from rich.console import Console
from rich.table import Table

from claude_code_with_bedrock.config import Config, Profile
from claude_code_with_bedrock.models import CLAUDE_MODELS

# --------------------------------------------------------------------------- #
# Zone name validation
# --------------------------------------------------------------------------- #

_ZONE_NAME_PATTERN = re.compile(r"^[a-z]+$")
_ZONE_NAME_MAX_LEN = 32
_ZONE_RESERVED = frozenset({"aws", "amazon", "bedrock", "default", "system", "admin"})

_ZONE_NAME_RULE = (
    "Zone names must be ONE word of lowercase letters a-z only. "
    "No digits, hyphens, underscores, uppercase letters, or special characters. "
    "Examples: france, europe, restricted, production, sandbox."
)


def validate_zone_name(raw: str) -> str:
    """Validate and return a zone name. Raises ValueError on violation."""
    if not raw:
        raise ValueError("Zone name cannot be empty. " + _ZONE_NAME_RULE)
    if len(raw) > _ZONE_NAME_MAX_LEN:
        raise ValueError(
            f"Zone name '{raw}' is too long (max {_ZONE_NAME_MAX_LEN} characters)."
        )
    if not _ZONE_NAME_PATTERN.match(raw):
        raise ValueError(f"Zone name '{raw}' is invalid. " + _ZONE_NAME_RULE)
    if raw in _ZONE_RESERVED:
        raise ValueError(
            f"Zone name '{raw}' is reserved. Please choose a different name."
        )
    return raw


def _zone_name_prompt_validator(value: str) -> bool | str:
    """questionary-compatible validator: return True or an error message."""
    try:
        validate_zone_name(value.strip())
        return True
    except ValueError as e:
        return str(e)


# --------------------------------------------------------------------------- #
# Model discovery
# --------------------------------------------------------------------------- #

# Anthropic foundation-model-ID pattern. The suffix shape varies across
# model releases and we've seen all of these in the wild:
#   anthropic.claude-opus-4-7                            (newest format, no date, no -v)
#   anthropic.claude-sonnet-4-6                          (newest format)
#   anthropic.claude-opus-4-6-v1                         (has -v but no date)
#   anthropic.claude-opus-4-5-20251101-v1:0              (has date + -v + :N)
#   anthropic.claude-sonnet-4-5-20250929-v1:0            (date + -v + :N)
#   anthropic.claude-haiku-4-5-20251001-v1:0             (date + -v + :N)
# Cross-region (CRIS) ids add a zone prefix: us.anthropic..., eu.anthropic...
# We accept all variants so future Anthropic releases with new suffix
# shapes keep working without requiring code changes.
_ANTHROPIC_MODEL_RE = re.compile(
    r"^(?:[a-z]{2,6}\.)?"                        # optional zone prefix "us.", "eu.", "apac.", "global."
    r"anthropic\."
    r"claude-(?P<family>opus|sonnet|haiku)"
    r"-(?P<major>\d)"                            # single-digit major (4, 5, ...)
    r"-(?P<minor>\d{1,2})"                       # 1-2 digit minor (1-99). Excludes 8-digit date
    r"(?![\d])"                                   # boundary: next char must not be a digit
    r"(?:-\d{8})?"                                # optional date stamp
    r"(?:-v\d+)?"                                 # optional -v<rev>
    r"(?::\d+)?$"                                 # optional :N suffix on inference profile IDs
)


@dataclass(frozen=True)
class ModelChoice:
    """One Claude model available for selection."""

    short_name: str            # e.g. "opus-4-6"
    display_name: str          # e.g. "Claude Opus 4.6"
    family: str                # opus | sonnet | haiku
    major: int
    minor: int
    foundation_arn_template: str  # arn pattern without partition/region filled
    cris_profile_id: str | None   # e.g. "us.anthropic.claude-opus-4-6-v1" if available

    def __lt__(self, other: ModelChoice) -> bool:
        # Family order, then newer versions first
        family_order = {"opus": 0, "sonnet": 1, "haiku": 2}
        return (
            family_order.get(self.family, 99),
            -self.major,
            -self.minor,
        ) < (
            family_order.get(other.family, 99),
            -other.major,
            -other.minor,
        )


def _parse_model_id(model_id: str) -> tuple[str, int, int] | None:
    """Return (family, major, minor) for a recognized Anthropic ID, else None."""
    m = _ANTHROPIC_MODEL_RE.match(model_id)
    if not m:
        return None
    return m.group("family"), int(m.group("major")), int(m.group("minor"))


def _discover_models_live(region: str) -> list[ModelChoice]:
    """Try to enumerate Anthropic models in the region via Bedrock APIs.

    Returns the latest 2 versions per family (opus, sonnet, haiku). Returns
    an empty list if the API call fails for any reason (no creds, region
    unreachable, API throttling). Callers should fall back to ``_discover
    _models_from_models_py()``.
    """
    try:
        client = boto3.client("bedrock", region_name=region)
        # Foundation models in this region:
        fm_resp = client.list_foundation_models(byProvider="anthropic")
    except (ClientError, NoCredentialsError, Exception):
        return []

    # CRIS profiles (system-defined) also enumerate what cross-region routing
    # exists so we can surface them as an alternative backing.
    try:
        sys_resp = client.list_inference_profiles(typeEquals="SYSTEM_DEFINED")
        sys_profiles = sys_resp.get("inferenceProfileSummaries", []) or []
    except (ClientError, Exception):
        sys_profiles = []

    # Build a map short_name -> ModelChoice. Keep only INVOKE-capable chat models.
    by_short: dict[str, ModelChoice] = {}
    for fm in fm_resp.get("modelSummaries", []) or []:
        model_id = fm.get("modelId", "")
        parsed = _parse_model_id(model_id)
        if not parsed:
            continue
        family, major, minor = parsed
        # Only interactive chat modalities — skip embeddings/image.
        if "TEXT" not in (fm.get("outputModalities") or []):
            continue
        # Only models that support on-demand invocation or inference profile.
        lifecycle = fm.get("modelLifecycle", {}).get("status", "ACTIVE")
        if lifecycle != "ACTIVE":
            continue
        short = f"{family}-{major}-{minor}"
        if short in by_short:
            continue  # already recorded

        # Find a matching CRIS profile for this family/version, if any.
        cris_id = None
        for sp in sys_profiles:
            sp_id = sp.get("inferenceProfileId", "")
            sp_parsed = _parse_model_id(sp_id)
            if sp_parsed == (family, major, minor):
                cris_id = sp_id
                break

        by_short[short] = ModelChoice(
            short_name=short,
            display_name=f"Claude {family.capitalize()} {major}.{minor}",
            family=family,
            major=major,
            minor=minor,
            foundation_arn_template=model_id,  # we'll splice region/partition when building copyFrom
            cris_profile_id=cris_id,
        )

    # Keep only the top 2 versions per family.
    families: dict[str, list[ModelChoice]] = {}
    for mc in by_short.values():
        families.setdefault(mc.family, []).append(mc)

    keep: list[ModelChoice] = []
    for lst in families.values():
        lst.sort()  # uses __lt__ = newer-first
        keep.extend(lst[:2])
    return sorted(keep)


def _discover_models_from_models_py() -> list[ModelChoice]:
    """Fallback: enumerate from the repo's CLAUDE_MODELS dict.

    This only runs when live Bedrock API discovery fails — typically
    missing credentials, throttling, or a region with no Bedrock
    endpoint. The hardcoded list in ``claude_code_with_bedrock/models.py``
    is maintained alongside releases but always lags by days to weeks,
    so admins should treat fallback output as a degraded experience and
    rerun when their AWS credentials are valid.
    """
    out: list[ModelChoice] = []
    for short, meta in CLAUDE_MODELS.items():
        # Skip variants that aren't straightforward (govcloud, etc.).
        # The models.py dict includes govcloud overlays with suffixes
        # like "sonnet-4-5-govcloud" that should never surface in a
        # generic model picker — they belong in specialized govcloud flows.
        m = re.match(r"^(opus|sonnet|haiku)-(\d)-(\d{1,2})$", short)
        if not m:
            continue
        family, major, minor = m.group(1), int(m.group(2)), int(m.group(3))
        base_model = meta.get("base_model_id", "")
        profiles = meta.get("profiles", {}) or {}
        # Pick "us" as the preferred CRIS if present; caller can switch.
        cris_id = None
        for cris_key in ("us", "eu", "apac", "global"):
            if cris_key in profiles:
                cris_id = profiles[cris_key].get("model_id")
                break
        out.append(
            ModelChoice(
                short_name=short,
                display_name=meta.get("name", f"Claude {family.capitalize()} {major}.{minor}"),
                family=family,
                major=major,
                minor=minor,
                foundation_arn_template=base_model,
                cris_profile_id=cris_id,
            )
        )
    # Top 2 per family, newest first.
    families: dict[str, list[ModelChoice]] = {}
    for mc in out:
        families.setdefault(mc.family, []).append(mc)
    keep: list[ModelChoice] = []
    for lst in families.values():
        lst.sort()
        keep.extend(lst[:2])
    return sorted(keep)


def discover_models(region: str) -> tuple[list[ModelChoice], str]:
    """Return (models, source) where source is 'live' or 'fallback'."""
    live = _discover_models_live(region)
    if live:
        return live, "live"
    return _discover_models_from_models_py(), "fallback"


# --------------------------------------------------------------------------- #
# CRIS (cross-region) profile discovery
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class CrisProfile:
    """A system-defined cross-region inference profile available to the account."""

    profile_id: str        # e.g. "us.anthropic.claude-opus-4-6-v1"
    profile_arn: str       # full ARN
    zone_prefix: str       # "us" | "eu" | "apac" | "global"
    model_short: str       # "opus-4-6"


def discover_cris_profiles(region: str) -> list[CrisProfile]:
    """Return all Anthropic CRIS profiles visible to the account in region."""
    try:
        client = boto3.client("bedrock", region_name=region)
        resp = client.list_inference_profiles(typeEquals="SYSTEM_DEFINED")
    except (ClientError, NoCredentialsError, Exception):
        return []

    out: list[CrisProfile] = []
    for sp in resp.get("inferenceProfileSummaries", []) or []:
        sp_id = sp.get("inferenceProfileId", "")
        sp_arn = sp.get("inferenceProfileArn", "")
        if not sp_id or not sp_arn:
            continue
        parsed = _parse_model_id(sp_id)
        if not parsed:
            continue
        family, major, minor = parsed
        # Extract zone prefix (everything before the first dot) — e.g. "us"
        prefix = sp_id.split(".", 1)[0] if "." in sp_id else ""
        if not prefix:
            continue
        out.append(
            CrisProfile(
                profile_id=sp_id,
                profile_arn=sp_arn,
                zone_prefix=prefix,
                model_short=f"{family}-{major}-{minor}",
            )
        )
    return out


# --------------------------------------------------------------------------- #
# Region discovery
# --------------------------------------------------------------------------- #


def discover_bedrock_regions(candidate_regions: list[str]) -> list[str]:
    """Return regions from ``candidate_regions`` that answer Bedrock calls."""
    ok: list[str] = []
    for r in candidate_regions:
        try:
            client = boto3.client("bedrock", region_name=r)
            client.list_foundation_models(byProvider="anthropic")
            ok.append(r)
        except Exception:
            continue
    return ok


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _save_zone_mapping(
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


def _remove_zone_mapping(
    config: Config,
    profile: Profile,
    zone: str,
    model_short: str | None = None,
) -> None:
    """Remove a single (zone, model) or all models for a zone."""
    mapping = getattr(profile, "zone_inference_profiles", {}) or {}
    if zone not in mapping:
        return
    if model_short:
        mapping[zone].pop(model_short, None)
        if not mapping[zone]:
            del mapping[zone]
    else:
        del mapping[zone]
    profile.zone_inference_profiles = mapping
    config.save_profile(profile)


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #


class InferenceZoneCreateCommand(Command):
    """Create (or extend) a zone with one or more Bedrock inference profiles."""

    name = "inference-zone create"
    description = "Create Bedrock application inference profiles for a GDPR zone"

    options = [
        option("profile", description="ccwb configuration profile", flag=False, default=None),
        option(
            "zone",
            description="Zone name (lowercase letters only; skip to prompt)",
            flag=False,
            default=None,
        ),
    ]

    def handle(self) -> int:  # pragma: no cover - interactive CLI
        console = Console()
        config = Config.load()
        profile_name = self.option("profile") or config.active_profile
        profile = config.get_profile(profile_name)
        if not profile:
            console.print(f"[red]Profile '{profile_name}' not found.[/red]")
            return 1

        # ---- Zone name ----
        raw_zone = self.option("zone")
        if raw_zone:
            try:
                zone = validate_zone_name(raw_zone.strip().lower())
            except ValueError as e:
                console.print(f"[red]{e}[/red]")
                return 1
        else:
            console.print(
                "\n[bold cyan]Zone name[/bold cyan]  "
                "[dim](one word, lowercase letters only)[/dim]"
            )
            answer = questionary.text(
                "Zone name:",
                instruction=f"({_ZONE_NAME_RULE})",
                validate=_zone_name_prompt_validator,
            ).ask()
            if answer is None:
                console.print("[yellow]Cancelled.[/yellow]")
                return 1
            zone = answer.strip().lower()

        # ---- Backing style: specific region or cross-region ----
        console.print(
            f"\n[bold cyan]Configuration for zone '{zone}'[/bold cyan]"
        )
        style = questionary.select(
            "Model backing for this zone:",
            choices=[
                questionary.Choice(
                    "Specific AWS region  (single region, direct routing)",
                    value="region",
                ),
                questionary.Choice(
                    "AWS cross-region inference profile  (multi-region routing, higher availability)",
                    value="cris",
                ),
            ],
        ).ask()
        if style is None:
            console.print("[yellow]Cancelled.[/yellow]")
            return 1

        region_for_create: str
        cris_filter_prefix: str | None = None

        if style == "region":
            # Offer the profile's allowed_bedrock_regions; verify reachability.
            candidates = list(profile.allowed_bedrock_regions or [])
            if not candidates:
                candidates = [profile.aws_region]
            console.print("[dim]Checking which Bedrock regions your account can reach...[/dim]")
            reachable = discover_bedrock_regions(candidates)
            if not reachable:
                console.print(
                    "[red]No reachable Bedrock regions found for this profile. "
                    f"Candidates: {', '.join(candidates)}[/red]"
                )
                return 1
            chosen_region = questionary.select(
                "Pick a region for this zone:",
                choices=reachable,
                default=reachable[0],
            ).ask()
            if chosen_region is None:
                console.print("[yellow]Cancelled.[/yellow]")
                return 1
            region_for_create = chosen_region

        else:  # cris
            # Discover CRIS profiles from the profile's primary region, then
            # let the admin pick which zone-prefix to use.
            discovery_region = profile.aws_region
            console.print(
                f"[dim]Discovering cross-region inference profiles in {discovery_region}...[/dim]"
            )
            all_cris = discover_cris_profiles(discovery_region)
            if not all_cris:
                console.print(
                    "[red]No cross-region inference profiles found. "
                    "Try the 'Specific AWS region' option instead.[/red]"
                )
                return 1
            zone_prefixes = sorted({c.zone_prefix for c in all_cris})
            cris_filter_prefix = questionary.select(
                "Cross-region zone:",
                choices=zone_prefixes,
                default=zone_prefixes[0],
            ).ask()
            if cris_filter_prefix is None:
                console.print("[yellow]Cancelled.[/yellow]")
                return 1
            region_for_create = discovery_region

        # ---- Model selection (multi-select) ----
        console.print(f"\n[dim]Discovering Claude models in {region_for_create}...[/dim]")
        models, source = discover_models(region_for_create)

        # If cross-region mode, filter to models that have a CRIS profile under
        # the selected prefix.
        if style == "cris" and cris_filter_prefix:
            cris_model_shorts = {
                c.model_short for c in all_cris if c.zone_prefix == cris_filter_prefix
            }
            models = [m for m in models if m.short_name in cris_model_shorts]

        if not models:
            console.print(
                "[red]No Claude models available to enable for this zone.[/red]"
            )
            return 1
        if source == "fallback":
            console.print(
                "[yellow]Using built-in model list (Bedrock API unreachable or "
                "returned unfamiliar model IDs).[/yellow]"
            )

        selected_shorts = questionary.checkbox(
            f"Which models to enable for zone '{zone}'? (space to toggle, enter to confirm)",
            choices=[
                questionary.Choice(f"{m.display_name}  [{m.short_name}]", value=m.short_name)
                for m in models
            ],
        ).ask()
        if not selected_shorts:
            console.print("[yellow]No models selected. Aborted.[/yellow]")
            return 1

        # ---- Create each selected profile ----
        bedrock = boto3.client("bedrock", region_name=region_for_create)
        created: list[tuple[str, str]] = []  # (short, arn)
        failures: list[tuple[str, str]] = []  # (short, error)

        for short in selected_shorts:
            mc = next(m for m in models if m.short_name == short)

            # Resolve copyFrom source ARN.
            if style == "cris":
                # Find the CRIS ARN for this model under the admin's chosen prefix.
                cris = next(
                    (
                        c
                        for c in all_cris
                        if c.zone_prefix == cris_filter_prefix and c.model_short == short
                    ),
                    None,
                )
                if not cris:
                    failures.append(
                        (short, f"No {cris_filter_prefix}.{short} CRIS profile found")
                    )
                    continue
                copy_from = cris.profile_arn
            else:
                # Specific region: copyFrom the foundation-model ARN.
                sts = boto3.client("sts", region_name=region_for_create)
                account = sts.get_caller_identity()["Account"]
                copy_from = (
                    f"arn:aws:bedrock:{region_for_create}::foundation-model/"
                    f"{mc.foundation_arn_template}"
                )
                _ = account  # account unused for foundation-model ARNs (double-colon)

            inf_name = f"{zone}-{short}"
            tags = [
                {"key": "Zone", "value": zone},
                {"key": "ccwb:Region", "value": region_for_create},
                {"key": "ccwb:Profile", "value": profile.name},
                {"key": "ccwb:Model", "value": short},
            ]
            try:
                resp = bedrock.create_inference_profile(
                    inferenceProfileName=inf_name,
                    description=f"ccwb {zone} zone profile for {mc.display_name}",
                    modelSource={"copyFrom": copy_from},
                    tags=tags,
                )
                arn = resp.get("inferenceProfileArn")
                if not arn:
                    failures.append((short, "CreateInferenceProfile returned no ARN"))
                    continue
                created.append((short, arn))
                _save_zone_mapping(config, profile, zone, short, arn)
            except ClientError as e:
                failures.append((short, str(e)))

        # ---- Summary ----
        if created:
            table = Table(
                title=f"Zone '{zone}' — {len(created)} inference profile(s) created",
                box=box.ROUNDED,
            )
            table.add_column("Model", style="magenta")
            table.add_column("ARN")
            for short, arn in created:
                table.add_row(short, arn)
            console.print(table)
            console.print(
                "\n[dim]Share this list with users in your Okta "
                f"'{zone}' project groups. They will set their model "
                "inside Claude Code with:[/dim]\n"
                "  [cyan]/model <arn>[/cyan]"
            )
        if failures:
            for short, err in failures:
                console.print(f"[red]FAILED {short}: {err}[/red]")
            return 1
        return 0


class InferenceZoneListCommand(Command):
    """List zone -> (model, ARN) mappings recorded in the active ccwb profile."""

    name = "inference-zone list"
    description = "List zones and their inference profile ARNs"

    options = [
        option("profile", description="ccwb configuration profile", flag=False, default=None),
        option("zone", description="Filter to a single zone", flag=False, default=None),
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
        zone_filter = (self.option("zone") or "").strip().lower() or None

        if zone_filter:
            zones_to_show = {zone_filter: mapping.get(zone_filter, {})}
            if not zones_to_show[zone_filter]:
                console.print(
                    f"[yellow]No profiles recorded for zone '{zone_filter}'.[/yellow]"
                )
                return 0
        else:
            zones_to_show = mapping

        if not zones_to_show:
            console.print(
                "[yellow]No zones recorded.[/yellow] "
                "Run [cyan]ccwb inference-zone create[/cyan]."
            )
            return 0

        for zone in sorted(zones_to_show):
            models = zones_to_show[zone]
            table = Table(title=f"Zone '{zone}'", box=box.ROUNDED)
            table.add_column("Model", style="magenta")
            table.add_column("ARN")
            for short in sorted(models):
                table.add_row(short, models[short])
            console.print(table)
        return 0


class InferenceZoneDeleteCommand(Command):
    """Delete all (or one specific) Bedrock inference profile for a zone."""

    name = "inference-zone delete"
    description = "Delete zone inference profile(s)"

    options = [
        option("profile", description="ccwb configuration profile", flag=False, default=None),
        option("zone", description="Zone name to delete from", flag=False),
        option(
            "model",
            description="Specific model short-name; omit to delete ALL models for the zone",
            flag=False,
            default=None,
        ),
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

        zone_raw = (self.option("zone") or "").strip().lower()
        if not zone_raw:
            console.print("[red]--zone is required[/red]")
            return 1
        try:
            zone = validate_zone_name(zone_raw)
        except ValueError as e:
            console.print(f"[red]{e}[/red]")
            return 1

        model_short = (self.option("model") or "").strip() or None
        region = self.option("region") or profile.aws_region

        mapping = getattr(profile, "zone_inference_profiles", {}) or {}
        zone_map = mapping.get(zone, {})
        if not zone_map:
            console.print(
                f"[red]Zone '{zone}' has no profiles recorded in the ccwb profile.[/red]"
            )
            return 1

        if model_short:
            if model_short not in zone_map:
                console.print(
                    f"[red]Zone '{zone}' has no '{model_short}' profile recorded.[/red]"
                )
                return 1
            targets = {model_short: zone_map[model_short]}
        else:
            targets = dict(zone_map)

        # Confirm
        if not self.option("yes"):
            console.print(f"\n[bold]About to delete from zone '{zone}':[/bold]")
            for short, arn in targets.items():
                console.print(f"  {short}  {arn}")
            resp = self.ask("\nDelete? [y/N] ", default="n")
            if not resp or resp.lower() not in ("y", "yes"):
                console.print("Aborted.")
                return 1

        bedrock = boto3.client("bedrock", region_name=region)
        failed = []
        for short, arn in targets.items():
            try:
                bedrock.delete_inference_profile(inferenceProfileIdentifier=arn)
                _remove_zone_mapping(config, profile, zone, short)
                console.print(f"[green]Deleted[/green] {short}  {arn}")
            except ClientError as e:
                failed.append((short, str(e)))
                console.print(f"[red]FAILED {short}: {e}[/red]")
        return 1 if failed else 0
