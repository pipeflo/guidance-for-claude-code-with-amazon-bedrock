# ABOUTME: Generates MDM trust-anchor profiles for the Claude Desktop bootstrap server
# ABOUTME: Pairs with the bootstrap-server CloudFormation stack to deploy dynamic config

"""Claude Desktop bootstrap MDM trust-anchor generation command.

`ccwb claude-desktop generate` produces the minimal MDM payload (.json,
.mobileconfig, .reg) that IT pushes to every device. The payload contains
only the bootstrap URL + OIDC settings — per-user configuration (region,
models, MCP servers) is delivered dynamically by the bootstrap Lambda at
sign-in based on the user's Okta groups.

Use this after `ccwb deploy bootstrap` succeeds and the endpoint is saved
to the profile.
"""

from pathlib import Path

from cleo.commands.command import Command
from cleo.helpers import option
from rich.console import Console
from rich.panel import Panel

from claude_code_with_bedrock.cli.utils.claude_desktop_bootstrap import (
    build_trust_anchor_config,
    generate_all,
)
from claude_code_with_bedrock.config import Config


class ClaudeDesktopGenerateCommand(Command):
    """
    Generate Claude Desktop bootstrap trust-anchor MDM profiles

    claude-desktop generate
    """

    name = "claude-desktop generate"
    description = (
        "Generate MDM trust-anchor profiles (.mobileconfig, .reg, .json) for Claude Desktop bootstrap"
    )

    options = [
        option(
            "profile",
            description="Configuration profile to use (defaults to active profile)",
            flag=False,
            default=None,
        ),
        option(
            "output",
            "o",
            description="Output directory (defaults to dist/claude-desktop/)",
            flag=False,
            default=None,
        ),
        option(
            "endpoint",
            "e",
            description="Bootstrap URL override (defaults to profile.claude_desktop_bootstrap_endpoint)",
            flag=False,
            default=None,
        ),
    ]

    def handle(self):
        console = Console()

        profile_name = self.option("profile")
        config = Config.load()
        # get_profile(None) already falls through to the active profile, so the
        # None case needs no special handling. Config has no get_active_profile().
        profile = config.get_profile(profile_name)

        if not profile:
            console.print("[red]No profile found. Run `ccwb init` first.[/red]")
            return 1

        # Resolve bootstrap endpoint: CLI option > profile > error
        endpoint = (
            self.option("endpoint")
            or getattr(profile, "claude_desktop_bootstrap_endpoint", None)
        )
        if not endpoint:
            console.print(
                Panel(
                    "[red]No bootstrap endpoint found.[/red]\n\n"
                    "Either deploy the bootstrap stack first:\n"
                    "  [cyan]ccwb deploy bootstrap[/cyan]\n\n"
                    "Or pass it explicitly:\n"
                    "  [cyan]ccwb claude-desktop generate --endpoint https://...[/cyan]",
                    title="Bootstrap endpoint required",
                    border_style="red",
                )
            )
            return 1

        # Build the trust-anchor config from the profile
        trust_anchor = build_trust_anchor_config(profile, endpoint)

        # Validate required OIDC fields
        if not trust_anchor["bootstrapOidc"]["issuer"]:
            console.print(
                "[red]Could not derive OIDC issuer URL from profile.[/red] "
                "Check profile.provider_type and provider_domain."
            )
            return 1

        # Output dir
        if self.option("output"):
            output_dir = Path(self.option("output"))
        else:
            output_dir = Path("dist") / profile.name / "claude-desktop"

        console.print(
            Panel(
                f"[bold]Profile:[/bold] {profile.name}\n"
                f"[bold]Provider:[/bold] {profile.provider_type}\n"
                f"[bold]OIDC issuer:[/bold] {trust_anchor['bootstrapOidc']['issuer']}\n"
                f"[bold]Client ID:[/bold] {trust_anchor['bootstrapOidc']['clientId']}\n"
                f"[bold]Bootstrap URL:[/bold] {endpoint}\n"
                f"[bold]Output:[/bold] {output_dir}",
                title="Claude Desktop Trust Anchor",
                border_style="cyan",
            )
        )

        generate_all(output_dir, trust_anchor, console)

        console.print(
            "\n[bold green]✓[/bold green] Trust-anchor files generated.\n"
            "\n[dim]Push the .mobileconfig (macOS) or .reg (Windows) to your MDM platform.[/dim]\n"
            "[dim]End users will fetch their personalized config from the bootstrap server at sign-in.[/dim]"
        )
        return 0
