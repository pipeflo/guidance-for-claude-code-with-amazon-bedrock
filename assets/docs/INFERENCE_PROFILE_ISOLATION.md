# Per-zone Bedrock inference profile isolation (GDPR)

This guide walks through enabling the optional per-zone inference-profile
isolation feature. With it, each Okta compliance zone (e.g. `eu`, `us`)
is pinned to its own Bedrock application inference profile. Users in one
zone cannot invoke another zone's profile — IAM denies cross-zone
invocation, and IAM also denies any invocation from a user who has no
project assignment at all.

Two things compose the GDPR boundary:

1. **AWS-side enforcement.** When `enforce_project_isolation=true`, the
   federated role's Bedrock policy (a) denies `InvokeModel*` / `Converse*`
   whenever the caller's STS session is missing either the `Project` or
   `Zone` tag, and (b) allows `InvokeModel*` against application
   inference profiles only when `aws:ResourceTag/Zone` equals
   `aws:PrincipalTag/Zone`. Foundation-model wildcard access is removed —
   all traffic must go through tagged application profiles.
2. **Client-side routing.** The installer emits a shell wrapper that
   runs `credential-process --get-tag Zone` on every `claude` launch,
   looks up the matching application-inference-profile ARN from the
   bundle's `config.json`, and sets `ANTHROPIC_MODEL` for just that
   invocation. No `settings.json` mutations; no `managed-settings.json`.

## Recommended group naming

```
<prefix>-<zone>-<project>
```

Example: `acmeprod-eu-alpha`, `acmeprod-us-beta`.

This is a recommendation, not a rule — ccwb prints the matching Okta
claim expression for whatever prefix you pass it at `ccwb init` time.
A hyphen-free prefix (e.g. `acmeprod`) produces the simplest Okta
expressions (`String.split(group, "-")[1]` for zone, `[2]` for project).
A multi-token prefix (e.g. `ccwb-okta-demo`) still works — the wizard
picks a `substringAfter` variant so you never have to count dashes.

## One-time admin setup

1. **Enable the feature at init time.** Re-run `ccwb init` (or edit the
   profile JSON) and answer yes to:
   - "Enable per-project cost attribution?"
   - "Enforce per-zone inference-profile isolation (GDPR)?"
   Then list your zones (e.g. `eu us`) and confirm the Okta group prefix.

2. **Create one Bedrock application inference profile per zone × model.**
   ccwb wraps `bedrock:CreateApplicationInferenceProfile` with the right
   tagging so the IAM policy and the client wrapper stay consistent:
   ```
   ccwb inference-profile create --zone eu --model opus-4-6 --region eu-west-1
   ccwb inference-profile create --zone us --model opus-4-6 --region us-east-1
   ```
   Each call tags the resulting profile `Zone=<zone>`, stores the returned
   ARN in your ccwb profile, and reminds you to re-run `ccwb package`.

3. **Configure the Okta claims.** The `ccwb init` wizard prints both
   claim expressions at the end — Project and Zone. Paste them into your
   Okta Custom Authorization Server as ID-token claims with "Disable when
   empty string: yes". If a user isn't in a `<prefix>-<zone>-<project>`
   group, the claims simply aren't emitted, and the IAM Deny statement
   catches them at `InvokeModel` time.

4. **Deploy the new IAM policy.** `ccwb deploy` (or `ccwb deploy --update`)
   threads `EnforceProjectIsolation=true` into the auth CloudFormation
   stack. Existing customers are unaffected until they flip the flag.

5. **Re-package and redistribute.** `ccwb package` emits the zone → ARN
   map into the bundle's `config.json`. `ccwb distribute` pushes the new
   bundle. End users re-run the install script; the installer detects
   `enforce_project_isolation=true` and adds a marker-delimited block to
   their shell profile that dot-sources the `claude-wrapper.sh` /
   `claude-wrapper.ps1` generated for their specific zones.

## Per-project day-to-day

Adding a new project = **zero AWS work**.

1. Create an Okta group named `<prefix>-<zone>-<project>` (e.g.
   `acmeprod-eu-newteam`).
2. Assign users to it.
3. Assign the group to the Claude Code OIDC application.

Done. Users in the new group automatically get the right Project tag for
cost attribution and the right Zone tag for IAM routing. The client
wrapper picks up the matching application inference profile ARN from
`config.json` on the user's first `claude` launch.

## Troubleshooting

**"Claude Code: no Zone assignment found on your Okta token."**
The user is authenticated but their Okta token has no `Zone` session tag.
Usually means they aren't in a `<prefix>-<zone>-<project>` group, or the
Zone claim expression in Okta was misconfigured. Have the user run
`credential-process --profile <name> --show-tags` to see the actual claim
payload on their cached token.

**"AccessDenied: explicit deny in identity-based policy" on `InvokeModel`.**
IAM is enforcing: either the user has no `Project`/`Zone` session tag
(user is not in any project group), or the user's Zone tag doesn't match
the invoked profile's Zone tag. Check CloudTrail for the failing call —
the request's `principalTags` and the invoked resource ARN reveal which.

**"Claude Code: zone '<z>' has no inference profile mapping."**
The user's Zone tag is set, but the bundle's `config.json` has no matching
entry. Run `ccwb inference-profile create --zone <z> --model opus-4-6`,
then `ccwb package && ccwb distribute`, and have the user reinstall.

**Case mismatch between Okta Zone value and Bedrock `Zone` tag.**
IAM string comparison is case-sensitive. If Okta emits `EU` but the
Bedrock profile is tagged `Zone=eu`, IAM denies every invocation.
`ccwb inference-profile create --zone <z>` lowercases `--zone` before
tagging to eliminate one direction of drift. On the Okta side, keep
zone tokens lowercase in group names (the wizard's example output uses
lowercase throughout).

**Cross-link:** for Project-tag cost attribution details (Cost Explorer,
CUR 2.0, Athena queries) see [COST_ATTRIBUTION.md](COST_ATTRIBUTION.md).
For upgrading an existing deployment from Org AS to CAS see
[UPGRADE_ORG_AS_TO_CAS.md](UPGRADE_ORG_AS_TO_CAS.md).
