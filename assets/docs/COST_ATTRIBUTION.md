# Cost Attribution for Amazon Bedrock

This applies to the **direct IAM path** (`FederationType=direct`) only. The Cognito path handles cost attribution automatically.

---

## 1. Built-in per-user tracking (no IdP changes required)

The credential provider embeds the user's email in the STS session name, so the resulting principal ARN looks like:

```
arn:aws:sts::123456789012:assumed-role/app-role/alice@acme.com
```

This ARN automatically appears in the `line_item_iam_principal` column of CUR 2.0 when IAM principal data is enabled. **This is the default behavior — no IdP changes or tag configuration required.**

### Enable IAM principal data in CUR 2.0

1. Open the Billing and Cost Management console → **Data Exports**
2. Create or edit a Standard data export (CUR 2.0)
3. Under **Additional export content**, enable **"Include caller identity (IAM principal) allocation data"**

The following example shows per-user Bedrock costs queried from CUR 2.0 data using Athena:

![Per-user Bedrock cost attribution via CUR 2.0](../images/cost-attribution-per-user.png)

Each user's email is visible in the `line_item_iam_principal` column, enabling per-user cost visibility without any IdP changes or tag configuration.

> **Note:** `line_item_iam_principal` is available in CUR 2.0 data and can be queried using tools like Athena or QuickSight. Cost Explorer does not expose this column as a filter or grouping dimension. To see per-user costs in Cost Explorer, configure session tags as described in [section 3](#3-optional-session-tags-for-richer-per-user-attribution).

---

## 2. IAM principal tags for team/department-level attribution

Tags applied to IAM principals (users or roles) in the IAM console appear in CUR 2.0 with the `iamPrincipal/` prefix (e.g., `iamPrincipal/department`, `iamPrincipal/cost-center`). In this solution all federated users share the same role, so role-level tags are useful for team or department attribution but cannot distinguish between individual users.

To set this up:

1. In the IAM console, tag the federation role with organizational tags (e.g., `department`, `cost-center`)
2. In the Billing and Cost Management console → **Cost Allocation Tags**, filter for **IAM principal type** tags, select the desired tags, and click **Activate**
3. Tags only appear after the role has made at least one Bedrock API call, and take up to **24 hours to appear** and a further **24 hours to activate**

---

## 3. Optional: session tags for richer per-user attribution

If you need per-user **tag-based** cost allocation (beyond the session name in the ARN), you can embed session tags in the ID token.

When `AssumeRoleWithWebIdentity` is called, STS reads the `https://aws.amazon.com/tags` claim from the ID token and attaches those tags to the resulting session. Once activated as **user-defined cost allocation tags** (not the "IAM principal type" filter), they appear in CUR 2.0 and Cost Explorer.

### Trust policy requirement

The IAM role's trust policy must include `sts:TagSession` in addition to `sts:AssumeRoleWithWebIdentity`. Without it, the `AssumeRoleWithWebIdentity` call fails entirely with an `AccessDenied` error — STS does not silently ignore the tags.

### Claim format

Your IdP must add the `https://aws.amazon.com/tags` claim to the ID token. Two formats are accepted by STS:

- **Nested object** (Auth0): tag values are single-element arrays inside a `principal_tags` object.
- **Flattened per-key claims** (Okta, Entra ID): one claim per tag, with plain string values and JSON Pointer-encoded paths.

Nested object format (Auth0):

```json
{
  "principal_tags": {
    "UserEmail": ["alice@acme.com"],
    "UserId":    ["user-internal-id"]
  },
  "transitive_tag_keys": ["UserEmail", "UserId"]
}
```

### Auth0

Add a post-login Action that sets the claim:

```javascript
exports.onExecutePostLogin = async (event, api) => {
  api.idToken.setCustomClaim('https://aws.amazon.com/tags', {
    principal_tags: {
      UserEmail: [event.user.email],
      UserId:    [event.user.user_id],
    },
    transitive_tag_keys: ['UserEmail', 'UserId'],
  });
};
```

### Okta

Okta's Expression Language cannot produce a JSON object value directly. Use an [Okta inline token hook](https://developer.okta.com/docs/guides/token-inline-hook/) with `com.okta.identity.patch` operations to inject the flattened per-key claim format. URI-style claim names must be JSON Pointer-encoded: `/` becomes `~1`, so `https://aws.amazon.com/tags` as a patch path becomes `https:~1~1aws.amazon.com~1tags`.

Your token hook endpoint must return:

```json
{
  "commands": [{
    "type": "com.okta.identity.patch",
    "value": [
      {
        "op": "add",
        "path": "/claims/https:~1~1aws.amazon.com~1tags~1principal_tags~1UserEmail",
        "value": "alice@acme.com"
      },
      {
        "op": "add",
        "path": "/claims/https:~1~1aws.amazon.com~1tags~1principal_tags~1UserId",
        "value": "user-internal-id"
      },
      {
        "op": "add",
        "path": "/claims/https:~1~1aws.amazon.com~1tags~1transitive_tag_keys",
        "value": ["UserEmail", "UserId"]
      }
    ]
  }]
}
```

> **Note:** AWS requires `transitive_tag_keys` to be an array of strings. Okta's hook schema formally types `value` as a scalar string, so array support depends on runtime behavior — test this against your Okta org. If Okta rejects the array, mark only the tag key you need in Cost Explorer (e.g., `"UserEmail"`) and accept that the other key will not propagate to child sessions.

Refer to the [token inline hook reference](https://developer.okta.com/docs/reference/token-hook/) for the full request/response schema.

### Microsoft Entra ID

Entra ID's custom claims provider does not support JSON object values (only `String` and `String array`), so use the [flattened STS claim format](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_session-tags.html) via a [custom claims provider](https://learn.microsoft.com/en-us/entra/identity-platform/custom-claims-provider-overview) backed by an Azure Function. The function must return:

```json
{
  "data": {
    "@odata.type": "microsoft.graph.onTokenIssuanceStartResponseData",
    "actions": [
      {
        "@odata.type": "microsoft.graph.tokenIssuanceStart.provideClaimsForToken",
        "claims": {
          "https://aws.amazon.com/tags/principal_tags/UserEmail": "alice@acme.com",
          "https://aws.amazon.com/tags/principal_tags/UserId":    "object-id-from-entra",
          "https://aws.amazon.com/tags/transitive_tag_keys":      ["UserEmail", "UserId"]
        }
      }
    ]
  }
}
```

### Activate session tags as cost allocation tags

After at least one Bedrock API call has been made with session tags:

1. Open **Billing and Cost Management console → Cost Allocation Tags**
2. Filter for **user-defined** cost allocation tags (not "IAM principal type" — that is for section 2 role-level tags)
3. Locate `UserEmail` and `UserId` and click **Activate** — tags take up to **24 hours to appear** after the first tagged API call, and a further **24 hours to activate**
4. In Cost Explorer, group or filter by **Tag → `UserEmail`** to see per-user Bedrock spend

Once activated, session tags are available in both **Cost Explorer** and **CUR 2.0**. This means you can group or filter costs by tag in the Cost Explorer console without needing Athena, unlike the `line_item_iam_principal` column in section 1 which is only available in CUR 2.0.

With session tags configured, you can also group costs by department or any other tag dimension. The following example shows department-level Bedrock costs queried from CUR 2.0 data using Athena:

![Per-department Bedrock cost attribution via CUR 2.0](../images/cost-attribution-per-department.png)

---

## 4. Per-project cost attribution driven by IdP groups

A common variant of section 3: the customer team creates one IdP group per project and adds developers to groups. They want monthly Bedrock spend rolled up by project in Cost Explorer, with **no AWS-side work whenever a new project starts** — just Okta group creation and user assignment.

This is section 3 applied to a single `Project` tag whose value comes from the user's IdP group membership. The group name becomes the tag value directly — **no prefix required on the AWS side**. The filter that decides "which of this user's groups is the project" lives inside the IdP's expression engine, so customers can name groups anything they want (`Alpha`, `Widget-Project`, `XYZ_Initiative`, etc.).

### Operator workflow

**One-time admin setup:**
1. Create (or identify) a single federated IAM role. Ensure its trust policy includes `sts:TagSession` alongside `sts:AssumeRoleWithWebIdentity` (the `DirectIAMRole` generated by `bedrock-auth-*.yaml` already does).
2. Configure the IdP authorization server to emit `https://aws.amazon.com/tags` with a `Project` entry whose value is the user's project group name (three patterns below — pick whichever fits your IdP policy).
3. After the first tagged Bedrock call reaches CUR 2.0, activate `Project` as a **user-defined cost allocation tag** in Billing console → Cost Allocation Tags.

**Per-new-project (customer team, every time):**
1. Create Okta group `ClaudeProject-<name>` (or any convention — see patterns below).
2. Assign developers to the group.
3. Done. No `ccwb deploy`, no new bundle, no CloudFormation change.

### Three ways to pick which group becomes the `Project` tag

Most IdP users are in many groups (`Everyone`, `VPN-Users`, plus their project groups). The IdP needs **some** rule to pick the project-bearing group. None of these require a naming prefix in our code — all of them run inside Okta / Auth0 / Entra expressions.

#### Pattern A — "Groups assigned to the Claude OIDC app are project groups" (simplest)

Admin assigns project groups directly to the Claude Code OIDC application in Okta. Non-project groups (e.g. `Everyone`) are not assigned to the app. The expression reads only app-assigned groups and emits the first one:

**Okta** — inline token hook that calls your endpoint; endpoint builds the response from `context.session.identity.groups` filtered via `appassignments`. Simplest path in practice: use [Okta Profile Mapping](https://developer.okta.com/docs/concepts/profile-sourcing/) from the Claude app's assigned groups to a custom user attribute `user.claudeProject`, then emit that attribute (see Pattern C).

**Auth0 Post-Login Action:**

```javascript
exports.onExecutePostLogin = async (event, api) => {
  // event.authorization.roles is populated only with app-assigned roles.
  const project = (event.authorization?.roles || [])[0];
  if (project) {
    api.idToken.setCustomClaim('https://aws.amazon.com/tags', {
      principal_tags: { Project: [project] },
      transitive_tag_keys: ['Project']
    });
  }
};
```

Customers name groups anything they like (`Alpha`, `Widget Project`, `ACME-Initiative`). Group name flows to `iamPrincipal/Project` verbatim.

#### Pattern B — Custom group attribute in the IdP

Admin defines a custom attribute on the IdP's group object (e.g. `group.claudeProject = true`). The expression filters user's groups by that attribute and emits the first qualifying one. Customer can opt a group in or out by toggling the attribute — no renaming required.

**Okta**: Directory → Profile Editor → Groups → Add custom attribute `claudeProject` (boolean). Mark project groups with `claudeProject=true`. Your inline token hook filters `context.session.identity.groups` on this attribute.

**Entra ID**: configure a [custom claims provider](https://learn.microsoft.com/en-us/entra/identity-platform/custom-claims-provider-overview) backed by an Azure Function that queries Microsoft Graph for groups tagged with an extension attribute, selects one, and returns it as the flattened tag claim.

#### Pattern C — User profile attribute maintained by Group Rules

Admin defines a user profile attribute `user.claudeProject`. An IdP Group Rule maps "member of Group X" → "set `claudeProject` = <group name>". The claim then emits `user.claudeProject` directly. Most flexible, since the tag value comes from a scalar attribute with no in-token filtering logic. Good fit when a user's "current project" is explicitly managed (e.g. via HR system sync).

**Okta Group Rule** (Directory → Group Rules → Add Rule):
- Condition: `isMemberOfGroupName("Alpha")`
- Action: `user.claudeProject = "Alpha"`

Repeat one rule per project group. Then the token hook / expression just emits `user.claudeProject`.

### Which pattern to pick

| Pattern | Okta/Auth0 setup cost | Per-new-project effort | Group-name flexibility |
| --- | --- | --- | --- |
| A: app-assigned groups | Low (assign group to app) | Zero — just create group + assign users + assign to app | Any name |
| B: custom group attribute | Medium (one-time attribute setup) | Low — create group, set attribute | Any name |
| C: user profile attribute via Group Rules | Medium-High (per-project rule) | Medium — add a Group Rule per project | Any name |

For the typical customer described in this section (non-technical admins creating groups), **Pattern A** is the minimum-friction choice: create group → assign to Claude app → done.

### Verifying it works

Once the IdP is configured and a user has signed in at least once, run the diagnostic:

```bash
credential-process --profile <profile> --show-tags
```

This decodes the user's cached ID token and prints the `https://aws.amazon.com/tags` claim. Output should look like:

```json
{
  "principal_tags": {
    "Project": ["Alpha"]
  },
  "transitive_tag_keys": ["Project"]
}
```

If the claim is missing entirely, the IdP isn't emitting it — revisit the patterns above. If the value is wrong, the IdP expression is picking the wrong group.

### Multi-project users

If a developer is in more than one project group, patterns A–C will pick **one** deterministically (first app-assigned role, first tagged group, first matching Group Rule — depending on pattern). This is usually fine for attribution: spend rolls up to one project per session.

If developers legitimately split work across multiple projects within a single session, you have three options:

1. **Don't. Create one Okta user per project-developer pair.** Cleanest from an attribution standpoint.
2. **Use an explicit "primary project" attribute (Pattern C).** User's manager maintains `user.currentProject` in HR/Okta when people switch teams.
3. **Emit all of the user's project groups into one `Project` session tag as a comma-joined value** (`Project=Alpha,Beta`). Cost Explorer will treat that literal string as one tag value — meaning "Alpha,Beta" is a distinct project from "Alpha" or "Beta" alone. Rarely what you want.

None of these require changes to our Go binary, CloudFormation, or Python CLI — all live in IdP configuration.
