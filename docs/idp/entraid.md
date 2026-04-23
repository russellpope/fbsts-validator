# Microsoft Entra ID Setup

Step-by-step guide for configuring Microsoft Entra ID (formerly Azure AD) as an identity provider for fbsts.

## Prerequisites

- An Entra tenant with permission to create app registrations (or an admin who can do so for you)
- The tenant ID (GUID) — you'll find it on the Entra overview page
- Users and groups in the tenant that match the trust policy you intend to apply

## Step-by-Step Setup

### 1. Create the app registration

1. Entra admin portal → **App registrations → New registration**.
2. **Name:** e.g., `fbsts-validator`.
3. **Supported account types:** "Accounts in this organizational directory only (single tenant)". Multi-tenant works too but complicates the issuer URL (see Caveats).
4. **Redirect URI:** skip for now — we'll configure the platform in the next step.
5. Register.
6. Note the **Application (client) ID** — this is the `client_id` you'll put in the fbsts config.

### 2. Configure the platform

1. Open the app → **Authentication** → **Add a platform** → **Mobile and desktop applications**.
2. Add the **`https://login.microsoftonline.com/common/oauth2/nativeclient`** redirect URI (pre-filled checkbox).
3. Save.

### 3. Enable public client flows

Still on the **Authentication** page:

1. Scroll to **Advanced settings**.
2. **Allow public client flows:** **Yes**.
3. Save.

> **Caveat:** This is the single most common first-attempt failure point. If it's off (the default), the token endpoint returns `AADSTS7000218` asking for `client_assertion` or `client_secret` — even though device code flow doesn't use either.

### 4. Expose the app so `/.default` resolves

1. **Expose an API** → at the top, next to **Application ID URI**, click **Add**. Accept the default (`api://<your-client-id>`). Save.
2. This step makes the `<client-id>/.default` scope resolvable to your app rather than falling through to Microsoft Graph.

You don't need to add scopes under "Expose an API" for fbsts's purposes — the `.default` shortcut uses the consented set. But the Application ID URI must be set.

### 5. Configure a groups claim (optional but usually desired)

By default, Entra does not emit a `groups` claim in JWTs. To add one:

1. **Token configuration** → **Add groups claim**.
2. Pick which groups to include (Security groups, Directory roles, or All).
3. Under **ID** (and optionally Access), configure what to emit as the value:
   - **Group ID** (GUIDs) — default, works everywhere but produces unreadable trust policies
   - **`sAMAccountName`** — readable, but only works for groups synced from on-prem Active Directory
   - **`Cloud-only group display names`** — readable for cloud-only groups
4. Save.

> **Caveat:** In hybrid tenants, some groups are AD-synced and others are cloud-only. Picking `sAMAccountName` leaves cloud-only groups as GUIDs. Picking `Cloud-only group display names` leaves AD-synced groups as GUIDs. Pick the option that matches your majority case, then expect the trust policy to have a mix of readable and opaque values.

### 6. Assign users and groups

1. **Entra admin portal → Enterprise applications → [your app] → Users and groups**.
2. Add the users/groups that should be able to authenticate.
3. If your tenant enforces assignment ("Assignment required: Yes" on the enterprise application's Properties page), only assigned identities can complete device login.

### 7. fbsts TOML config

```toml
[entraid]
issuer_url = "https://login.microsoftonline.com/<tenant-id>/v2.0"
client_id  = "<application-client-id>"
# Use the raw client-ID/.default form, NOT api://<client-id>/.default
# (see Caveats below for why).
scopes     = ["openid", "profile", "<application-client-id>/.default"]
```

Replace both occurrences of `<application-client-id>` with the same GUID from step 1.

## Caveats and Things to Watch Out For

- **Use the tenant-specific issuer URL, not `common` or `organizations`.** The JWT's `iss` claim contains the *actual* tenant ID, not the placeholder you authenticated against. If you use `https://login.microsoftonline.com/common/v2.0`, the issued JWT still has `iss = https://login.microsoftonline.com/<tenant-id>/v2.0`, and the FlashBlade OIDC provider config won't match unless you hardcode the tenant-specific URL.
- **Use the v2.0 endpoint.** `/v2.0` appended to the tenant URL gives you a proper JWT with a `scp` claim and a clean `aud`. The v1.0 endpoint issues a different token format that's harder to write trust policies for.
- **`<client-id>/.default` vs. `api://<client-id>/.default`.** When the client and the resource are the same app (the default fbsts setup), Entra returns `AADSTS90009` on `api://<client-id>/.default` and explicitly says to use the raw GUID form. The `api://...` form is only appropriate when there's a separate resource server. Always use `<client-id>/.default` for fbsts.
- **Bare GUID as a scope hits Microsoft Graph.** If you put just the client ID (no `/.default` suffix) as a scope, Entra can't resolve it against your app and falls through to Microsoft Graph, which has never heard of it — you'll get `AADSTS650053`. The `/.default` suffix is what anchors it to your app.
- **Group values default to GUIDs.** Without the Token configuration step, `jwt:groups` contains tenant-level object GUIDs. Trust policies still work — they just look like `ForAnyValue:StringEquals jwt:groups [8a3b1c2d-..., d4e5f6g7-...]`. For human-readable policies, configure the groups claim emission as described in step 5.
- **"Assignment required" vs. "Anyone in your tenant".** If you don't require assignment, any user in the tenant can complete device login. If you do, only explicitly-assigned users can. This is a consequential decision — think about whether you want random tenant members to be able to authenticate against your FlashBlade role.
- **Conditional Access policies can block device code flow.** If your tenant has a Conditional Access policy requiring MFA or compliant device, device code flow may get blocked mid-auth. Check CA logs if you hit a mysterious failure after the user completes the browser portion.

## Troubleshooting

| Error code / symptom | Likely cause | Fix |
|---|---|---|
| `AADSTS650053` — "scope doesn't exist on resource `00000003-0000-0000-c000-000000000000`" | Scope passed as bare GUID; Entra fell back to Microsoft Graph | Change the scope to `<client-id>/.default` |
| `AADSTS90009` — "Application is requesting a token for itself. This scenario is supported only if resource is specified using the GUID" | Used `api://<client-id>/.default` when the client and resource are the same app | Change the scope to `<client-id>/.default` (raw GUID form) |
| `AADSTS7000218` — "request body must contain `client_assertion` or `client_secret`" | App registration is not configured as a public client | **Authentication → Advanced settings → Allow public client flows = Yes** |
| `AADSTS500011` — "resource principal not found" | Application ID URI not set on **Expose an API** | Set it (defaults to `api://<client-id>`) |
| `AADSTS65001` — "user or administrator has not consented" | User hasn't consented to the requested scopes | Either grant admin consent on **API permissions**, or have the user consent during device login |
| JWT has no `groups` claim | Token configuration's groups claim not added | Add it under **Token configuration → Add groups claim** |
| JWT groups are GUIDs, not names | Emission mode set to Group ID (default) | Change the emission under Token configuration (`sAMAccountName` for AD-synced groups, Cloud-only display names for cloud groups) |
| STS `InvalidIdentityToken: Audience mismatch` | FB OIDC provider audience doesn't include the JWT's `aud` (your client ID) | Update the FB OIDC provider config to accept the client ID as an audience |
| STS `InvalidIdentityToken: Issuer mismatch` | FB OIDC provider issuer URL doesn't exactly match the JWT's `iss` | Use the tenant-specific v2.0 URL consistently on both sides |

## Decoding a Real JWT to Check

If you're unsure whether the issued JWT has the expected shape, emit one and decode it:

```bash
fbsts validate --idp entraid --config ./fbsts.toml --emit-token ./entra.jwt
fbsts decode ./entra.jwt
```

Look for:
- `iss` — must be `https://login.microsoftonline.com/<tenant-id>/v2.0`
- `aud` — must be your app's client ID (`407c...` style GUID), NOT `00000003-0000-0000-c000-000000000000` (which is Graph)
- `tid` — your tenant GUID
- `oid` — the user's stable object ID
- `groups` — present if Token configuration step was done; values depend on emission mode
- `upn` — the user's principal name (e.g., `alice@contoso.com`)

## Related

- [Okta setup](okta.md)
- [Keycloak setup](keycloak.md)
- [fbsts trust-policy guide in the main README](../../README.md#trust-policy-generation)
