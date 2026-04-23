# Okta Setup

Step-by-step guide for configuring Okta as an identity provider for fbsts.

## Prerequisites

- An Okta org with admin access
- A default or custom **Authorization Server** (most orgs use the default one at `https://<tenant>.okta.com/oauth2/default`; you can also use the org authorization server at `https://<tenant>.okta.com` without a path)
- Test users and groups that match the trust policy you intend to apply on the FlashBlade

## Step-by-Step Setup

### 1. Create the OIDC application

1. In the Okta admin console, go to **Applications → Applications → Create App Integration**.
2. Choose **OIDC - OpenID Connect**.
3. Application type: **Native Application** (this is required for the device authorization grant).
4. Give the app a name and save.

### 2. Enable the device authorization grant

On the new application's page:

1. Go to the **General** tab → **General Settings** → Edit.
2. Under **Grant type**, check **Device Authorization**.
3. Save.

> **Caveat:** Okta hides the Device Authorization grant behind the Native app type. If you chose "Web Application" or "Single-Page Application", the checkbox won't be available and you'll need to create the app fresh as Native.

### 3. Assign users and groups

1. **Assignments** tab → **Assign** → pick individual users or groups.
2. Only assigned users can complete the device login flow against this app.

### 4. Configure the groups scope and claim

This is what makes the `groups` claim show up in the issued JWT. Two pieces are needed:

**Scope:**

1. Go to **Security → API → Authorization Servers** → pick your authorization server (e.g., `default`).
2. **Scopes** tab → **Add Scope** → name it `groups`, display name `groups`. Save.

**Claim:**

1. Same authorization server, **Claims** tab → **Add Claim**.
2. Name: `groups`. Include in token: **ID Token**, Always. Value type: **Groups**. Filter: **Matches regex** `.*` (or a narrower regex if you want to emit only specific groups).
3. Save.

> **Caveat:** If you're using the **default** authorization server, the above is all you need. If you're using the **org** authorization server (`https://<tenant>.okta.com` with no path), the Scopes and Claims UI is under a different part of the admin console and `groups` behaves slightly differently — the default authorization server is generally easier.

### 5. Capture the config values

From the application's **General** tab:

- **Client ID** — the value under "Client Credentials"
- **Issuer URL** — for the default authorization server, this is `https://<your-tenant>.okta.com/oauth2/default`. For the org authorization server, it's `https://<your-tenant>.okta.com` (no path). Check the authorization server's Metadata URI if in doubt — the `issuer` field is authoritative.

### 6. fbsts TOML config

```toml
[okta]
tenant_url = "https://<your-tenant>.okta.com/oauth2/default"
client_id  = "0oa1b2c3d4e5f6g7h8i9"
scopes     = ["openid", "profile", "groups"]
```

The `tenant_url` here is what we call the issuer URL on the Okta side — Okta's legacy naming carries through. It must match the `iss` claim that will appear in the JWT exactly.

## Caveats and Things to Watch Out For

- **Native app type is non-negotiable for device flow.** If you created the app as Web or SPA, recreate it — you can't flip the type.
- **`groups` is not emitted by default.** If your trust policy conditions on `jwt:groups` but the JWT doesn't carry one, STS will fail with `AccessDenied`. Confirm the claim is present with `fbsts decode ./token.jwt` before troubleshooting the FlashBlade side.
- **Authorization server choice matters.** Use the **default** authorization server (`/oauth2/default`) unless you have a specific reason to use the **org** authorization server. The JWKS endpoint and issuer URL differ between them, and the FlashBlade OIDC provider config must match whichever you pick.
- **Groups filter regex.** A broad `.*` emits every group the user belongs to. For large orgs this can bloat the JWT. Narrow the regex (e.g., `^flashblade-.*`) once you're confident about which groups the trust policy cares about.
- **User assignment vs. everyone-in-org.** By default, users must be explicitly assigned (or belong to an assigned group). If you set the app to "Allow everyone in your organization", the `groups` claim still won't populate unless the group-claim filter matches.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `invalid_grant` or the device-auth POST returns a 400 | Device Authorization grant not enabled on the app | Enable it in **General → Grant type → Device Authorization** |
| JWT has no `groups` claim | Missing scope, missing claim, or user not in any matching group | Add the `groups` scope and claim on the authorization server; verify the user's group memberships |
| STS `AccessDenied` with a JWT that *does* have groups | Trust policy conditions don't match the actual group names/IDs emitted | Run `fbsts trust-policy ./token.jwt --principal <fb-oidc-provider-name>` to generate a matching policy |
| STS `InvalidIdentityToken: Issuer mismatch` | FlashBlade OIDC provider's issuer URL doesn't match the JWT's `iss` | Confirm both sides use exactly the same issuer URL (default vs. org authorization server is the usual mismatch) |
| Device flow succeeds but no `id_token` is returned | The app wasn't configured to request `openid` scope | Make sure `scopes` includes `openid` in the fbsts config |

## Related

- [fbsts trust-policy guide in the main README](../../README.md#trust-policy-generation)
- [Entra ID setup](entraid.md)
- [Keycloak setup](keycloak.md)
