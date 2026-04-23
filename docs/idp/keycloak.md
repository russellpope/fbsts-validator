# Keycloak Setup

Step-by-step guide for configuring Keycloak as an identity provider for fbsts.

## Prerequisites

- A running Keycloak instance, version 20+ recommended (tested through 25.x)
- Admin access to a realm (create a realm for testing if you don't have one)
- Keycloak must be reachable via HTTPS from the FlashBlade for JWKS retrieval; dev-mode HTTP won't work end-to-end

## Step-by-Step Setup

### 1. Create the client

1. In the Keycloak admin console, select your realm → **Clients → Create client**.
2. **Client type:** OpenID Connect.
3. **Client ID:** pick something like `fbsts-cli`.
4. **Name / description:** optional.
5. Next page — **Capability config:**
   - **Client authentication:** **Off** (this makes it a public client — required for device code flow without a secret).
   - **Authorization:** Off.
   - **Authentication flow:** leave the standard flow enabled.
   - **OAuth 2.0 Device Authorization Grant:** **On** ← this is easy to miss.
6. **Login settings** page — root URL / home URL are optional; leave blank.
7. Save.

> **Caveat:** The "OAuth 2.0 Device Authorization Grant" toggle is on the Capability config page during client creation. It's also editable after the fact under **Settings → Capability config** on the client page, but it's collapsed by default and easy to miss.

### 2. Configure a groups claim (required for most trust policies)

Keycloak does not emit a `groups` claim by default. Add a protocol mapper:

1. Open the client you just created.
2. **Client scopes** tab → find `<client-id>-dedicated` (created automatically) → click it.
3. **Mappers** tab → **Add mapper → By configuration → Group Membership**.
4. Fill in:
   - **Name:** `groups`
   - **Token Claim Name:** `groups`
   - **Full group path:** **Off** (turn this off unless you want `/parent/child` formatted values — trust policies are easier with flat group names)
   - **Add to ID token:** **On**
   - **Add to access token:** On (optional)
   - **Add to userinfo:** On (optional)
5. Save.

### 3. Create users and groups

If you don't already have realm users and groups:

1. **Groups → Create group** → name it (e.g., `flashblade-admins`). Save.
2. **Users → Create new user** → fill in username and email → Save.
3. On the user's page, **Credentials** tab → set a password.
4. **Groups** tab → Join the group you created.

### 4. Note the issuer URL and client ID

The issuer URL is `<keycloak-base-url>/realms/<realm-name>` (no trailing slash). The client ID is what you entered in step 1.

Verify by hitting the discovery endpoint:

```bash
curl https://keycloak.example.com/realms/my-realm/.well-known/openid-configuration | jq .issuer
```

The `issuer` field must match what you'll put in the fbsts config exactly.

### 5. fbsts TOML config

```toml
[keycloak]
issuer_url = "https://keycloak.example.com/realms/my-realm"
client_id  = "fbsts-cli"
scopes     = ["openid", "profile"]
```

## Caveats and Things to Watch Out For

- **Realm path is part of the issuer URL.** Keycloak issuer URLs always include `/realms/<name>`. Don't truncate to the base hostname.
- **Public client means no client secret.** The "Client authentication: Off" toggle is what makes this a public client. If you turn it On later, you'll get a `invalid_client` error on the token endpoint because fbsts doesn't send a secret.
- **Device Authorization Grant toggle defaults to Off.** The most common first-attempt failure is "everything looks fine in Keycloak" but discovery's `device_authorization_endpoint` is missing — because the toggle is off. fbsts's error message hints at this.
- **Group membership mapper's "Full group path" setting changes claim values.** On produces `/flashblade-admins`, off produces `flashblade-admins`. Trust policies must match whichever form you chose. Mixing the two silently breaks policy matching.
- **FlashBlade needs HTTPS.** Keycloak in dev mode defaults to HTTP, which the FlashBlade won't trust for the JWKS fetch. Run Keycloak with `--https-port=8443` and a TLS cert (self-signed is fine for a lab — just add it to the FlashBlade's trusted CA list), or front Keycloak with an HTTPS reverse proxy.
- **Keycloak 25+ `organization` feature.** New organization/protocol-mapper features introduced in Keycloak 25 can interact oddly with device code flow. If you see unexpected 500 errors from the token endpoint on a brand-new Keycloak 25+ instance, try starting with `--features-disabled=organization` until the issue is isolated.
- **Client audience.** By default, the issued token's `aud` claim is the client ID. If you need a different audience for the FlashBlade OIDC provider config, add an **Audience** mapper on the client's dedicated scope.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Discovery fails with "OIDC discovery missing device_authorization_endpoint — ensure the Keycloak client has 'OAuth 2.0 Device Authorization Grant' enabled" | Device Authorization Grant toggle is off | Enable it under **Clients → [your client] → Settings → Capability config** |
| Token polling returns `invalid_client` | Client has "Client authentication: On" (now a confidential client) | Turn Client authentication **Off** in the client's Capability config |
| JWT has no `groups` claim | Group Membership mapper missing or "Add to ID token" is off | Add the mapper (see step 2) and confirm "Add to ID token" is on |
| Group values have `/` prefixes | "Full group path" is on in the Group Membership mapper | Turn it off (or update your trust policy to match the path form) |
| STS `InvalidIdentityToken: Signature validation failed` | FlashBlade can't reach the JWKS endpoint, or TLS to Keycloak isn't trusted | Verify the FlashBlade's DNS resolves Keycloak; add Keycloak's CA (or self-signed cert) to the FB trust store |
| STS `InvalidIdentityToken: Audience mismatch` | FB OIDC provider's audience doesn't include the JWT's `aud` (your client ID) | Update the FB OIDC provider config, or add an Audience mapper on the client |

## Related

- [Okta setup](okta.md)
- [Entra ID setup](entraid.md)
- [fbsts trust-policy guide in the main README](../../README.md#trust-policy-generation)
