# Identity Provider Setup Guides

Step-by-step setup for each identity provider fbsts supports. Each guide covers the minimum IDP-side configuration, the corresponding fbsts TOML config, caveats, and troubleshooting for the common errors.

- [Okta](okta.md)
- [Keycloak](keycloak.md)
- [Microsoft Entra ID](entraid.md)

## Which IDP should I pick?

Any of them work. Pick the one your org already uses — fbsts abstracts the auth flow, so the STS/S3 validation output is identical regardless of IDP.

## Common setup steps across all IDPs

1. **Create an OIDC application / client** configured as a **public client** with the **device authorization grant** enabled. (Each IDP labels this differently — see the individual guides.)
2. **Configure a `groups` claim** (or equivalent authorization claim) so the JWT carries the group membership that your FlashBlade trust policy will match on.
3. **Note the `client_id` and the full issuer URL** — these go into the fbsts config.
4. **Register the IDP on the FlashBlade** under Settings → Single Sign-On with the OIDC discovery URL (`<issuer>/.well-known/openid-configuration`).
5. **Apply a trust policy** on the target role that matches the claims your IDP actually emits. The `fbsts trust-policy` subcommand can generate one directly from a captured JWT:

   ```bash
   fbsts validate --idp <idp> --emit-token ./token.jwt
   fbsts trust-policy ./token.jwt --principal <oidc-provider-name-on-fb>
   ```

After setup, validate end-to-end:

```bash
fbsts validate --idp <idp> --config ./fbsts.toml
```
