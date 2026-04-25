# FlashBlade-Side Setup

The FlashBlade-side configuration is the same regardless of whether you're using federation or client assertion: the array trusts the **IDP that issued the JWT presented at STS**, not the original platform.

For federation: FB trusts Entra / Okta / Keycloak (which trust the K8s cluster or GitHub Actions).
For client assertion: FB trusts Entra / Okta / Keycloak (which trust the registered public key).

The shape on the FB side is identical. The only thing that varies is which claims appear in the IDP-issued JWT, which drives the trust policy conditions.

## Step 1: Register the OIDC provider on the array

Navigate: **FlashBlade GUI → Settings → Single Sign-On → OIDC Providers → Add**.

[Screenshot: FlashBlade GUI → Settings → Single Sign-On → OIDC Providers → Add]

Required input fields:

| Field | Value | Why |
|---|---|---|
| Provider name | Internal label (e.g., `entra-prod`, `okta-corp`, `keycloak-lab`) | Used by `fbsts trust-policy --principal` and in trust policy `Federated` principals |
| Issuer URL | The IDP's tenant-specific issuer URL — see "Cheat sheet" below | The FB validates the JWT's `iss` claim against this |
| Audience | The value that will appear as `aud` in the IDP-issued JWT | The FB validates the JWT's `aud` against this |
| JWKS URL | Auto-discovered from `<issuer>/.well-known/openid-configuration` | Override only if FB can't reach the discovery endpoint directly |

[Screenshot: filled-in OIDC Provider form]

Save. The provider is now eligible to be referenced in role trust policies.

## Step 2: Create or update the role

Navigate: **FlashBlade GUI → Storage → Object Store → Accounts → [account] → Roles → Create**.

[Screenshot: Storage → Object Store → Accounts → [account] → Roles → Create]

Required input fields:

| Field | Value | Why |
|---|---|---|
| Role name | Any role name (e.g., `app-uploader`, `ci-deploy`) | The role's identifier; appears in the role ARN |
| Account | The Object Store account you're working in | Scopes the role to one account |
| ARN format | `prn` (FlashBlade-native) or `aws` (AWS-compatible) — match what your apps expect | Determines the format of the role ARN |

The role's ARN will be displayed after save. Copy it — apps need this for the `RoleArn` field on `AssumeRoleWithWebIdentity`.

[Screenshot: role created with ARN visible]

## Step 3: Apply the trust policy

The trust policy is what restricts which JWTs can assume this role. It conditions on claims of the IDP-issued JWT.

Recommended workflow: capture a real JWT and let `fbsts trust-policy` generate the policy from it, then review and apply.

```bash
# 1. Capture an IDP-issued JWT from your federation or client-assertion flow
#    (interactively, or by running the exchange manually):
fbsts validate --idp <idp> --emit-token ./token.jwt

# 2. Generate a trust-policy rule from the JWT:
fbsts trust-policy ./token.jwt --principal <provider-name-from-step-1>

# 3. Review the JSON. Apply via the FlashBlade GUI / CLI / REST API.
```

[Screenshot: role's trust policy editor with example JSON]

For Entra-issued JWTs, the generator includes `tid`, `oid`, `upn`, and `roles` claims by default in addition to the standard `aud`, `sub`, `azp`, and `groups`. For Okta and Keycloak, only the standard set is included; add custom claims via `--condition`.

## Step 4: Validate with `fbsts`

Before integrating app code, validate the trust setup interactively:

```bash
fbsts validate --idp <idp> --role-arn <your-role-arn> --insecure
```

A successful run confirms:

- The OIDC provider on the FB is registered correctly (issuer + audience)
- The role exists with a valid trust policy that matches the JWT's claims
- The FB Data VIP is reachable and S3 operations work with the temporary credentials

If this passes interactively, the same configuration will work for non-interactive callers (federation or client-assertion patterns), assuming the JWTs they produce carry the same `iss` / `aud` and have claims that satisfy the trust policy.

## Reference: Required input fields cheat sheet

For Step 1, the exact issuer URL and typical audience format per IDP:

| IDP | Issuer URL | Typical audience |
|---|---|---|
| Microsoft Entra ID | `https://login.microsoftonline.com/<tenant-id>/v2.0` | Application (client) ID, e.g., `407c9831-d155-40e9-8def-06d5606b4a5e` |
| Okta (default authorization server) | `https://<tenant>.okta.com/oauth2/default` | Whatever was configured via Okta's audience mapper; often `api://default` or the client ID |
| Okta (org authorization server) | `https://<tenant>.okta.com` | Same as above |
| Keycloak | `https://<keycloak-host>/realms/<realm>` | Whatever was configured via Keycloak's audience mapper; often the client ID |

When in doubt, run `fbsts decode ./your-jwt.txt` to see the actual `iss` and `aud` values your IDP is producing.
