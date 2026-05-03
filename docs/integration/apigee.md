# Apigee Integration Patterns for FlashBlade STS

Apigee can interact with the FlashBlade STS / OIDC story in three distinct ways depending on the role you want it to play. This document is research-grade — it lays out the three patterns and the tradeoffs so you can pick one before scoping a full step-by-step guide. Once a pattern is selected, the deeper guide should follow the same nine-section skeleton used by the existing federation and client-assertion spokes under `docs/integration/`.

---

## Pattern A — Apigee as the API gateway *in front of* FlashBlade

**What it does:** Clients call Apigee. Apigee validates an OIDC JWT (issued by Entra, Okta, Keycloak, or Apigee itself). On success, Apigee proxies the call to the FlashBlade STS endpoint or directly to S3 with already-minted temporary credentials.

**Apigee mechanism:** the **VerifyJWT** policy. Point it at the IDP's JWKS URL (auto-fetched from `<issuer>/.well-known/openid-configuration`); specify the expected `iss`, `aud`, and any required claim conditions. Apigee verifies signature, expiry, and claim values per request. Failed verification short-circuits with a 401; success extracts the claims into Apigee context variables for downstream policies.

**Where it shines:**

- You want a single API surface for clients (Apigee policies, rate limiting, analytics, mTLS termination, custom logging) and FlashBlade is one of several backends.
- The trust chain becomes: client → Apigee (validates OIDC JWT) → FlashBlade. FlashBlade's OIDC trust still references the original IDP (Entra/Okta/Keycloak), not Apigee.
- Reuses existing IDP work — no changes to the FlashBlade trust model.

**Where it doesn't:**

- If you want Apigee itself to be the principal that FlashBlade trusts (so the JWT FlashBlade sees was issued *by Apigee*), this isn't the right pattern — see Pattern B.

---

## Pattern B — Apigee as the IDP / token issuer

**What it does:** Apigee acts as the OIDC issuer that FlashBlade trusts. Apigee fronts a custom auth backend (LDAP, custom DB, anything) and exposes a `/token` endpoint that mints JWTs. FlashBlade's OIDC provider config points at Apigee's well-known URL and accepts Apigee-signed JWTs at STS `AssumeRoleWithWebIdentity`.

**Apigee mechanism:** a token-issuance proxy. Reference implementations exist in the community:

- Dino Chiesa's `Apigee-Edge-OIDC-Demonstration`
- The `nas-hub/apigee-as-oidc-idp-for-existing-authentication-service` repo

Apigee implements `/.well-known/openid-configuration`, a JWKS endpoint, and one or more grant types (typically `client_credentials`, `password`, or `jwt-bearer`) using the GenerateJWT policy.

**Where it shines:**

- You have a non-OIDC user store you can't easily federate (legacy SSO, custom LDAP, on-prem AD without ADFS) and you want a stable OIDC-shaped front for FlashBlade.
- Apigee becomes a thin OIDC adapter over your real auth.

**Where it doesn't:**

- More work to operate than standing up Keycloak (which is purpose-built for the IDP role and is already validated against fbsts).
- Pattern B makes sense if you're already deeply invested in Apigee; otherwise Keycloak / Entra / Okta is less effort.

---

## Pattern C — Apigee X workloads calling FlashBlade STS

**What it does:** Apigee X / Apigee Hybrid runs application logic that needs to access FlashBlade S3. The Apigee runtime itself uses workload identity federation to obtain credentials.

**Apigee mechanism (the GCP side):** Apigee Hybrid on AKS / EKS / GKE supports GCP workload identity federation natively. A pod running an Apigee runtime gets a Kubernetes-issued OIDC token, exchanges it via Google's Security Token Service for a short-lived GCP federated token, then impersonates a GCP service account.

**Apigee mechanism (the FlashBlade side):** that same Kubernetes-issued OIDC token can be federated *separately* through your existing IDP (Entra / Okta / Keycloak) to FlashBlade STS — exactly the pattern documented in [`kubernetes-federation.md`](kubernetes-federation.md). From FlashBlade's perspective, an Apigee pod is just a K8s pod with a SA token.

**Where it shines:**

- Apigee Hybrid deployments where you want one workload-identity story across both GCP and FlashBlade.
- Apigee pods don't hold any long-lived FlashBlade credentials.

**Where it doesn't:**

- Apigee X (managed) doesn't expose the underlying runtime, so you can't do K8s SA-token federation directly.
- For Apigee X, you'd need either:
  1. A small intermediary (Cloud Run / GKE pod) that does the federation and brokers credentials to your Apigee proxies, or
  2. Use Pattern A (Apigee gateways traffic; the *clients* hold the OIDC identity).

---

## Decision matrix

| Use case | Pattern |
|---|---|
| Clients call FlashBlade through an API surface; Apigee handles authn/authz at the edge | A |
| Apigee is the only identity surface available; non-OIDC user store needs to be presented as OIDC | B |
| Apigee Hybrid pods themselves need FlashBlade access for their own backend logic | C |
| Apigee X (managed) pods need FlashBlade access | A (clients hold identity) or a brokered variant of C |

---

## Recommendations

- **Most common case — clients calling FlashBlade through an API surface:** **Pattern A.** Apigee handles authn/authz at the edge, validates JWTs from your existing IDP, and proxies to FlashBlade. No changes to the FlashBlade trust model; you reuse the work already done with Entra / Okta / Keycloak.
- **You don't have a "real" IDP and Apigee is your only PaaS-ish identity surface:** **Pattern B.** Apigee plays IDP. More setup, but doable.
- **Apigee Hybrid pods that need FlashBlade access for their own backend logic:** **Pattern C.** Same K8s federation pattern as anything else running in those clusters.

---

## Next steps

When a customer commits to one of the three patterns, develop a full guide for that pattern under `docs/integration/apigee-<pattern>.md` mirroring the nine-section skeleton: When to Use, Architecture, Prerequisites, Step 1 (Apigee setup), Step 2 (IDP configuration if applicable), Step 3 (FlashBlade configuration), Step 4 (App / proxy code flow), Validation, Troubleshooting.

---

## References

- [VerifyJWT policy reference (Apigee X / Cloud)](https://docs.cloud.google.com/apigee/docs/api-platform/reference/policies/verify-jwt-policy)
- [VerifyJWT policy reference (Apigee Edge)](https://docs.apigee.com/api-platform/reference/policies/verify-jwt-policy)
- [JWS and JWT policies overview](https://docs.apigee.com/api-platform/reference/policies/jwt-policies-overview)
- [Apigee Edge OAuth2 and Third-Party Identity Providers — Robert Broeckelmann](https://medium.com/@robert.broeckelmann/apigee-edge-oauth2-and-third-party-identity-providers-48cc0eaedc3a)
- [Apigee + Okta OIDC integration reference (apigee/apigee-okta)](https://github.com/apigee/apigee-okta/blob/master/oidc_integration/README.md)
- [Apigee-as-OIDC-IdP demonstration — DinoChiesa](https://github.com/DinoChiesa/Apigee-Edge-OIDC-Demonstration/blob/master/README.md)
- [Apigee as an OIDC IdP for an existing auth service — nas-hub](https://github.com/nas-hub/apigee-as-oidc-idp-for-existing-authentication-service)
- [Enabling Workload Identity Federation on AKS and EKS — Apigee Hybrid (GCP docs)](https://cloud.google.com/apigee/docs/hybrid/v1.15/enable-workload-identity-federation)
- [Configure Workload Identity Federation with AWS or Azure VMs (GCP docs)](https://docs.cloud.google.com/iam/docs/workload-identity-federation-with-other-clouds)
- [Workload Identity Federation with GitLab and Apigee X — Erika Vazquez Lopez](https://medium.com/@erika.vazquez/workload-identity-federation-with-gitlab-and-apigee-x-d951d100763b)
- [Apigee Hybrid — Workload Identity Federation to replace GCP Service account Keys (Apigee community)](https://discuss.google.dev/t/apigee-hybrid-workload-identity-federation-to-replace-gcp-service-account-keys/147795)
