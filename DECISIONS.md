# Architecture Decision Records (ADR)

Decisions made during design of the Zero Trust Auth system.
Each record explains what was decided, why, and what alternatives were considered.

---

## ADR-001: Opaque tokens over JWT for access tokens

**Status:** Accepted

**Decision:** Use Opaque tokens (random strings) for `access_token` and `refresh_token`
issued to clients. Verify via Token Introspection (RFC 7662).

**Why:**
- Opaque tokens require introspection on every API request
- Introspection is the natural point to re-evaluate trust score
- This implements true Zero Trust: "verify at every request"
- JWT local verification would skip trust re-evaluation between refreshes
- Immediate revocation works — token state is server-side

**Why NOT JWT:**
- JWT is self-contained — resource server verifies locally without calling us
- This means trust score is evaluated only at token issuance, not continuously
- Revocation requires blocklist (additional complexity) or waiting for exp
- JWT TTL would need to be very short (1-2 min) to compensate — bad UX

**Tradeoff accepted:**
Every API request requires one extra network call (introspection).
This is the cost of continuous Zero Trust verification.

**Note:** Keycloak still uses JWT internally for its own id_token.
We read id_token once (to get sub/roles), then discard it.
Our system issues its own Opaque tokens for client use.

---

## ADR-002: Keycloak as Identity Provider

**Status:** Accepted

**Decision:** Use Keycloak as the IAM solution for user storage, login UI, MFA, and social login.

**Why:**
- Mature, battle-tested (10+ years production use)
- CNCF incubating project (transferred from Red Hat, April 2023)
- Handles all boring-but-critical parts: password hashing, TOTP, WebAuthn, email verification
- Social login connectors (GitHub, Google, LDAP) via configuration, not code
- Admin UI for user management
- Our service never sees user passwords — Zero Trust principle applied to our own code

**Alternatives considered:**
- Ory Hydra + Kratos: Go-native, lighter, but requires writing login UI from scratch
- Dex: Good for federation proxy, not a standalone user store
- Zitadel: Go-native, multi-tenant, but younger and smaller community
- Writing our own: months of security-critical work (argon2id, TOTP RFC 6238, WebAuthn)

**What Keycloak does NOT do (our responsibility):**
- Adaptive trust scoring
- Token family rotation with reuse detection
- Continuous session re-evaluation
- OPA policy enforcement

---

## ADR-003: IDPAdapter pattern

**Status:** Accepted

**Decision:** Introduce a dedicated IDPAdapter service that isolates all Keycloak-specific logic.
Gateway does not communicate with Keycloak directly.

**Why:**
- If we switch from Keycloak to Google, Auth0, or another IDP — only IDPAdapter changes
- Gateway, Auth, Trust, Token services have zero IDP-specific code
- IDPAdapter owns its own PKCE flow with Keycloak (independent from client's PKCE with Gateway)
- Clean separation: IDPAdapter answers "who is this person", Gateway answers "what can they do"

**IDPAdapter responsibilities:**
- Generate own PKCE (idp_code_verifier/challenge) for Keycloak
- Handle /callback from browser after Keycloak login
- Exchange code for id_token at Keycloak
- Extract sub, email, roles from id_token
- Call Auth Service to resolve sub → internal user_id
- Call Gateway on private port with resolved identity

---

## ADR-004: Private port for IDPAdapter → Gateway callback

**Status:** Accepted

**Decision:** IDPAdapter calls Gateway on an internal-only port after resolving user identity.
user_id is never placed in a browser-visible URL.

**Why:**
- GET redirect URLs appear in: browser address bar, browser history, proxy logs, Referer header
- user_id in URL = information disclosure
- Internal Docker/k8s network call is not visible to browser or proxies

**Implementation:**
```yaml
# docker-compose.yml
gateway:
  ports:
    - "443:443"   # public
  expose:
    - "8081"      # private — only accessible within Docker network
```

**Alternative considered:** State token in redirect URL (`/continue?state=xyz`)
- state is opaque (random string), so it's safer than user_id
- But still requires an extra lookup step
- Private port call is cleaner and more direct

---

## ADR-005: Two-phase trust evaluation

**Status:** Accepted

**Decision:** Trust Service is called twice per login flow.

**Phase 1 — Anonymous (before login):**
- Triggered by: `GET /authorize` arriving at Gateway
- Input: ip, user_agent, tls_fingerprint only
- Purpose: Block known-bad IPs, Tor exits, bot traffic, rate limiting
- No personal trust score — user is not identified yet

**Phase 2 — Personal (after login):**
- Triggered by: IDPAdapter callback to Gateway with user_id
- Input: user_id + full request context
- Purpose: Compute personal trust score using login history
- Impossible travel, device recognition, working hours pattern

**Why two phases:**
Phase 1 prevents unnecessary load on Keycloak login page from bots.
Phase 2 uses personal history which is only available after authentication.

---

## ADR-006: Token family rotation with reuse detection

**Status:** Accepted

**Decision:** Implement refresh token rotation with token family tracking.
Any attempt to reuse an already-consumed refresh token triggers full family revocation.

**Why:**
- Refresh token theft detection (RFC 9700 recommendation)
- One stolen refresh token does not give permanent access
- Reuse of consumed token = strong signal of theft

**Flow:**
```
refresh_token presented
    → look up token hash in Redis
    → if status == CONSUMED → theft detected
        → revoke entire family_id (all sessions)
        → notify user
    → if status == ACTIVE
        → mark CONSUMED
        → issue new refresh_token (same family_id)
        → issue new access_token
```

---

## ADR-007: OPA as Policy Decision Point

**Status:** Accepted

**Decision:** Use Open Policy Agent (OPA) as external PDP. Deploy as standalone Docker container.
Gateway is PEP, OPA is PDP. Policies written in Rego.

**Why OPA over custom policy microservice:**
- CNCF graduated project — audited, production-proven
- Declarative Rego policies — readable as business rules
- Hot reload without service restart (`--watch` flag)
- Built-in audit log of every decision
- Built-in policy unit testing (`opa test`)
- In-memory evaluation — sub-millisecond decision latency

**Why NOT embedded in Gateway:**
- OPA as sidecar keeps policy logic separate from enforcement logic
- Policies can be updated by security team without Go code changes
- Visible as distinct architectural component (PDP/PEP separation per NIST SP 800-207)

**Policy model:** Hybrid RBAC + ABAC
- RBAC: role determines base permissions
- ABAC: trust_score, time_of_day, resource classification add contextual constraints

**OPA never sees raw tokens** — Gateway performs introspection first,
then sends unpacked semantic context to OPA as JSON input.

---

## ADR-008: Gateway as Authorization Server for clients

**Status:** Accepted

**Decision:** Gateway implements OAuth 2.0 Authorization Code Flow for client apps.
Gateway is the Authorization Server from the client's perspective.
Keycloak is hidden behind IDPAdapter — clients have no knowledge of it.

**Two-level OAuth:**
```
Level 1: Client ↔ Gateway (our OAuth AS)
  - Client generates code_verifier + code_challenge
  - Gateway issues own_code after full trust evaluation
  - Client exchanges own_code + code_verifier → our opaque tokens

Level 2: IDPAdapter ↔ Keycloak (Keycloak as OAuth AS)
  - IDPAdapter generates idp_code_verifier + idp_code_challenge
  - Keycloak issues idp_code after user login
  - IDPAdapter exchanges idp_code → id_token (used internally, never sent to client)
```

**own_code generation:**
Gateway generates a random one-time code after trust evaluation.
Stores context (user_id, roles, trust_score, code_challenge) in Redis with 60s TTL.
Client receives this code in redirect, exchanges it at `POST /token`.

---

## ADR-009: Roles sourced from Keycloak id_token

**Status:** Accepted

**Decision:** User roles are stored in Keycloak and embedded in id_token.
IDPAdapter extracts roles from id_token claims (`realm_access.roles`).
No separate roles database in our system.

**Why:**
- Keycloak is already the source of truth for user identity
- Roles in id_token = zero extra DB calls per login
- Admin manages roles in Keycloak Admin UI
- If role changes mid-session: next token refresh picks up new roles

**Limitation:**
Role changes take effect at next refresh (up to 15 min delay with opaque tokens + introspection).
For immediate role revocation: admin can force-logout user via Admin API.

---

## ADR-010: Device fingerprint from HTTP signals only

**Status:** Accepted

**Decision:** Device identification uses only signals available in HTTP requests:
TLS JA3 fingerprint, User-Agent, and login history comparison.
No MDM certificates, no mobile SDK jailbreak detection.

**Why:**
- System is a web service — browser clients don't provide MDM certificates
- mTLS client certificates require MDM infrastructure not in scope
- Jailbreak detection requires mobile SDK — not applicable to web
- JA3 + User-Agent + login history is sufficient for "known device" signal

**What this means for trust scoring:**
Device signal is binary: "seen this fingerprint before" vs "never seen".
No MDM enrollment bonus, no jailbreak penalty — these signals are absent, not zero.

---

## ADR-011: Go as implementation language

**Status:** Accepted

**Decision:** All custom services (Gateway, IDPAdapter, Auth, Trust, Token, Audit) implemented in Go.

**Why:**
- Single static binary — trivial deployment, no runtime dependencies
- Goroutines — efficient concurrent handling of introspection calls
- Strong standard library: net/http, crypto, encoding/json
- Fast compilation — short feedback loop
- go-oidc, golang.org/x/oauth2 — mature OIDC/OAuth libraries
- OPA has first-class Go SDK (embedded or REST)
- Consistent technology across all services — one language to maintain
