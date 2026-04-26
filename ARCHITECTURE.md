# Zero Trust Authentication System — Architecture

## Overview

Self-hosted authentication and access control system implementing OAuth 2.0 / OpenID Connect
with adaptive trust evaluation based on Zero Trust principles (NIST SP 800-207).

**Language:** Go  
**Deployment:** Docker / Kubernetes (self-hosted, on-premise or private cloud)  
**IdP:** Keycloak (CNCF incubating, transferred from Red Hat in 2023)

---

## System Topology

```
Client App
    │
    │  OAuth 2.0 Authorization Code Flow + PKCE
    ▼
API Gateway  ──────────────────────────────────────────────┐
    │                                                       │
    │ private port (internal network only)                  │
    │                                                       │
IDPAdapter ──► Keycloak (IDP + AS)                        Trust Service
    │               └── POST /token (exchange code)         │
    │               └── GET /.well-known/openid-config       │
    │               └── GET /certs (JWKS)                   │
    │                                                       │
    └──────────────────────────────────────────────────────►│
                                                            │
                                              OPA (Policy Decision Point)
                                                            │
                                              Token Service (issue/introspect)
                                                            │
                                              Audit Service (Kafka consumer)
```

---

## Services

### 1. API Gateway
**Role:** Single entry point, OAuth 2.0 Authorization Server for client apps, orchestrator.

**Responsibilities:**
- Accept `GET /authorize` from client, validate `client_id`, rate limiting
- Collect anonymous risk signals: IP, User-Agent, TLS JA3 fingerprint
- Forward to Trust Service for anonymous check before login
- Redirect browser to Keycloak login URL (via IDPAdapter)
- Accept internal callback from IDPAdapter on private port
- Call Trust Service for full trust evaluation after user identity is known
- Generate `own_code` (authorization code for client), store context in Redis (TTL 60s)
- Handle `POST /token`: verify PKCE (`SHA256(code_verifier) == stored code_challenge`), verify `client_secret`, issue tokens via Token Service
- Forward all API requests to OPA for policy enforcement after token introspection

**PKCE state stored at Gateway:**
```
Redis key: session:{state}
Value: {
  code_challenge: "E9Melhoa2...",
  client_id:      "portal-app",
  ip:             "81.19.xx.xx",
  user_agent:     "...",
  created_at:     unix_timestamp
}
TTL: 10 minutes
```

**own_code stored at Gateway:**
```
Redis key: authcode:{own_code}
Value: {
  user_id:     "usr_01HX",
  roles:       ["developer"],
  trust_score: 0.91,
  code_challenge: "E9Melhoa2..."
}
TTL: 60 seconds (one-time use, deleted after /token exchange)
```

---

### 2. IDPAdapter
**Role:** OAuth 2.0 client to Keycloak. Thin adapter isolating IDP-specific logic.

**Responsibilities:**
- Generate own PKCE pair (`idp_code_verifier` + `idp_code_challenge`) for Keycloak communication
- Store `idp_code_verifier` keyed by `state` in Redis
- Return `loginURL` to Gateway (Keycloak authorize endpoint with `idp_code_challenge`)
- Handle `GET /callback?code=idp_code&state=...` from browser after Keycloak login
- Exchange `idp_code` for `id_token` via `POST /token` to Keycloak (with `idp_code_verifier`)
- Extract `sub`, `email`, `roles` from `id_token`
- Call Auth Service: `resolveUser(sub)` → `internal user_id`
- Call Gateway on **private port**: `POST /internal/continue { state, user_id, roles, requestCtx }`
- Redirect browser to Gateway `/callback?state=...`

**Why private port for Gateway call:**  
`user_id` must never appear in browser URL bar, browser history, proxy logs, or Referer headers.
Internal service-to-service call on a port not exposed outside Docker/k8s network.

**Two independent PKCE flows:**
```
Flow 1 (IDPAdapter ↔ Keycloak):
  idp_code_verifier → idp_code_challenge → Keycloak → idp_code → exchange → id_token

Flow 2 (Client ↔ Gateway):
  client's code_verifier → code_challenge → Gateway → own_code → exchange → our tokens
```

---

### 3. Auth Service
**Role:** Internal user identity resolution. Maps external IDP identifiers to internal ones.

**Responsibilities:**
- `resolveUser(sub string) → (userID string, error)`: look up or create internal user by IDP `sub`
- Store mapping: `idp_sub → internal_user_id` in PostgreSQL
- If first login: create user record, assign default roles

**Why mapping sub → internal_user_id:**  
`sub` is IDP-specific. If we switch from Keycloak to another IDP tomorrow, `sub` values change.
Internal `user_id` is stable and IDP-agnostic.

---

### 4. Trust Service
**Role:** Adaptive trust score computation. Heart of Zero Trust.

**Two-phase evaluation:**

**Phase 1 — Anonymous check** (before login, no user_id known):
- Input: `ip`, `user_agent`, `tls_fingerprint`
- Checks: IP reputation (abuse databases), ASN type (datacenter vs residential), bot User-Agent, rate limit
- Output: ALLOW (continue) or DENY (block immediately)
- Does NOT compute personal trust score — user is unknown

**Phase 2 — Full evaluation** (after login, user_id known):
- Input: `user_id`, `roles`, `ip`, `user_agent`, `device_fingerprint`, `timestamp`
- Computes weighted trust score from signals:

| Signal | Weight | Source |
|--------|--------|--------|
| Device known | 0.25 | Redis `trust:devices:{user_id}` |
| IP reputation | 0.20 | External API (cached in Redis, TTL 1h) |
| Geo anomaly (impossible travel) | 0.30 | Compare with Redis `trust:last:{user_id}` |
| Time of day | 0.15 | Compare with PG `trust_working_hours` |
| Velocity | 0.10 | Redis `trust:fails:{user_id}` |

**Impossible travel formula:**
```
distance_km / time_hours > 900 km/h → impossible_travel = true → score penalty -0.45
```

**Trust decisions:**
```
score ≥ 0.80 → ALLOW
0.50 ≤ score < 0.80 → MFA_REQUIRED
0.30 ≤ score < 0.50 → STEP_UP
score < 0.30 → DENY
```

**Trust score re-evaluation:**  
Since we use Opaque tokens with Token Introspection, trust score is re-evaluated
at every introspection call (every API request). This is true Zero Trust continuous verification.

**Storage:**
- PostgreSQL: `trust_device_fingerprints`, `trust_login_history`, `trust_working_hours`, `trust_scores_log`
- Redis: `trust:last:{user_id}` (TTL 30d), `trust:devices:{user_id}` (TTL 90d), `trust:fails:{user_id}` (TTL 15m), `trust:ip:{ip_hash}` (TTL 1h)

**Privacy note:** IP addresses stored as `SHA256(ip + salt)` — GDPR compliance, IP is personal data.

---

### 5. Token Service
**Role:** Issue and introspect Opaque tokens.

**Token types issued by our system:**

| Token | Type | TTL | Purpose |
|-------|------|-----|---------|
| `access_token` | Opaque | 15 min | API access, presented to resource server |
| `refresh_token` | Opaque | 7 days | Silent renewal, presented only to Auth/Gateway |

**Why Opaque (not JWT):**  
Opaque tokens enable true Zero Trust: every API request triggers Token Introspection,
which triggers Trust Score re-evaluation. JWT local verification would bypass this.

**Token storage in Redis:**
```
key: token:{sha256(access_token)}
value: {
  user_id:     "usr_01HX",
  roles:       ["developer"],
  trust_score: 0.91,
  device_id:   "dev_mac_01",
  session_id:  "ses_01HX",
  family_id:   "fam_01HX",
  created_at:  unix_ts,
  exp:         unix_ts
}
TTL: 15 minutes
```

**Refresh token rotation:**
```
1. Client sends refresh_token
2. Token Service looks up token hash → finds record
3. If status == CONSUMED → Token Reuse Attack detected:
   - Revoke entire token family (family_id)
   - Publish TokenReuseAttackDetected to Kafka
   - Notify user via Notify Service
4. If status == ACTIVE:
   - Mark old token as CONSUMED
   - Issue new access_token + new refresh_token (same family_id)
   - Store new tokens in Redis
```

**Introspection response (RFC 7662):**
```json
{
  "active": true,
  "user_id": "usr_01HX",
  "roles": ["developer"],
  "trust_score": 0.91,
  "exp": 1712345678
}
```

---

### 6. OPA (Open Policy Agent)
**Role:** Policy Decision Point (PDP). Deployed as standalone Docker container.

**Deployment:**
```yaml
opa:
  image: openpolicyagent/opa:latest
  command: run --server --watch /policies
  volumes:
    - ./policies:/policies
  expose:
    - "8181"  # internal only, not exposed to host
```

**How Gateway uses OPA:**
1. Gateway performs Token Introspection → gets `{user_id, roles, trust_score}`
2. Gateway sends to OPA:
```json
POST http://opa:8181/v1/data/authz/allow
{
  "input": {
    "user": { "roles": ["developer"], "trust_score": 0.91 },
    "resource": "secrets",
    "action": "read",
    "context": { "time_hour": 14 }
  }
}
```
3. OPA evaluates Rego policy → `{ "result": true/false }`
4. Gateway enforces decision

**OPA never sees the token itself** — only the unpacked semantic context after introspection.

**Example Rego policy (RBAC + ABAC hybrid):**
```rego
package authz

default allow = false

# Regular resources: role check + minimum trust
allow {
    input.user.roles[_] == required_role[input.resource]
    input.user.trust_score >= 0.60
}

# Sensitive resources: role + high trust + step-up
allow {
    input.resource == "secrets"
    input.user.roles[_] == "developer"
    input.user.trust_score >= 0.85
    input.user.step_up == true
}

required_role := {
    "projects": "developer",
    "reports":  "viewer",
    "admin":    "admin"
}
```

---

### 7. Audit Service
**Role:** Kafka consumer. Writes immutable audit log.

**Publishes events (producers: Gateway, Token Service, Trust Service):**
- `UserLoggedIn`
- `UserLoggedOut`
- `AnomalousLoginDetected`
- `ImpossibleTravelDetected`
- `MfaChallengeIssued`
- `TrustDegraded`
- `TokenReuseAttackDetected`
- `AccessDenied`
- `AdminForcedLogout`

---

## Infrastructure

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Primary DB | PostgreSQL | User mappings, trust history, login history |
| Cache / Sessions | Redis | Tokens, sessions, trust context cache |
| Event bus | Kafka | Audit events, async notifications |
| Secrets | HashiCorp Vault | Service credentials, signing keys |
| Tracing | Jaeger | Distributed tracing |
| Metrics | Prometheus + Grafana | Observability |
| IDP | Keycloak | User store, login UI, OIDC/OAuth AS |
| Policy engine | OPA | PDP, Rego policies |

---

## Key Design Decisions

See [DECISIONS.md](./DECISIONS.md) for full ADR list.

**Summary:**
- Opaque tokens over JWT → enables continuous trust re-evaluation per request
- Keycloak as IDP → mature, CNCF, handles user store / MFA / social login
- IDPAdapter pattern → IDP-agnostic, swap Keycloak for Google/Auth0 without touching Gateway
- OPA as PDP → declarative policies, hot reload, audit log, CNCF graduated
- Private port for IDPAdapter→Gateway → user_id never in browser URL
- Token family rotation → detect theft, revoke entire family on reuse
- Two-phase trust evaluation → anonymous check before login, personal score after
