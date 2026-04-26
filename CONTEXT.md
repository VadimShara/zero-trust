# Project Context for Claude Code

## What this project is

Zero Trust authentication and access control system implementing:
- OAuth 2.0 Authorization Code Flow + PKCE (RFC 6749, RFC 7636, RFC 9700)
- OpenID Connect 1.0 via Keycloak as IDP
- Adaptive trust scoring (0.0–1.0) re-evaluated at every API request
- Opaque tokens + Token Introspection (RFC 7662) — never JWT for client tokens
- OPA as Policy Decision Point with hybrid RBAC + ABAC model
- Token family rotation with reuse detection

## Read these files before doing anything

1. `ARCHITECTURE.md` — full system design, all services, storage schemas
2. `DECISIONS.md` — why each decision was made (11 ADRs)
3. `SEQUENCE.md` — Mermaid sequence diagrams for all flows
4. `SERVICES.md` — project structure, HTTP APIs, Redis/PG schemas, env vars

## Language and stack

- **Go 1.22** — all custom services
- **Single go.mod** — one module `github.com/your-org/zero-trust-auth`
- Each service has its own `cmd/main.go`, built separately:
  `go build ./services/gateway/cmd/...`
- **No web framework** — standard `net/http` + `chi` router
- **toolkit/pkg/** — shared code imported by all services

## Directory structure inside each service

```
services/{name}/
├── cmd/
│   └── main.go      ← entrypoint, wires dependencies
└── internal/
    ├── adapter/     ← outbound infrastructure (postgres, redis, kafka, http clients)
    │                ← implements port/ interfaces
    ├── cases/       ← use cases, application logic
    │                ← imports only entities/ and port/
    ├── entities/    ← domain entities, value objects
    │                ← zero external dependencies
    └── port/        ← interfaces (repositories, service clients, publishers)
                     ← only interface definitions, no implementations
```

**Dependency rule:** `entities` ← `port` ← `cases` ← `adapter`
Nothing flows the other way. adapter imports port, never the reverse.

## Services (what we write in Go)

| Service | Public port | Private port | Role |
|---------|------------|--------------|------|
| gateway | 3000 | 8081 | OAuth AS for clients, orchestrator |
| idpadapter | — | 8080 | Keycloak adapter |
| auth | — | 8080 | sub → user_id mapping |
| trust | — | 8080 | Trust score computation |
| token | — | 8080 | Issue / introspect opaque tokens |
| audit | — | — | Kafka consumer, audit log |

## External products (not our code)

| Product | Port | Role |
|---------|------|------|
| Keycloak | 8080 (public) | IDP: user store, login UI, OIDC AS |
| OPA | 8181 (internal only) | Policy Decision Point |
| PostgreSQL | 5432 (internal) | Persistent storage |
| Redis | 6379 (internal) | Tokens, sessions, trust cache |
| Kafka | 9092 (internal) | Audit event bus |

## Critical decisions — do not change without reading DECISIONS.md

### 1. Opaque tokens, not JWT
Client tokens are random opaque strings stored in Redis.
Every API request → Token Introspection → trust score re-evaluated.
This is the core Zero Trust mechanism.
JWT would allow local verification — bypassing continuous trust evaluation.

### 2. Two independent PKCE flows
- **Client ↔ Gateway**: client generates `code_verifier`/`code_challenge`
  Gateway issues `own_code`, client exchanges it at `POST /token`
- **IDPAdapter ↔ Keycloak**: IDPAdapter generates its own `idp_code_verifier`/`idp_code_challenge`
  IDPAdapter exchanges `idp_code` for `id_token`
These are completely independent. Do NOT mix them.

### 3. IDPAdapter → Gateway via private port :8081
After resolving user identity, IDPAdapter calls:
`POST http://gateway:8081/internal/continue`
Port 8081 is NOT exposed outside Docker network.
`user_id` must NEVER appear in browser redirect URLs.

### 4. Roles from Keycloak id_token
Roles are stored in Keycloak, embedded in `id_token.realm_access.roles`.
IDPAdapter extracts them. No separate roles table in our system.
Role changes take effect at next token refresh.

### 5. OPA receives unpacked context, not raw token
Gateway does Token Introspection first → gets `{user_id, roles, trust_score}`.
Then sends this JSON to OPA as input. OPA never sees the token itself.

### 6. Trust score — five signals only (weights sum to 1.0)
```
device_known:  0.25  ← fingerprint seen in history?
ip_reputation: 0.20  ← residential vs datacenter/tor/vpn
geo_anomaly:   0.30  ← impossible travel (>900 km/h)
time_of_day:   0.15  ← within typical working hours?
velocity:      0.10  ← recent failed attempts counter
```
No MDM certificates, no jailbreak detection — web service only.
IPs stored as SHA256(ip + salt) for GDPR compliance.

### 7. Trust score re-evaluated at every introspection
Token Service calls Trust Service during every introspect call.
This gives true per-request Zero Trust verification.

## Full request flow (summary)

```
LOGIN:
1.  Client     → GET /authorize?code_challenge=...&state=...  (Gateway :3000)
2.  Gateway    → Trust: anonymousCheck(ip, ua, fingerprint)
3.  Gateway    → IDPAdapter: getLoginURL(state)
4.  IDPAdapter   generates idp_code_verifier + idp_code_challenge
5.  IDPAdapter → Gateway: loginURL (Keycloak URL with idp_code_challenge)
6.  Browser    → Keycloak: GET loginURL → login form → user enters credentials
7.  Keycloak   → Browser: redirect to IDPAdapter /idp/callback?code=idp_code&state=...
8.  IDPAdapter → Keycloak: POST /token {idp_code, idp_code_verifier} → id_token
9.  IDPAdapter   extracts sub, email, roles from id_token
10. IDPAdapter → Auth: POST /auth/resolve-user {sub} → user_id
11. IDPAdapter → Gateway:8081: POST /internal/continue {state, user_id, roles, ctx}
12. Gateway    → Trust: evaluateTrust(user_id, roles, ctx) → trust_score
13. Gateway      generates own_code, stores {user_id, roles, trust_score, code_challenge}
14. Gateway    → Browser: redirect to Client /callback?code=own_code&state=...
15. Client       verifies state matches original
16. Client     → Gateway: POST /token {own_code, code_verifier, client_secret}
17. Gateway      verifies SHA256(code_verifier)==code_challenge, verifies client_secret
18. Gateway      deletes own_code (one-time use)
19. Gateway    → Token: issue(user_id, roles, trust_score)
20. Client       receives access_token (opaque, TTL 15m) + refresh_token (opaque, TTL 7d)

PER API REQUEST:
21. Client     → GET /api/resource  Authorization: Bearer <opaque_token>
22. Gateway    → Token: introspect(token)
23. Token      → Trust: evaluateTrust(user_id, current_ctx) ← re-evaluated here
24. Token      → Gateway: {active, user_id, roles, trust_score, exp}
25. Gateway    → OPA: {user:{roles,trust_score}, resource, action}
26. OPA        → {result: allow/deny}
27. Gateway      enforces decision → 200 or 403
```

### 8. golang-migrate for database migrations
Each service owns its migrations in `services/{name}/migrations/`.
Files: `000001_description.up.sql` and `000001_description.down.sql`.
Services run migrations on startup via golang-migrate embedded in cmd/main.go.
auth service → authdb, trust service → trustdb, audit service → authdb (audit_log table).

## What Claude Code must NOT do

- Do NOT use JWT for client-facing access_token or refresh_token
- Do NOT expose gateway port 8081 to host in docker-compose
- Do NOT let Gateway call Keycloak directly — only via IDPAdapter
- Do NOT put user_id in browser redirect URLs
- Do NOT embed role/trust checks in service code — use toolkit/policies/authz.rego via OPA
- Do NOT store raw IP addresses — always SHA256(ip + salt)
- Do NOT import adapter/ or infrastructure packages in entities/ or port/
- Do NOT create go.work or separate go.mod per service — single go.mod only

## First prompt for Claude Code

```
Read CONTEXT.md, then ARCHITECTURE.md, DECISIONS.md, SEQUENCE.md, SERVICES.md.

After reading all five files, scaffold the project:

1. Create go.mod with module github.com/your-org/zero-trust-auth, Go 1.22,
   and dependencies from SERVICES.md

2. Create directory structure for all six services exactly as in SERVICES.md:
   services/{gateway,idpadapter,auth,trust,token,audit}/
   each with cmd/main.go and internal/{adapter,cases,entities,port}/

3. Create toolkit/pkg/ with logger/, errors/, tracing/, httpserver/, middleware/

4. Create toolkit/policies/authz.rego with the policy from SERVICES.md

5. Create .env.example with all variables from SERVICES.md

6. In each cmd/main.go write only: package main, func main() {}

7. In each internal file write only: package {dirname}

Do not write any business logic. Show directory tree after scaffolding.
```
