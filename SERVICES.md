# Services Reference

## Project Structure (Single go.mod — Monorepo)

```
zero-trust-auth/
├── go.mod                           ← one module: github.com/your-org/zero-trust-auth
├── go.sum
│
├── services/
│   ├── gateway/                     ← OAuth AS for clients, orchestrator
│   │   ├── cmd/
│   │   │   └── main.go
│   │   └── internal/
│   │       ├── adapter/             ← outbound: redis, kafka, http clients
│   │       │   ├── redis/
│   │       │   │   ├── session_store.go
│   │       │   │   └── authcode_store.go
│   │       │   ├── kafka/
│   │       │   │   └── event_publisher.go
│   │       │   └── http/
│   │       │       ├── trust_client.go
│   │       │       ├── token_client.go
│   │       │       ├── idpadapter_client.go
│   │       │       └── opa_client.go
│   │       ├── cases/               ← use cases / application logic
│   │       │   ├── authorize.go     ← handle GET /authorize
│   │       │   ├── exchange_code.go ← handle POST /token (own_code → tokens)
│   │       │   ├── refresh.go       ← handle POST /token (refresh)
│   │       │   ├── logout.go
│   │       │   └── continue.go      ← handle POST /internal/continue (private port)
│   │       ├── entities/            ← domain entities / value objects
│   │       │   ├── oauth_session.go ← state → {code_challenge, client_id, ip}
│   │       │   └── auth_code.go     ← own_code → {user_id, roles, trust_score}
│   │       └── port/                ← interfaces
│   │           ├── session_store.go
│   │           ├── authcode_store.go
│   │           ├── trust_service.go
│   │           ├── token_service.go
│   │           └── policy_engine.go
│   │
│   ├── idpadapter/                  ← Keycloak adapter, thin IDP bridge
│   │   ├── cmd/
│   │   │   └── main.go
│   │   └── internal/
│   │       ├── adapter/
│   │       │   ├── keycloak/
│   │       │   │   └── oidc_client.go  ← exchange code, verify id_token via JWKS
│   │       │   ├── redis/
│   │       │   │   └── pkce_store.go   ← state → idp_code_verifier
│   │       │   └── http/
│   │       │       ├── auth_client.go
│   │       │       └── gateway_client.go ← call gateway private port :8081
│   │       ├── cases/
│   │       │   ├── get_login_url.go    ← generate PKCE, build Keycloak URL
│   │       │   └── handle_callback.go  ← exchange code → id_token → resolve → gateway
│   │       ├── entities/
│   │       │   └── idp_identity.go     ← sub, email, roles from id_token
│   │       └── port/
│   │           ├── pkce_store.go
│   │           ├── oidc_provider.go
│   │           ├── auth_service.go
│   │           └── gateway_service.go
│   │
│   ├── auth/                        ← sub → internal user_id mapping
│   │   ├── cmd/
│   │   │   └── main.go
│   │   └── internal/
│   │       ├── adapter/
│   │       │   └── postgres/
│   │       │       └── user_repo.go
│   │       ├── cases/
│   │       │   └── resolve_user.go    ← find or create user by (idp, sub)
│   │       ├── entities/
│   │       │   ├── user.go            ← User: id, created_at
│   │       │   └── idp_link.go        ← UserIDPLink: idp, sub, user_id, email
│   │       └── port/
│   │           └── user_repository.go
│   │
│   ├── trust/                       ← adaptive trust score computation
│   │   ├── cmd/
│   │   │   └── main.go
│   │   └── internal/
│   │       ├── adapter/
│   │       │   ├── postgres/
│   │       │   │   ├── device_repo.go
│   │       │   │   ├── login_history_repo.go
│   │       │   │   └── working_hours_repo.go
│   │       │   ├── redis/
│   │       │   │   ├── last_context_cache.go
│   │       │   │   ├── device_cache.go
│   │       │   │   ├── fail_counter.go
│   │       │   │   └── ip_reputation_cache.go
│   │       │   └── http/
│   │       │       └── ip_reputation_client.go ← external IP reputation API
│   │       ├── cases/
│   │       │   ├── anonymous_check.go  ← phase 1: before login, no user_id
│   │       │   └── evaluate_trust.go   ← phase 2: after login, compute score
│   │       ├── entities/
│   │       │   ├── trust_score.go      ← TrustScore: value, decision, signals
│   │       │   ├── risk_signal.go      ← RiskSignal: name, score, weight
│   │       │   └── trust_context.go    ← TrustContext: user_id, ip, ua, timestamp
│   │       └── port/
│   │           ├── device_repository.go
│   │           ├── login_history_repository.go
│   │           ├── trust_cache.go
│   │           └── ip_reputation.go
│   │
│   ├── token/                       ← opaque token lifecycle
│   │   ├── cmd/
│   │   │   └── main.go
│   │   └── internal/
│   │       ├── adapter/
│   │       │   ├── redis/
│   │       │   │   ├── access_token_store.go
│   │       │   │   ├── refresh_token_store.go
│   │       │   │   └── token_family_store.go
│   │       │   ├── kafka/
│   │       │   │   └── event_publisher.go
│   │       │   └── http/
│   │       │       └── trust_client.go ← re-evaluate trust on introspect
│   │       ├── cases/
│   │       │   ├── issue.go         ← create access + refresh token pair
│   │       │   ├── introspect.go    ← validate token, re-eval trust, return context
│   │       │   ├── refresh.go       ← rotation + reuse detection
│   │       │   └── revoke.go        ← revoke token or entire family
│   │       ├── entities/
│   │       │   ├── access_token.go  ← OpaqueToken: hash, user_id, roles, trust_score, exp
│   │       │   ├── refresh_token.go ← RefreshToken: hash, family_id, status, exp
│   │       │   └── token_family.go  ← TokenFamily: family_id, user_id, set of hashes
│   │       └── port/
│   │           ├── access_token_store.go
│   │           ├── refresh_token_store.go
│   │           ├── token_family_store.go
│   │           ├── event_publisher.go
│   │           └── trust_service.go
│   │
│   └── audit/                       ← Kafka consumer, immutable audit log
│       ├── cmd/
│       │   └── main.go
│       └── internal/
│           ├── adapter/
│           │   ├── kafka/
│           │   │   └── consumer.go
│           │   └── postgres/
│           │       └── audit_repo.go
│           ├── cases/
│           │   └── handle_event.go
│           ├── entities/
│           │   └── audit_event.go
│           └── port/
│               ├── event_consumer.go
│               └── audit_repository.go
│
├── toolkit/                         ← non-service shared tooling
│   ├── pkg/                         ← shared Go code (imported by all services)
│   │   ├── logger/
│   │   │   └── logger.go           ← structured logging (slog)
│   │   ├── errors/
│   │   │   └── errors.go           ← domain error types
│   │   ├── tracing/
│   │   │   └── tracing.go          ← OpenTelemetry setup
│   │   ├── httpserver/
│   │   │   └── server.go           ← graceful shutdown wrapper
│   │   └── middleware/
│   │       ├── rate_limit.go
│   │       └── recovery.go
│   │
│   └── policies/                    ← OPA Rego policies (mounted into OPA container)
│       ├── authz.rego
│       └── authz_test.rego
│
├── docker-compose.yml
└── .env.example
```

Migrations live next to the service that owns the database:

```
services/
├── auth/
│   ├── migrations/
│   │   ├── 000001_create_users.up.sql
│   │   ├── 000001_create_users.down.sql
│   │   ├── 000002_create_idp_links.up.sql
│   │   └── 000002_create_idp_links.down.sql
│   └── ...
│
├── trust/
│   ├── migrations/
│   │   ├── 000001_create_trust_devices.up.sql
│   │   ├── 000001_create_trust_devices.down.sql
│   │   ├── 000002_create_login_history.up.sql
│   │   ├── 000002_create_login_history.down.sql
│   │   ├── 000003_create_working_hours.up.sql
│   │   └── 000003_create_working_hours.down.sql
│   └── ...
│
└── audit/
    ├── migrations/
    │   ├── 000001_create_audit_log.up.sql
    │   └── 000001_create_audit_log.down.sql
    └── ...
```

---

## go.mod

```
module github.com/your-org/zero-trust-auth

go 1.22

require (
    github.com/go-chi/chi/v5 v5.0.12
    github.com/coreos/go-oidc/v3 v3.10.0
    golang.org/x/oauth2 v0.21.0
    github.com/redis/go-redis/v9 v9.5.3
    github.com/jackc/pgx/v5 v5.6.0
    github.com/segmentio/kafka-go v0.4.47
    github.com/google/uuid v1.6.0
    github.com/golang-migrate/migrate/v4 v4.17.1
)
```

## Import paths for toolkit/pkg

```go
// All services import shared code with toolkit/pkg/ prefix:
import (
    "github.com/your-org/zero-trust-auth/toolkit/pkg/logger"
    "github.com/your-org/zero-trust-auth/toolkit/pkg/errors"
    "github.com/your-org/zero-trust-auth/toolkit/pkg/httpserver"
    "github.com/your-org/zero-trust-auth/toolkit/pkg/middleware"
    "github.com/your-org/zero-trust-auth/toolkit/pkg/tracing"
)
```

## Build each service separately

```bash
go build ./services/gateway/cmd/...
go build ./services/idpadapter/cmd/...
go build ./services/auth/cmd/...
go build ./services/trust/cmd/...
go build ./services/token/cmd/...
go build ./services/audit/cmd/...
```

---

## Layer responsibilities

### adapter/
Outbound infrastructure — implements `port/` interfaces.
All external I/O: PostgreSQL, Redis, Kafka, HTTP calls to other services.
**Rule:** adapter depends on port, never the other way.

### cases/
Use cases / application logic. Orchestrates entities and calls ports.
No infrastructure code here — only interfaces from `port/`.
**Rule:** cases import only `entities/` and `port/`.

### entities/
Domain entities, aggregates, value objects.
Pure Go structs + methods. Zero external dependencies.
**Rule:** no imports outside standard library.

### port/
Interfaces (contracts) for everything outside the service.
**Rule:** only interface definitions, no implementations.

---

## HTTP APIs

### Gateway — Public (port 3000)

```
GET  /authorize
     Query: client_id, response_type=code,
            code_challenge, code_challenge_method=S256, state
     → 302 redirect to Keycloak login URL (via IDPAdapter)

GET  /callback
     Query: state
     → 302 redirect to Client /callback?code=own_code&state=...

POST /token
     Body (application/x-www-form-urlencoded):
       grant_type=authorization_code
       code=<own_code>
       code_verifier=<client_pkce_verifier>
       client_secret=<secret>
     → 200 { access_token, refresh_token, token_type, expires_in }

POST /token (refresh)
     Body:
       grant_type=refresh_token
       refresh_token=<opaque>
       client_secret=<secret>
     → 200 { access_token, refresh_token, token_type, expires_in }
     → 401 if token reuse detected

POST /logout
     Header: Authorization: Bearer <opaque_access_token>
     Body: { logout_all: bool }
     → 200 OK

POST /introspect  (RFC 7662)
     Body: { token: string }
     → 200 { active, user_id, roles, trust_score, exp }
```

### Gateway — Private (port 8081, internal network only)

```
POST /internal/continue
     Body: {
       state:       string,
       user_id:     string,
       roles:       []string,
       request_ctx: { ip, user_agent, fingerprint }
     }
     → 200 OK
```

### IDPAdapter (port 8080, internal)

```
GET /idp/login-url?state=...
    → 200 { login_url: string }

GET /idp/callback?code=...&state=...
    → internally: exchange → resolve → call gateway:8081
    → 302 redirect to Gateway /callback?state=...
```

### Auth Service (port 8080, internal)

```
POST /auth/resolve-user
     Body: { sub, email, idp }
     → 200 { user_id, created }
```

### Trust Service (port 8080, internal)

```
POST /trust/anonymous-check
     Body: { ip, user_agent, fingerprint }
     → 200 { decision: "ALLOW"|"DENY", reason }

POST /trust/evaluate
     Body: { user_id, roles, ip, user_agent, fingerprint, timestamp }
     → 200 { trust_score, decision, signals }
     decision: "ALLOW" | "MFA_REQUIRED" | "STEP_UP" | "DENY"
```

### Token Service (port 8080, internal)

```
POST /tokens/issue
     Body: { user_id, roles, trust_score, session_id }
     → 200 { access_token, refresh_token }

POST /tokens/introspect
     Body: { token }
     → 200 { active, user_id, roles, trust_score, exp }

POST /tokens/refresh
     Body: { refresh_token, request_ctx }
     → 200 { access_token, refresh_token }
     → 401 { error: "token_reuse_detected" }

POST /tokens/revoke
     Body: { token, revoke_family }
     → 200 OK
```

---

## Redis Key Schema

```
# Gateway
session:{state}               TTL 10m  → { code_challenge, client_id, ip, user_agent }
authcode:{own_code}           TTL 60s  → { user_id, roles, trust_score, code_challenge }
                                          deleted immediately after /token exchange

# IDPAdapter
idp:pkce:{state}              TTL 10m  → idp_code_verifier string

# Token Service
token:access:{sha256(token)}  TTL 15m  → { user_id, roles, trust_score, family_id, exp }
token:refresh:{sha256(token)} TTL 7d   → { user_id, family_id, status, exp }
                                          status: ACTIVE | CONSUMED | REVOKED
family:{family_id}            TTL 7d   → SET of token hashes

# Trust Service
trust:last:{user_id}          TTL 30d  → { ip_hash, country, asn, timestamp }
trust:devices:{user_id}       TTL 90d  → SET of fingerprint_hashes
trust:fails:{user_id}         TTL 15m  → INT counter
trust:ip:{sha256(ip)}         TTL 1h   → { type, asn, country, is_tor, is_datacenter }
```

---

## PostgreSQL Schema

```sql
-- authdb (auth + audit services)

CREATE TABLE users (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE user_idp_links (
    user_id    UUID NOT NULL REFERENCES users(id),
    idp        TEXT NOT NULL,
    sub        TEXT NOT NULL,
    email      TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (idp, sub)
);

CREATE TABLE audit_log (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type TEXT NOT NULL,
    user_id    UUID,
    payload    JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- trustdb (trust service)

CREATE TABLE trust_device_fingerprints (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id          UUID NOT NULL,
    fingerprint_hash TEXT NOT NULL,   -- SHA256(fingerprint + salt)
    ua_hash          TEXT NOT NULL,
    first_seen       TIMESTAMPTZ NOT NULL,
    last_seen        TIMESTAMPTZ NOT NULL,
    seen_count       INT NOT NULL DEFAULT 1
);

CREATE TABLE trust_login_history (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id        UUID NOT NULL,
    ip_hash        TEXT NOT NULL,    -- SHA256(ip + salt), GDPR compliance
    country        TEXT,
    asn            TEXT,
    timestamp      TIMESTAMPTZ NOT NULL,
    was_successful BOOLEAN NOT NULL,
    trust_score    FLOAT,
    decision       TEXT
);

CREATE TABLE trust_working_hours (
    user_id       UUID PRIMARY KEY,
    timezone      TEXT NOT NULL DEFAULT 'UTC',
    typical_start INT NOT NULL DEFAULT 8,
    typical_end   INT NOT NULL DEFAULT 20,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

---

## Migrations (golang-migrate)

Tool: `github.com/golang-migrate/migrate/v4`
Format: separate `.up.sql` and `.down.sql` files per migration.
Naming: `000001_description.up.sql` / `000001_description.down.sql`
Each service runs its own migrations against its own database on startup.

### Integration in cmd/main.go (each service)

```go
import (
    "github.com/golang-migrate/migrate/v4"
    _ "github.com/golang-migrate/migrate/v4/database/postgres"
    _ "github.com/golang-migrate/migrate/v4/source/file"
)

m, err := migrate.New("file://migrations", os.Getenv("POSTGRES_DSN"))
if err != nil {
    log.Fatal("migrate init:", err)
}
if err := m.Up(); err != nil && err != migrate.ErrNoChange {
    log.Fatal("migrate up:", err)
}
```

### services/auth/migrations/

**000001_create_users.up.sql**
```sql
CREATE TABLE users (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

**000001_create_users.down.sql**
```sql
DROP TABLE IF EXISTS users;
```

**000002_create_idp_links.up.sql**
```sql
CREATE TABLE user_idp_links (
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    idp        TEXT NOT NULL,
    sub        TEXT NOT NULL,
    email      TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (idp, sub)
);
CREATE INDEX idx_idp_links_user_id ON user_idp_links(user_id);
```

**000002_create_idp_links.down.sql**
```sql
DROP TABLE IF EXISTS user_idp_links;
```

### services/trust/migrations/

**000001_create_trust_devices.up.sql**
```sql
CREATE TABLE trust_device_fingerprints (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id          UUID NOT NULL,
    fingerprint_hash TEXT NOT NULL,
    ua_hash          TEXT NOT NULL,
    first_seen       TIMESTAMPTZ NOT NULL,
    last_seen        TIMESTAMPTZ NOT NULL,
    seen_count       INT NOT NULL DEFAULT 1
);
CREATE INDEX idx_trust_devices_user_id ON trust_device_fingerprints(user_id);
CREATE UNIQUE INDEX idx_trust_devices_user_fp
    ON trust_device_fingerprints(user_id, fingerprint_hash);
```

**000001_create_trust_devices.down.sql**
```sql
DROP TABLE IF EXISTS trust_device_fingerprints;
```

**000002_create_login_history.up.sql**
```sql
CREATE TABLE trust_login_history (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id        UUID NOT NULL,
    ip_hash        TEXT NOT NULL,
    country        TEXT,
    asn            TEXT,
    timestamp      TIMESTAMPTZ NOT NULL,
    was_successful BOOLEAN NOT NULL,
    trust_score    FLOAT,
    decision       TEXT
);
CREATE INDEX idx_login_history_user_id  ON trust_login_history(user_id);
CREATE INDEX idx_login_history_timestamp ON trust_login_history(timestamp DESC);
```

**000002_create_login_history.down.sql**
```sql
DROP TABLE IF EXISTS trust_login_history;
```

**000003_create_working_hours.up.sql**
```sql
CREATE TABLE trust_working_hours (
    user_id       UUID PRIMARY KEY,
    timezone      TEXT NOT NULL DEFAULT 'UTC',
    typical_start INT NOT NULL DEFAULT 8,
    typical_end   INT NOT NULL DEFAULT 20,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

**000003_create_working_hours.down.sql**
```sql
DROP TABLE IF EXISTS trust_working_hours;
```

### services/audit/migrations/

**000001_create_audit_log.up.sql**
```sql
CREATE TABLE audit_log (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type TEXT NOT NULL,
    user_id    UUID,
    payload    JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_audit_log_user_id    ON audit_log(user_id);
CREATE INDEX idx_audit_log_event_type ON audit_log(event_type);
CREATE INDEX idx_audit_log_created_at ON audit_log(created_at DESC);
```

**000001_create_audit_log.down.sql**
```sql
DROP TABLE IF EXISTS audit_log;
```

---

## Kafka Topics

```
auth.events:
  UserLoggedIn, UserLoggedOut, AnomalousLoginDetected,
  ImpossibleTravelDetected, MfaChallengeIssued, LoginBlocked

token.events:
  TokenReuseAttackDetected, TokenFamilyRevoked

access.events:
  AccessGranted, AccessDenied, TrustDegraded

admin.events:
  AdminForcedLogout, PolicyChanged
```

---

## Trust Score

```go
// Five signals, weights sum to 1.0
// 0.0 = high risk, 1.0 = no risk
// trust_score = Σ(signal.score × signal.weight)

signals := []RiskSignal{
    {Name: "device_known",  Weight: 0.25}, // fingerprint seen before?
    {Name: "ip_reputation", Weight: 0.20}, // residential vs datacenter/tor
    {Name: "geo_anomaly",   Weight: 0.30}, // impossible travel
    {Name: "time_of_day",   Weight: 0.15}, // within working hours?
    {Name: "velocity",      Weight: 0.10}, // recent failed attempts
}

// Impossible travel: distance_km(last, current) / time_hours > 900 → penalty -0.45
// IPs stored as SHA256(ip + salt) — GDPR compliance
// No MDM, no jailbreak detection — web service only

// Decisions:
// ≥ 0.80 → ALLOW
// 0.50–0.79 → MFA_REQUIRED
// 0.30–0.49 → STEP_UP
// < 0.30 → DENY

// Re-evaluation: at every Token Introspection call (every API request)
```

---

## OPA Policy (toolkit/policies/authz.rego)

```rego
package authz

default allow = false

# Regular resources: role + minimum trust
allow {
    input.user.roles[_] == required_role[input.resource]
    input.user.trust_score >= 0.60
}

# Sensitive resources: role + high trust
allow {
    sensitive_resources[input.resource]
    input.user.roles[_] == required_role[input.resource]
    input.user.trust_score >= 0.85
}

sensitive_resources := {"secrets", "admin", "audit"}

required_role := {
    "projects": "developer",
    "reports":  "viewer",
    "secrets":  "developer",
    "admin":    "admin",
    "audit":    "security_admin",
}
```

---

## Environment Variables (.env.example)

```bash
# gateway
GATEWAY_PUBLIC_PORT=3000
GATEWAY_PRIVATE_PORT=8081
GATEWAY_CLIENT_SECRET=changeme
REDIS_URL=redis://redis:6379
OPA_URL=http://opa:8181
TOKEN_SERVICE_URL=http://token:8080
TRUST_SERVICE_URL=http://trust:8080
IDPADAPTER_URL=http://idpadapter:8080
KAFKA_BROKERS=kafka:9092

# idpadapter
KEYCLOAK_ISSUER=http://localhost:8080/realms/demo
KEYCLOAK_CLIENT_ID=zero-trust-app
KEYCLOAK_CLIENT_SECRET=changeme
AUTH_SERVICE_URL=http://auth:8080
GATEWAY_PRIVATE_URL=http://gateway:8081
REDIS_URL=redis://redis:6379

# auth
POSTGRES_DSN=postgres://auth:secret@postgres/authdb?sslmode=disable

# trust
POSTGRES_DSN=postgres://trust:secret@postgres/trustdb?sslmode=disable
REDIS_URL=redis://redis:6379
KAFKA_BROKERS=kafka:9092
IP_REPUTATION_API_KEY=

# token
REDIS_URL=redis://redis:6379
KAFKA_BROKERS=kafka:9092
TRUST_SERVICE_URL=http://trust:8080

# audit
KAFKA_BROKERS=kafka:9092
POSTGRES_DSN=postgres://audit:secret@postgres/authdb?sslmode=disable
```
