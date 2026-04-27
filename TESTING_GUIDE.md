# Testing Guide — Zero Trust Authentication System

This guide walks a developer through testing the system manually from scratch.
No prior knowledge of the codebase is assumed.

---

## Prerequisites

Install the following tools before starting:

| Tool | Version | Purpose |
|------|---------|---------|
| Docker + Docker Compose | v24+ | Run all services |
| curl | any | Send HTTP requests |
| jq | any | Pretty-print JSON responses |
| A browser | any | Walk through the OAuth login flow |
| psql (optional) | v14+ | Query the audit log directly |

Install on Fedora/RHEL:
```bash
sudo dnf install docker docker-compose-plugin curl jq postgresql
sudo systemctl start docker
sudo usermod -aG docker $USER   # log out and back in after this
```

Install on Ubuntu/Debian:
```bash
sudo apt install docker.io docker-compose-plugin curl jq postgresql-client
sudo systemctl start docker
sudo usermod -aG docker $USER
```

Verify everything is installed:
```bash
docker compose version   # should print Compose version
curl --version
jq --version
```

---

## Starting the System

### 1. Clone and configure

```bash
git clone <repo-url>
cd zero-trust-auth

cp .env.example .env
```

The `.env.example` already contains working development values. The only secrets you
may want to change are:

```bash
# .env
GATEWAY_CLIENT_ID=zero-trust-app
GATEWAY_CLIENT_SECRET=changeme
KEYCLOAK_CLIENT_SECRET=changeme
```

### 2. Build all service images

This compiles all six Go services into Docker images (~5 minutes on first run):

```bash
docker compose build
```

You should see six `Successfully tagged` lines at the end.

### 3. Start infrastructure first

Start the databases, cache, and message broker before the application services:

```bash
docker compose up -d postgres redis kafka
```

Wait for them to become healthy (~15 seconds):

```bash
docker compose ps
# postgres: healthy
# redis:    healthy
# kafka:    healthy
```

### 4. Start Keycloak

```bash
docker compose up -d keycloak
```

Keycloak takes 30–60 seconds to initialise its database. Wait until you can
reach the admin console:

```bash
# Poll until ready (run this in a separate terminal or just wait ~45s)
until curl -sf http://localhost:8080/realms/master > /dev/null; do
  echo "waiting for Keycloak..."; sleep 5
done
echo "Keycloak is ready"
```

You can also watch the logs:
```bash
docker compose logs -f keycloak
# Ready when you see: "Keycloak 24.x on JVM ... started in Xs"
```

### 5. Configure Keycloak

The `keycloak/realm-export.json` file is automatically imported on first start.
It creates the `demo` realm, `zero-trust-app` client, and a `testuser` with the
`developer` role.

**Verify** the import worked:

```bash
# Get an admin token
ADMIN_TOKEN=$(curl -sf -X POST http://localhost:8080/realms/master/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=admin-cli&username=admin&password=admin&grant_type=password" \
  | jq -r '.access_token')

# Check the demo realm exists
curl -sf -H "Authorization: Bearer $ADMIN_TOKEN" \
  http://localhost:8080/admin/realms/demo | jq '.realm, .enabled'
# Output: "demo"  true

# Check the client exists
curl -sf -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://localhost:8080/admin/realms/demo/clients?clientId=zero-trust-app" \
  | jq '.[0].clientId, .[0].directAccessGrantsEnabled'
# Output: "zero-trust-app"  true

# Check the test user
curl -sf -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://localhost:8080/admin/realms/demo/users?username=testuser" \
  | jq '.[0].username, .[0].enabled'
# Output: "testuser"  true
```

If the realm was NOT imported automatically, create it manually:

```bash
# Create realm
curl -sf -X POST http://localhost:8080/admin/realms \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"realm":"demo","enabled":true}'

# Create client
curl -sf -X POST http://localhost:8080/admin/realms/demo/clients \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "clientId": "zero-trust-app",
    "secret": "changeme",
    "redirectUris": ["http://idpadapter:8080/idp/callback"],
    "publicClient": false,
    "standardFlowEnabled": true,
    "directAccessGrantsEnabled": true,
    "protocol": "openid-connect"
  }'

# Create developer role
curl -sf -X POST http://localhost:8080/admin/realms/demo/roles \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"developer"}'

# Create test user with password
curl -sf -X POST http://localhost:8080/admin/realms/demo/users \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@test.com",
    "firstName": "Test",
    "lastName": "User",
    "enabled": true,
    "emailVerified": true,
    "credentials": [{"type":"password","value":"testpass","temporary":false}]
  }'

# Assign developer role to test user
USER_ID=$(curl -sf -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://localhost:8080/admin/realms/demo/users?username=testuser" \
  | jq -r '.[0].id')

ROLE_ID=$(curl -sf -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://localhost:8080/admin/realms/demo/roles/developer" \
  | jq -r '.id')

curl -sf -X POST \
  "http://localhost:8080/admin/realms/demo/users/$USER_ID/role-mappings/realm" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d "[{\"id\":\"$ROLE_ID\",\"name\":\"developer\"}]"
```

### 6. Start all application services

```bash
docker compose up -d opa auth trust token idpadapter gateway audit
```

Wait for them to start (~20 seconds):

```bash
docker compose ps
```

Expected output — all should show `Up`:

```
NAME              STATUS
vkr_audit_1       Up
vkr_auth_1        Up
vkr_gateway_1     Up
vkr_idpadapter_1  Up
vkr_kafka_1       Up (healthy)
vkr_keycloak_1    Up
vkr_opa_1         Up (healthy)
vkr_postgres_1    Up (healthy)
vkr_redis_1       Up (healthy)
vkr_token_1       Up
vkr_trust_1       Up
```

Verify the gateway is responding:

```bash
curl -sf http://localhost:3000/health && echo "Gateway is up"
```

---

## Scenario 1 — Normal Login (Happy Path)

This walks through the complete OAuth 2.0 Authorization Code + PKCE flow.

### Step 1 — Generate PKCE parameters

The client app (your browser/script) generates a PKCE pair to prove it made the
original request:

```bash
# Generate a random code verifier (43–128 characters, URL-safe)
CODE_VERIFIER=$(python3 -c "import secrets; print(secrets.token_urlsafe(43))")
echo "code_verifier: $CODE_VERIFIER"

# Derive the code challenge: BASE64URL(SHA256(verifier))
CODE_CHALLENGE=$(python3 -c "
import sys, hashlib, base64
v = '$CODE_VERIFIER'
h = hashlib.sha256(v.encode()).digest()
print(base64.urlsafe_b64encode(h).rstrip(b'=').decode())
")
echo "code_challenge: $CODE_CHALLENGE"

# Generate a random state (CSRF protection)
STATE=$(python3 -c "import secrets; print(secrets.token_urlsafe(16))")
echo "state: $STATE"
```

### Step 2 — Open the authorize URL in your browser

Construct the URL and open it:

```bash
echo "Open this URL in your browser:"
echo "http://localhost:3000/authorize?client_id=zero-trust-app&response_type=code&code_challenge=${CODE_CHALLENGE}&code_challenge_method=S256&state=${STATE}"
```

**What happens:**
1. Gateway validates `client_id`, stores the session in Redis, calls Trust Service for an anonymous IP check
2. Gateway calls IDPAdapter to get the Keycloak login URL
3. Browser is redirected to Keycloak's login page at `http://localhost:8080`

**What you see:** A Keycloak login form asking for username and password.

### Step 3 — Log in with the test user

Enter these credentials in the Keycloak form:

```
Username: testuser
Password: testpass
```

**What happens:**
1. Keycloak authenticates the user and redirects to IDPAdapter's callback URL
2. IDPAdapter exchanges the Keycloak code for an `id_token`, extracts `sub` and roles
3. IDPAdapter calls Auth Service to resolve `sub` → internal `user_id`
4. IDPAdapter calls Gateway's private port (`gateway:8081`) with the resolved identity
5. Gateway evaluates trust score, generates a one-time `own_code`
6. Browser is redirected to `http://localhost:3000/callback?state=...`
7. Gateway looks up `own_code` and redirects to the client callback URL

**What you see in the browser address bar:**
```
http://test-client.example.com/callback?code=f350...1a74&state=<your-state>
```

### Step 4 — Extract the authorization code

Copy the `code=` value from the URL. For this guide we will call it `OWN_CODE`:

```bash
OWN_CODE=f350...1a74   # paste the actual code value from the URL
```

Verify the state matches what you generated earlier (CSRF check):

```bash
echo "State in URL should match: $STATE"
```

### Step 5 — Exchange the code for tokens

```bash
curl -sf -X POST http://localhost:3000/token \
  -d "grant_type=authorization_code" \
  -d "code=$OWN_CODE" \
  -d "code_verifier=$CODE_VERIFIER" \
  -d "client_secret=changeme" \
  | jq .
```

**Expected response:**
```json
{
  "access_token": "25a3f061a61aa2362b2f2e3b0e8971a0bbe1eef0a6808fdcf6c8e14c4bc9104d",
  "refresh_token": "2e553f7585cf0455c6fdaf0d7e14605fe6c2c098bd8dc6ad44010a2ec21e4bac",
  "token_type": "Bearer",
  "expires_in": 900
}
```

Save the tokens:
```bash
ACCESS_TOKEN=25a3f061...    # paste your access_token
REFRESH_TOKEN=2e553f75...   # paste your refresh_token
```

> **Note:** The code is single-use. Trying to exchange the same `code` twice returns `invalid_grant`.

### Step 6 — Call an API endpoint

```bash
curl -sf -H "Authorization: Bearer $ACCESS_TOKEN" \
  http://localhost:3000/api/projects
# Returns: 200 OK
```

Check your identity via introspect:

```bash
curl -sf -X POST http://localhost:3000/introspect \
  -H "Content-Type: application/json" \
  -d "{\"token\": \"$ACCESS_TOKEN\"}" \
  | jq .
```

**Expected response:**
```json
{
  "active": true,
  "user_id": "a1b2c3d4-...",
  "roles": ["developer"],
  "trust_score": 0.85
}
```

> **Why is trust_score different from 0.91?**
> The score shown at issuance (0.91) was computed with full user context.
> On every introspect call, the Trust Service re-evaluates with the current
> request context (IP, device fingerprint, time of day). This is Zero Trust
> continuous verification — the score can go up or down between requests.

---

## Scenario 2 — Token Refresh and Rotation

Each refresh issues a completely new token pair. The old refresh token is
immediately invalidated.

### Step 1 — Refresh the tokens

```bash
curl -sf -X POST http://localhost:3000/token \
  -d "grant_type=refresh_token" \
  -d "refresh_token=$REFRESH_TOKEN" \
  -d "client_secret=changeme" \
  | jq .
```

**Expected response:**
```json
{
  "access_token": "NEW_ACCESS_TOKEN_64_CHARS_HEX",
  "refresh_token": "NEW_REFRESH_TOKEN_64_CHARS_HEX",
  "token_type": "Bearer",
  "expires_in": 900
}
```

Both tokens are completely different from the originals. Save the new pair:

```bash
NEW_ACCESS_TOKEN=...    # from response
NEW_REFRESH_TOKEN=...   # from response
```

### Step 2 — Attempt to reuse the old refresh token

```bash
curl -sf -X POST http://localhost:3000/token \
  -d "grant_type=refresh_token" \
  -d "refresh_token=$REFRESH_TOKEN" \ 
  -d "client_secret=changeme"
```

**Expected response (HTTP 401):**
```json
{"error": "token_reuse_detected"}
```

**What happens behind the scenes:**
- Token Service finds the old token in Redis with `status: CONSUMED`
- This is a token reuse attack signal
- Token Service revokes the entire token *family* (all sessions, all tokens)
- Token Service publishes `TokenReuseAttackDetected` to Kafka
- Audit Service records the event in `audit_log`
- Both the old AND new tokens are now invalid

Verify the new token was also revoked:

```bash
curl -sf -X POST http://localhost:3000/introspect \
  -H "Content-Type: application/json" \
  -d "{\"token\": \"$NEW_ACCESS_TOKEN\"}" \
  | jq .active
# Returns: false
```

---

## Scenario 3 — Access Denied by Trust Score

The OPA policy enforces minimum trust scores per resource. You can observe this
by querying OPA directly to simulate different contexts.

### Understanding the trust thresholds

| Score range | Decision | Meaning |
|------------|----------|---------|
| ≥ 0.80 | ALLOW | Full access |
| 0.50–0.79 | MFA_REQUIRED | Step-up authentication needed |
| 0.30–0.49 | STEP_UP | Additional verification required |
| < 0.30 | DENY | Access blocked |

OPA enforces separate thresholds per resource:
- Regular resources (`/api/projects`, `/api/reports`): trust_score ≥ **0.60**
- Sensitive resources (`/api/secrets`, `/api/admin`, `/api/audit`): trust_score ≥ **0.85**

### Simulate a developer with moderate trust (0.75) accessing projects

```bash
# This should ALLOW — 0.75 ≥ 0.60 for regular resource
curl -sf -X POST http://localhost:8181/v1/data/authz/allow \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "user": {"roles": ["developer"], "trust_score": 0.75},
      "resource": "projects",
      "action": "read"
    }
  }' | jq .result
# Returns: true
```

### Simulate the same developer accessing secrets with the same trust score

```bash
# This should DENY — 0.75 < 0.85 required for sensitive resource
curl -sf -X POST http://localhost:8181/v1/data/authz/allow \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "user": {"roles": ["developer"], "trust_score": 0.75},
      "resource": "secrets",
      "action": "read"
    }
  }' | jq .result
# Returns: false
```

### See the 403 response in practice

Issue a token directly (internal test, bypasses browser):

```bash
# Using docker exec to reach the internal token service
docker compose exec -T auth wget -qO- \
  --post-data='{"user_id":"00000000-0000-0000-0000-000000000099","roles":["developer"],"trust_score":0.40}' \
  --header='Content-Type: application/json' \
  http://token:8080/tokens/issue 2>/dev/null || \
# Alternative via host network with jq
docker run --rm --network zero-trust-auth_default \
  curlimages/curl -sf -X POST http://token:8080/tokens/issue \
  -H "Content-Type: application/json" \
  -d '{"user_id":"00000000-0000-0000-0000-000000000099","roles":["developer"],"trust_score":0.40}' \
  | jq .
```

```bash
LOW_TRUST_TOKEN=...  # access_token from response
```

Call `/api/projects` (regular resource — threshold 0.60):

```bash
curl -s -w "\nHTTP:%{http_code}" \
  -H "Authorization: Bearer $LOW_TRUST_TOKEN" \
  http://localhost:3000/api/projects
# HTTP:403 — trust_score 0.40 < 0.60
```

Now issue a token with trust_score = 0.75 and try `/api/secrets`:

```bash
# Token with moderate trust
MODERATE_TOKEN=$(docker run --rm --network zero-trust-auth_default \
  curlimages/curl -sf -X POST http://token:8080/tokens/issue \
  -H "Content-Type: application/json" \
  -d '{"user_id":"00000000-0000-0000-0000-000000000099","roles":["developer"],"trust_score":0.75}' \
  | jq -r .access_token)

curl -s -w "\nHTTP:%{http_code}" \
  -H "Authorization: Bearer $MODERATE_TOKEN" \
  http://localhost:3000/api/secrets
# HTTP:403 — trust_score 0.75 < 0.85 required for secrets
```

Compare with a high-trust token:

```bash
HIGH_TRUST_TOKEN=$(docker run --rm --network zero-trust-auth_default \
  curlimages/curl -sf -X POST http://token:8080/tokens/issue \
  -H "Content-Type: application/json" \
  -d '{"user_id":"00000000-0000-0000-0000-000000000099","roles":["developer"],"trust_score":0.91}' \
  | jq -r .access_token)

curl -s -w "\nHTTP:%{http_code}" \
  -H "Authorization: Bearer $HIGH_TRUST_TOKEN" \
  http://localhost:3000/api/secrets
# HTTP:200 — trust_score 0.91 ≥ 0.85
```

---

## Scenario 4 — Forced Logout

### Step 1 — Log out (revoke current session only)

```bash
curl -sf -X POST http://localhost:3000/logout \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"logout_all": false}'
# Returns: 200 OK (empty body)
```

### Step 2 — Verify the access token no longer works

```bash
curl -sf -X POST http://localhost:3000/introspect \
  -H "Content-Type: application/json" \
  -d "{\"token\": \"$ACCESS_TOKEN\"}" | jq .active
# Returns: false
```

Any API call also fails:

```bash
curl -s -w "\nHTTP:%{http_code}" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  http://localhost:3000/api/projects
# HTTP:401
```

### Step 3 — Verify the refresh token also fails

```bash
curl -s -w "\nHTTP:%{http_code}" -X POST http://localhost:3000/token \
  -d "grant_type=refresh_token" \
  -d "refresh_token=$REFRESH_TOKEN" \
  -d "client_secret=changeme"
# HTTP:401
```

### Force logout all sessions (nuclear option)

Use `logout_all: true` to revoke every token in the family (all devices):

```bash
curl -sf -X POST http://localhost:3000/logout \
  -H "Authorization: Bearer $VALID_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"logout_all": true}'
```

All refresh tokens issued to that user (across all devices) are immediately revoked.

---

## Checking Audit Events

The audit service consumes events from Kafka and writes them to the `audit_log`
table in PostgreSQL.

### Connect to the database

```bash
# Using docker compose exec
docker compose exec postgres psql -U postgres -d authdb

# Or using psql from your host
psql "postgres://audit:secret@localhost:5432/authdb?sslmode=disable"
```

> **Port note:** PostgreSQL is only exposed inside the Docker network by default.
> To access from the host, temporarily add `ports: - "5432:5432"` to the postgres
> service in `docker-compose.yml` and restart.

### Query the audit log

```sql
-- All events, newest first
SELECT event_type, payload->>'user_id' AS user_id, created_at
FROM audit_log
ORDER BY created_at DESC
LIMIT 20;
```

```sql
-- Filter by event type
SELECT * FROM audit_log
WHERE event_type = 'TokenReuseAttackDetected'
ORDER BY created_at DESC;
```

```sql
-- Events for a specific user
SELECT event_type, payload, created_at
FROM audit_log
WHERE payload->>'user_id' = '00000000-0000-0000-0000-000000000001'
ORDER BY created_at DESC;
```

### Expected events after each scenario

| Scenario | Event in audit_log |
|----------|-------------------|
| Successful login (full flow) | `UserLoggedIn` |
| Token reuse attempt | `TokenReuseAttackDetected` |
| Token family revoked | `TokenFamilyRevoked` |
| Access denied by OPA | `AccessDenied` |
| Admin forced logout | `AdminForcedLogout` |
| Trust score degraded | `TrustDegraded` |

### Example audit_log rows

```
event_type                 | user_id                              | created_at
---------------------------+--------------------------------------+------------------------------
TokenReuseAttackDetected   | 00000000-0000-0000-0000-000000000001 | 2026-04-26 18:50:35.589543+00
UserLoggedIn               | a1b2c3d4-e5f6-7890-abcd-ef1234567890 | 2026-04-26 18:30:12.123456+00
```

---

## Checking OPA Decisions

OPA is accessible on port 8181 **inside the Docker network only**. To query it
from the host, either:

**Option A — query via the gateway (recommended)**

The gateway calls OPA on every `GET /api/*` request. Observe OPA's effect by
testing different tokens (see Scenario 3).

**Option B — expose OPA temporarily for debugging**

Add to `docker-compose.yml` under the `opa` service:
```yaml
ports:
  - "8181:8181"
```
Then restart: `docker compose restart opa`

Now query directly:

```bash
# Allow: developer with high trust reading projects
curl -sf -X POST http://localhost:8181/v1/data/authz/allow \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "user": {"roles": ["developer"], "trust_score": 0.91},
      "resource": "projects",
      "action": "read"
    }
  }' | jq .
# {"result": true}
```

```bash
# Deny: low trust score
curl -sf -X POST http://localhost:8181/v1/data/authz/allow \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "user": {"roles": ["developer"], "trust_score": 0.40},
      "resource": "projects",
      "action": "read"
    }
  }' | jq .
# {"result": false}
```

```bash
# Deny: developer accessing audit (security_admin required)
curl -sf -X POST http://localhost:8181/v1/data/authz/allow \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "user": {"roles": ["developer"], "trust_score": 0.95},
      "resource": "audit",
      "action": "read"
    }
  }' | jq .
# {"result": false}
```

```bash
# Allow: security_admin accessing audit
curl -sf -X POST http://localhost:8181/v1/data/authz/allow \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "user": {"roles": ["security_admin"], "trust_score": 0.90},
      "resource": "audit",
      "action": "read"
    }
  }' | jq .
# {"result": true}
```

**Understanding the OPA response:**

The response is always `{"result": true}` or `{"result": false}`.
An absent `result` key means the policy returned `undefined` (treated as deny).

**Run all policy unit tests:**

```bash
docker run --rm -v $(pwd)/toolkit/policies:/policies:ro \
  openpolicyagent/opa:latest test /policies -v
```

Expected output:
```
PASS: 6/6 tests passed
```

---

## Common Problems and Fixes

### Container fails to start

```bash
# See why a specific container failed
docker compose logs auth
docker compose logs gateway

# Tail logs in real time
docker compose logs -f auth trust token
```

Common causes:
- **postgres ping failed** — PostgreSQL not healthy yet; wait and retry
- **redis ping failed** — Redis not healthy yet; wait and retry
- **kafka subscribe failed** — Kafka not ready; wait 30s and restart the service

### Keycloak shows "Account is not fully set up"

Keycloak 24 requires `firstName` and `lastName` for the user profile:

```bash
ADMIN_TOKEN=$(curl -sf -X POST \
  http://localhost:8080/realms/master/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=admin-cli&username=admin&password=admin&grant_type=password" \
  | jq -r .access_token)

USER_ID=$(curl -sf -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://localhost:8080/admin/realms/demo/users?username=testuser" \
  | jq -r '.[0].id')

curl -X PUT "http://localhost:8080/admin/realms/demo/users/$USER_ID" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"firstName":"Test","lastName":"User","emailVerified":true,"requiredActions":[]}'
```

### Roles missing from id_token

Keycloak 24 does not include realm roles in tokens by default. Add the mapper:

```bash
CLIENT_UUID=$(curl -sf -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://localhost:8080/admin/realms/demo/clients?clientId=zero-trust-app" \
  | jq -r '.[0].id')

curl -X POST \
  "http://localhost:8080/admin/realms/demo/clients/$CLIENT_UUID/protocol-mappers/models" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "realm roles",
    "protocol": "openid-connect",
    "protocolMapper": "oidc-usermodel-realm-role-mapper",
    "config": {
      "multivalued": "true",
      "id.token.claim": "true",
      "access.token.claim": "true",
      "claim.name": "realm_access.roles",
      "jsonType.label": "String"
    }
  }'
```

### 401 on all requests

Debug token validity:

```bash
# Check if the token is active
curl -X POST http://localhost:3000/introspect \
  -H "Content-Type: application/json" \
  -d "{\"token\": \"$ACCESS_TOKEN\"}" | jq .

# If active=false, the token expired (15min TTL) — refresh it:
curl -X POST http://localhost:3000/token \
  -d "grant_type=refresh_token&refresh_token=$REFRESH_TOKEN&client_secret=changeme" \
  | jq .
```

Check gateway logs for details:
```bash
docker compose logs --since 5m gateway | grep -i error
```

### 403 on every request

The OPA policy is denying access. Most likely causes:
1. **Trust score too low** — re-issue a token with a higher trust_score
2. **Wrong role** — check `jq .roles` in the introspect response
3. **Wrong resource name** — the resource is extracted from the URL path, e.g., `/api/projects` → `projects`

Test OPA directly (see "Checking OPA Decisions" section) to isolate the policy.

### Migrations failed

If a service fails with migration errors:

```bash
# Reset the entire postgres volume (destroys all data)
docker compose down
docker volume rm zero-trust-auth_postgres_data
docker compose up -d postgres
# Wait for postgres to be healthy, then restart services
docker compose up -d auth trust audit
```

For a partial reset (single database only):

```bash
docker compose exec postgres psql -U postgres -d authdb \
  -c "DROP TABLE IF EXISTS schema_migrations, users, user_idp_links, audit_log CASCADE;"
```

Then restart the affected service to re-run migrations.

### IDPAdapter keeps restarting

IDPAdapter retries connecting to Keycloak every 5 seconds for up to 150 seconds.
If it keeps restarting, Keycloak is not responding:

```bash
# Check Keycloak health
curl -sf http://localhost:8080/realms/demo/.well-known/openid-configuration > /dev/null \
  && echo "Keycloak OK" || echo "Keycloak not ready"

# Watch IDPAdapter logs
docker compose logs -f idpadapter
```

---

## Stopping the System

### Stop all containers (preserve data)

```bash
docker compose stop
```

Restart later with:
```bash
docker compose start
```

### Stop and remove containers (preserve volumes)

```bash
docker compose down
```

All data in PostgreSQL, Redis, and Kafka is preserved in Docker volumes.
Restart with `docker compose up -d`.

### Full reset (destroy all data)

```bash
docker compose down --volumes
```

This removes all named volumes (`postgres_data`, `redis_data`). The next startup
runs all migrations and Keycloak imports from scratch, as if it were the first time.

### Rebuild images after code changes

```bash
# Rebuild a single service
docker compose build gateway
docker compose restart gateway

# Rebuild all services
docker compose build
docker compose up -d
```

---

## Quick Reference

| What | Command |
|------|---------|
| Start everything | `docker compose up -d` |
| Check container health | `docker compose ps` |
| Tail all logs | `docker compose logs -f` |
| Tail one service | `docker compose logs -f gateway` |
| Gateway health | `curl http://localhost:3000/health` |
| Introspect a token | `curl -X POST http://localhost:3000/introspect -d '{"token":"..."}'` |
| Query OPA (if exposed) | `curl -X POST http://localhost:8181/v1/data/authz/allow -d '{"input":{...}}'` |
| Run OPA policy tests | `docker run --rm -v $(pwd)/toolkit/policies:/p openpolicyagent/opa test /p -v` |
| Run Go integration test | `go test ./services/gateway/... -v -run TestFullLoginFlow` |
| Stop everything | `docker compose down` |
| Full reset | `docker compose down --volumes` |

---

*For architecture decisions and design rationale, read `DECISIONS.md`.
For sequence diagrams of each flow, read `SEQUENCE.md`.
For HTTP API reference, read `SERVICES.md`.*
