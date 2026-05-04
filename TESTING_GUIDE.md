# Testing Guide — Zero Trust Authentication System

This guide covers manual testing of every implemented scenario.

---

## Prerequisites

| Tool | Purpose |
|------|---------|
| Docker + Docker Compose v24+ | Run all services |
| curl | Send HTTP requests |
| python3 | Parse JSON (built-in) |
| A browser | OAuth login flow |

Install on Fedora/RHEL:
```bash
sudo dnf install docker docker-compose-plugin curl
sudo systemctl start docker
sudo usermod -aG docker $USER   # re-login after this
```

---

## Starting the System

### 1. Configure

```bash
cp .env.example .env
# Edit GATEWAY_CLIENT_SECRET and KEYCLOAK_CLIENT_SECRET if needed
```

### 2. Build and start

```bash
sudo docker compose build
sudo docker compose up -d
```

Wait ~60 seconds for all services to initialise.

### 3. Verify everything is up

```bash
sudo docker compose ps
# All services should show "Up"

curl -s http://localhost:3000/health && echo "Gateway OK"
```

### 4. First-time Keycloak setup

On first start, enable event logging and the Kafka SPI listener:

```bash
ADMIN_TOKEN=$(curl -s -X POST http://localhost:8080/realms/master/protocol/openid-connect/token \
  -d client_id=admin-cli -d username=admin -d password=admin \
  -d grant_type=password | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# Enable event logging
curl -s -X PUT http://localhost:8080/admin/realms/demo/events/config \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"eventsEnabled":true,"eventsListeners":["jboss-logging","kafka"],"enabledEventTypes":["LOGIN","LOGIN_ERROR"]}' \
  -w '\nHTTP:%{http_code}'
# → HTTP:204

# Add realm roles mapper (so roles appear in tokens)
CLIENT_UUID=$(curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://localhost:8080/admin/realms/demo/clients?clientId=zero-trust-app" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['id'])")

curl -s -X POST \
  "http://localhost:8080/admin/realms/demo/clients/$CLIENT_UUID/protocol-mappers/models" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"realm roles","protocol":"openid-connect","protocolMapper":"oidc-usermodel-realm-role-mapper","config":{"multivalued":"true","id.token.claim":"true","access.token.claim":"true","claim.name":"realm_access.roles","jsonType.label":"String"}}' \
  -w '\nHTTP:%{http_code}'
# → HTTP:201
```

---

## Port Reference

| Service | Host Port | Purpose |
|---------|-----------|---------|
| Gateway | 3000 | Public API |
| Keycloak | 8080 | Identity provider |
| IDPAdapter | 8090 | OIDC callback |
| OPA | 8181 | Policy engine (debug) |
| Prometheus | 9090 | Metrics |
| Grafana | 9091 | Dashboards (admin/admin) |

---

## Scenario 1 — Normal Login (OAuth 2.0 + PKCE)

### Step 1 — Generate PKCE parameters

```bash
python3 -c "
import base64, hashlib, os, urllib.parse
verifier = base64.urlsafe_b64encode(os.urandom(40)).rstrip(b'=').decode()
challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
state = base64.urlsafe_b64encode(os.urandom(15)).rstrip(b'=').decode()
print('code_verifier:', verifier)
print()
print('Authorize URL:')
print(f'http://localhost:3000/authorize?client_id=zero-trust-app&response_type=code&code_challenge={challenge}&code_challenge_method=S256&state={urllib.parse.quote(state)}')
print()
print('Exchange command (replace CODE):')
print(f'curl -s -X POST http://localhost:3000/token -d grant_type=authorization_code -d code=CODE -d code_verifier={verifier} -d client_secret=changeme | python3 -m json.tool')
"
```

### Step 2 — Open the authorize URL in your browser

Paste the URL into a browser. You will be redirected to Keycloak.

Log in with: **testuser / testpassword**

### Step 3 — Exchange the code

After login, the browser redirects to:
```
http://localhost:4000/callback?code=<OWN_CODE>&state=...
```

Copy `OWN_CODE` and run:

```bash
curl -s -X POST http://localhost:3000/token \
  -d grant_type=authorization_code \
  -d code=OWN_CODE \
  -d code_verifier=YOUR_VERIFIER \
  -d client_secret=changeme | python3 -m json.tool
```

**Expected response:**
```json
{
  "access_token": "hex64chars...",
  "refresh_token": "hex64chars...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

Save the tokens:
```bash
export ACCESS_TOKEN="paste_access_token_here"
export REFRESH_TOKEN="paste_refresh_token_here"
```

### Step 4 — Introspect the token

```bash
curl -s -X POST http://localhost:3000/introspect \
  -H "Content-Type: application/json" \
  -d "{\"token\": \"$ACCESS_TOKEN\"}" | python3 -m json.tool
```

**Expected response:**
```json
{
  "active": true,
  "user_id": "694cf7c5-...",
  "roles": ["developer"],
  "trust_score": 0.75
}
```

### Step 5 — Call protected API endpoints

```bash
# Regular resource — requires role=developer, trust ≥ 0.60
curl -s -w '\nHTTP:%{http_code}' http://localhost:3000/api/projects \
  -H "Authorization: Bearer $ACCESS_TOKEN"
# → HTTP:200

# Sensitive resource — requires trust ≥ 0.85 (will trigger step-up)
curl -s -w '\nHTTP:%{http_code}' http://localhost:3000/api/secrets \
  -H "Authorization: Bearer $ACCESS_TOKEN"
# → HTTP:401 {"error":"insufficient_user_authentication",...}

# Without token
curl -s -w '\nHTTP:%{http_code}' http://localhost:3000/api/projects
# → HTTP:401
```

---

## Scenario 2 — MFA (TOTP Two-Factor Authentication)

MFA is triggered when the trust score is between 0.50 and 0.70 (new device, unknown IP etc.)

### First login from a new device

On the first login from any browser, the device is unknown → score ~0.50 → `MFA_REQUIRED`.
After Keycloak login the browser is redirected to:
```
http://localhost:3000/mfa?state=...
```

**First-time enrollment:** The page shows a TOTP secret key. Add it to Google Authenticator, Authy or any TOTP app.

**Subsequent logins:** Enter the 6-digit code from your authenticator app.

After successful TOTP:
- `trust:fails` counter is reset
- The own_code is generated
- Browser redirects to the client callback with the code

**Device learning:** After the second login from the same browser, the device is registered → score rises to 0.75 → `ALLOW` → no MFA required.

---

## Scenario 3 — Token Refresh and Rotation

### Normal refresh

```bash
curl -s -X POST http://localhost:3000/token \
  -d "grant_type=refresh_token" \
  -d "refresh_token=$REFRESH_TOKEN" | python3 -m json.tool
```

**Expected:** New `access_token` + `refresh_token`. Old access token is deleted immediately.

Save the new tokens:
```bash
export ACCESS_TOKEN="new_access_token"
export REFRESH_TOKEN="new_refresh_token"
```

### Token reuse attack detection

Use the **old** refresh token again:

```bash
curl -s -w '\nHTTP:%{http_code}' -X POST http://localhost:3000/token \
  -d "grant_type=refresh_token" \
  -d "refresh_token=OLD_REFRESH_TOKEN"
```

**Expected response (HTTP 401):**
```json
{"error": "token_reuse_detected"}
```

**What happens:**
1. Token service finds the old token marked `Consumed`
2. Revokes entire token family (all refresh tokens)
3. Sets `family:revoked:{id}` — blocks future introspects for all access tokens
4. Publishes `TokenReuseAttackDetected` to Kafka → audit log

Verify the new token was also invalidated:
```bash
curl -s -X POST http://localhost:3000/introspect \
  -H "Content-Type: application/json" \
  -d "{\"token\": \"$ACCESS_TOKEN\"}" | python3 -c \
  "import sys,json; print('active:', json.load(sys.stdin)['active'])"
# active: False
```

---

## Scenario 4 — Trust Score and OPA Policy

### Query OPA directly

OPA is exposed on port 8181:

```bash
# developer, trust 0.75, projects → allowed
curl -s -X POST http://localhost:8181/v1/data/authz/allow \
  -H "Content-Type: application/json" \
  -d '{"input":{"user":{"roles":["developer"],"trust_score":0.75},"resource":"projects","action":"read"}}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('result'))"
# True

# developer, trust 0.75, secrets → denied (trust < 0.85 for sensitive)
curl -s -X POST http://localhost:8181/v1/data/authz/allow \
  -H "Content-Type: application/json" \
  -d '{"input":{"user":{"roles":["developer"],"trust_score":0.75},"resource":"secrets","action":"read"}}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('result'))"
# False

# viewer, projects → denied (wrong role)
curl -s -X POST http://localhost:8181/v1/data/authz/allow \
  -H "Content-Type: application/json" \
  -d '{"input":{"user":{"roles":["viewer"],"trust_score":0.90},"resource":"projects","action":"read"}}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('result'))"
# False
```

### OPA thresholds summary

| Resource | Required role | Min trust | Sensitive |
|----------|--------------|-----------|-----------|
| projects | developer | 0.60 | No |
| reports | viewer | 0.60 | No |
| secrets | developer | 0.85 | Yes |
| admin | admin | 0.85 | Yes |
| audit | security_admin | 0.60 | No |

### Low trust score blocks API (velocity signal)

```bash
# Simulate 10+ failed logins (sets velocity counter to DENY range)
sudo docker exec vkr-redis-1 redis-cli SET \
  "trust:fails:694cf7c5-0211-49b9-bd18-c2a3954ecac9" 15 EX 900

# Issue new token
PAIR=$(sudo docker exec vkr-token-1 wget -qO- \
  --post-data='{"user_id":"694cf7c5-0211-49b9-bd18-c2a3954ecac9","roles":["developer"],"trust_score":0.75}' \
  --header='Content-Type: application/json' http://localhost:8080/tokens/issue 2>/dev/null)
LOW_AT=$(echo $PAIR | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

curl -s -w '\nHTTP:%{http_code}' http://localhost:3000/api/projects \
  -H "Authorization: Bearer $LOW_AT"
# → HTTP:401 (insufficient_user_authentication — step-up required)

# Clean up
sudo docker exec vkr-redis-1 redis-cli DEL \
  "trust:fails:694cf7c5-0211-49b9-bd18-c2a3954ecac9"
```

### Suspicious IP (datacenter) lowers trust

```bash
PAIR=$(sudo docker exec vkr-token-1 wget -qO- \
  --post-data='{"user_id":"694cf7c5-0211-49b9-bd18-c2a3954ecac9","roles":["developer"],"trust_score":0.75}' \
  --header='Content-Type: application/json' http://localhost:8080/tokens/issue 2>/dev/null)
AT=$(echo $PAIR | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# ip-api.com identifies 8.8.8.8 as Google datacenter → ip_reputation=0
curl -s -w '\nHTTP:%{http_code}' http://localhost:3000/api/projects \
  -H "Authorization: Bearer $AT" \
  -H "X-Real-IP: 8.8.8.8"
# → HTTP:401 (trust too low due to datacenter IP)
```

---

## Scenario 5 — Step-up Re-authentication (RFC 9470)

When an API call returns `401 insufficient_user_authentication`, the client must re-authenticate.

```bash
# Step 1: API returns step-up challenge
curl -si http://localhost:3000/api/projects \
  -H "Authorization: Bearer $LOW_TRUST_TOKEN" | head -6
# HTTP/1.1 401 Unauthorized
# WWW-Authenticate: Bearer error="insufficient_user_authentication",
#   acr_values="zero_trust_mfa",
#   authorization_uri="http://localhost:3000/authorize"

# Step 2: Parse authorize_url from JSON body
# {"error":"insufficient_user_authentication","authorization_uri":"http://localhost:3000/authorize",...}

# Step 3: Client generates new PKCE and starts fresh /authorize flow
# (same as Scenario 1)

# Step 4: After re-authentication, the device is registered (from the blocked request)
# → trust score rises → API succeeds
```

---

## Scenario 6 — Forced Logout (trust score DENY)

When trust score drops below 0.30 during an API call (Tor + many failed attempts), the session is terminated immediately.

```bash
# Simulate DENY conditions: datacenter IP + 15 failed logins
sudo docker exec vkr-redis-1 redis-cli SET \
  "trust:fails:694cf7c5-0211-49b9-bd18-c2a3954ecac9" 15 EX 900

PAIR=$(sudo docker exec vkr-token-1 wget -qO- \
  --post-data='{"user_id":"694cf7c5-0211-49b9-bd18-c2a3954ecac9","roles":["developer"],"trust_score":0.75}' \
  --header='Content-Type: application/json' http://localhost:8080/tokens/issue 2>/dev/null)
AT=$(echo $PAIR | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# Call API with datacenter IP → trust score ~ 0.15 → DENY → forced logout
curl -s -w '\nHTTP:%{http_code}' http://localhost:3000/api/projects \
  -H "Authorization: Bearer $AT" \
  -H "X-Real-IP: 8.8.8.8"
# → HTTP:401

# Token family is now fully revoked — even a fresh introspect fails
curl -s -X POST http://localhost:3000/introspect \
  -H "Content-Type: application/json" \
  -d "{\"token\":\"$AT\"}" | python3 -c \
  "import sys,json; print('active:', json.load(sys.stdin)['active'])"
# active: False

# ForcedLogout event published to Kafka:
sudo docker exec vkr-kafka-1 bash -c \
  "kafka-console-consumer --bootstrap-server localhost:9092 \
   --topic token.events --from-beginning \
   --property print.key=true --timeout-ms 3000 2>/dev/null" | \
  python3 -c "
import sys,json
for line in sys.stdin:
  try:
    d=json.loads(line.split('\t',1)[-1].strip())
    if d.get('event')=='ForcedLogout':
      print('ForcedLogout | trust:', d.get('trust_score'), '| reason:', d.get('reason'))
  except: pass
"

# Clean up
sudo docker exec vkr-redis-1 redis-cli DEL \
  "trust:fails:694cf7c5-0211-49b9-bd18-c2a3954ecac9"
```

---

## Scenario 7 — Normal Logout

### Logout current session

```bash
curl -s -w '\nHTTP:%{http_code}' -X POST http://localhost:3000/logout \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"logout_all": false}'
# → HTTP:200

# Access token is now inactive
curl -s -X POST http://localhost:3000/introspect \
  -H "Content-Type: application/json" \
  -d "{\"token\": \"$ACCESS_TOKEN\"}" | python3 -c \
  "import sys,json; print('active:', json.load(sys.stdin)['active'])"
# active: False
```

### Logout all sessions

```bash
curl -s -w '\nHTTP:%{http_code}' -X POST http://localhost:3000/logout \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"logout_all": true}'
# → HTTP:200 — all refresh tokens in the family revoked
```

---

## Scenario 8 — Emergency Admin Revocation

An administrator can immediately revoke all tokens for a compromised user.

```bash
# Issue admin token (requires role=admin + trust ≥ 0.85 in production;
# here we simulate via internal token service)
sudo docker exec vkr-token-1 wget -qO- \
  --post-data='{"user_id":"694cf7c5-0211-49b9-bd18-c2a3954ecac9","admin_id":"admin-001","reason":"account_compromise"}' \
  --header='Content-Type: application/json' \
  http://localhost:8080/tokens/admin/revoke-user 2>/dev/null | python3 -m json.tool
# {"revoked_families": N, "user_id": "..."}

# Via gateway with admin token (production path):
# POST http://localhost:3000/admin/users/{user_id}/revoke
# Authorization: Bearer <admin_access_token>
# {"reason": "account_compromise"}
```

**What happens:**
1. All token families for the user are retrieved from `user:families:{id}` Redis SET
2. Each family: `family.MarkRevoked` + `refresh.RevokeFamily`
3. All future introspects return `active: false`
4. `AdminRevokeUser` event published to Kafka → audit log

---

## Scenario 9 — Audit Log API

The audit service records all security events. Query them via the gateway.

### Get an access token with security_admin role

```bash
# Register the CLI fingerprint as a known device first
sudo docker exec vkr-trust-1 wget -qO- \
  --post-data='{"user_id":"694cf7c5-0211-49b9-bd18-c2a3954ecac9","ip":"127.0.0.1","user_agent":"test","fingerprint":"cli-fp-001","register":true,"timestamp":"2026-04-30T10:00:00Z"}' \
  --header='Content-Type: application/json' \
  http://localhost:8080/trust/evaluate 2>/dev/null >/dev/null
sleep 1

# Issue security_admin token
PAIR=$(sudo docker exec vkr-token-1 wget -qO- \
  --post-data='{"user_id":"694cf7c5-0211-49b9-bd18-c2a3954ecac9","roles":["security_admin"],"trust_score":0.90}' \
  --header='Content-Type: application/json' http://localhost:8080/tokens/issue 2>/dev/null)
AUDIT_TOKEN=$(echo $PAIR | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
```

### Query events

```bash
# All events (newest first, default limit=50)
curl -s "http://localhost:3000/audit/events" \
  -H "Authorization: Bearer $AUDIT_TOKEN" \
  -H "X-TLS-Fingerprint: cli-fp-001" | python3 -c "
import sys,json
d=json.load(sys.stdin)
print(f'total: {d[\"total\"]}')
for e in d['events']:
    print(f'  {e[\"event_type\"]:35} {e[\"created_at\"]}')
"

# Filter by event type
curl -s "http://localhost:3000/audit/events?event_type=ForcedLogout" \
  -H "Authorization: Bearer $AUDIT_TOKEN" \
  -H "X-TLS-Fingerprint: cli-fp-001" | python3 -c "
import sys,json; d=json.load(sys.stdin)
print('total:', d['total'])
for e in d['events']:
    print(f'  score={e[\"payload\"].get(\"trust_score\")} reason={e[\"payload\"].get(\"reason\")}')
"

# Filter by user_id
curl -s "http://localhost:3000/audit/events?user_id=694cf7c5-0211-49b9-bd18-c2a3954ecac9&limit=10" \
  -H "Authorization: Bearer $AUDIT_TOKEN" \
  -H "X-TLS-Fingerprint: cli-fp-001" | python3 -c "
import sys,json; d=json.load(sys.stdin)
print('total:', d['total'])
for e in d['events']:
    print(f'  {e[\"event_type\"]}')
"

# Pagination
curl -s "http://localhost:3000/audit/events?limit=5&offset=5" \
  -H "Authorization: Bearer $AUDIT_TOKEN" \
  -H "X-TLS-Fingerprint: cli-fp-001" | python3 -c "
import sys,json; d=json.load(sys.stdin)
print(f'total={d[\"total\"]} limit={d[\"limit\"]} offset={d[\"offset\"]}')
"

# developer token → 403 (wrong role)
curl -s -w '\nHTTP:%{http_code}' "http://localhost:3000/audit/events" \
  -H "Authorization: Bearer $ACCESS_TOKEN" | tail -1
# HTTP:403
```

### Query filters reference

| Parameter | Description | Example |
|-----------|-------------|---------|
| `user_id` | Filter by user UUID | `?user_id=694cf7c5-...` |
| `event_type` | Filter by event type | `?event_type=ForcedLogout` |
| `from` | Start date (ISO 8601) | `?from=2026-04-01` |
| `to` | End date (ISO 8601) | `?to=2026-04-30` |
| `limit` | Max results (1–200) | `?limit=20` |
| `offset` | Pagination offset | `?offset=40` |

### Event types

| Event | Service | Trigger |
|-------|---------|---------|
| `TokenReuseAttackDetected` | token | Consumed refresh token reused |
| `ForcedLogout` | token | Trust score drops to DENY during API call |
| `AdminRevokeUser` | token | Admin revokes all user tokens |

---

## Scenario 10 — Prometheus Metrics and Grafana

### View raw metrics

```bash
# Gateway metrics
curl -s http://localhost:3000/metrics | grep -E "^gateway_"

# Token service metrics (via docker exec)
sudo docker exec vkr-token-1 wget -qO- http://localhost:8080/metrics 2>/dev/null \
  | grep -E "^token_"
```

### Key metrics

| Metric | Type | Description |
|--------|------|-------------|
| `gateway_login_total{decision}` | Counter | Login completions by trust decision |
| `gateway_mfa_total{result}` | Counter | MFA attempts (success/invalid_code) |
| `gateway_token_exchange_total{result}` | Counter | Code→token exchanges |
| `gateway_token_refresh_total{result}` | Counter | Refresh attempts |
| `gateway_api_requests_total{resource,action,result}` | Counter | API requests by outcome |
| `gateway_step_up_challenges_total{resource}` | Counter | 401 step-up challenges sent |
| `token_introspect_total{result}` | Counter | Introspect calls (active/inactive/forced_logout) |
| `token_introspect_trust_score` | Histogram | Trust score distribution at introspect |
| `token_issue_total` | Counter | Token pairs issued |
| `token_refresh_total{result}` | Counter | Refresh by result |
| `token_forced_logout_total` | Counter | Sessions terminated by DENY decision |

### Grafana dashboards

Open **http://localhost:9091** (admin / admin).

The **Zero Trust Auth** dashboard (auto-provisioned) contains:
- Login flow decisions per minute
- Token operations per minute (issue, refresh, reuse attacks, forced logouts)
- Trust score distribution histogram
- API requests by resource and result
- Step-up challenges by resource
- MFA success rate
- Active introspects per second

### Prometheus query examples

```bash
# Login rate over last 5 minutes
curl -sg 'http://localhost:9090/api/v1/query?query=rate(gateway_login_total[5m])*60' \
  | python3 -c "import sys,json; [print(r['metric']['decision'], r['value'][1]) for r in json.load(sys.stdin)['data']['result']]"

# Average trust score (over histogram)
curl -sg 'http://localhost:9090/api/v1/query?query=rate(token_introspect_trust_score_sum[5m])/rate(token_introspect_trust_score_count[5m])' \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print('avg trust:', d['data']['result'][0]['value'][1] if d['data']['result'] else 'no data')"

# Forced logout count
curl -sg 'http://localhost:9090/api/v1/query?query=token_forced_logout_total' \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print('forced logouts:', d['data']['result'][0]['value'][1] if d['data']['result'] else 0)"
```

---

## Scenario 11 — Keycloak Password Failures → Velocity Signal

The `keycloak-bridge` service listens to Keycloak events via Kafka SPI and updates the trust velocity counter in real time.

```bash
# Simulate 3 wrong password attempts
for i in 1 2 3; do
  curl -s -X POST http://localhost:8080/realms/demo/protocol/openid-connect/token \
    -d client_id=zero-trust-app -d username=testuser -d password=WRONG$i \
    -d grant_type=password -d client_secret=changeme >/dev/null
  echo "Attempt $i: wrong password"
done

# Wait for keycloak-bridge to process events (~2s)
sleep 3

# Check velocity counter in Redis
sudo docker exec vkr-redis-1 redis-cli GET \
  "trust:fails:694cf7c5-0211-49b9-bd18-c2a3954ecac9"
# → 3 (or higher if previous tests added more)

# Verify keycloak-bridge processed the events
sudo docker compose logs keycloak-bridge --tail=10 2>/dev/null | grep LOGIN_ERROR
# → LOGIN_ERROR: fails incremented ...

# After successful login → fails reset to 0
# (ContinueCase calls trust.ResetFails on ALLOW)
```

---

## OPA Policy Reference

```bash
# Run all policy unit tests
docker run --rm -v $(pwd)/toolkit/policies:/policies:ro \
  openpolicyagent/opa:latest test /policies -v
```

Full policy matrix:

```bash
for role in developer viewer admin security_admin; do
  for resource in projects reports secrets admin audit; do
    result=$(curl -s -X POST http://localhost:8181/v1/data/authz/allow \
      -H "Content-Type: application/json" \
      -d "{\"input\":{\"user\":{\"roles\":[\"$role\"],\"trust_score\":0.75},\"resource\":\"$resource\",\"action\":\"read\"}}" \
      | python3 -c "import sys,json; print(json.load(sys.stdin).get('result', False))")
    echo "$role + $resource = $result"
  done
done
```

---

## Troubleshooting

### active: false on introspect

Token expired (TTL 1h) or family was revoked. Issue a new token:
```bash
# Via browser login (full flow) or via refresh token
curl -s -X POST http://localhost:3000/token \
  -d "grant_type=refresh_token" \
  -d "refresh_token=$REFRESH_TOKEN" | python3 -m json.tool
```

### 401 insufficient_user_authentication

Trust score too low. The response includes `authorization_uri` — start a fresh OAuth flow from that URL. After re-authentication from the same browser, the device is registered and trust rises.

### 403 forbidden (permanent)

Wrong role for the resource. Check `roles` in introspect response.

### Code gives invalid_grant

The authorization code expired (TTL 5 minutes). Generate a new PKCE pair and repeat the login.

### Trust score unexpectedly low

Check for stale geo-context (from previous IP tests) or high velocity counter:
```bash
sudo docker exec vkr-redis-1 redis-cli KEYS "*694cf7c5*"
sudo docker exec vkr-redis-1 redis-cli KEYS "trust:ip:*"
# If stale data found:
sudo docker exec vkr-redis-1 redis-cli DEL \
  "trust:last:694cf7c5-0211-49b9-bd18-c2a3954ecac9" \
  "trust:fails:694cf7c5-0211-49b9-bd18-c2a3954ecac9"
sudo docker exec vkr-redis-1 redis-cli KEYS "trust:ip:*" | \
  xargs -r sudo docker exec -i vkr-redis-1 redis-cli DEL
```

### Keycloak-bridge not processing events

```bash
sudo docker compose logs keycloak-bridge --tail=20
# Check if Kafka topic has messages:
sudo docker exec vkr-kafka-1 bash -c \
  "kafka-run-class kafka.tools.GetOffsetShell \
   --bootstrap-server localhost:9092 --topic keycloak.events"
```

---

## Stopping the System

```bash
# Stop, keep data
sudo docker compose down

# Full reset (delete all data)
sudo docker compose down --volumes

# Rebuild after code changes
sudo docker compose build <service>
sudo docker compose up -d <service>
```

---

## Quick Reference

| What | Command |
|------|---------|
| Start all | `sudo docker compose up -d` |
| Check status | `sudo docker compose ps` |
| Tail logs | `sudo docker compose logs -f gateway` |
| Gateway health | `curl http://localhost:3000/health` |
| Introspect token | `curl -X POST http://localhost:3000/introspect -H "Content-Type: application/json" -d '{"token":"..."}'` |
| OPA query | `curl -X POST http://localhost:8181/v1/data/authz/allow -H "Content-Type: application/json" -d '{"input":{...}}'` |
| Grafana | http://localhost:9091 (admin/admin) |
| Prometheus | http://localhost:9090 |
| Audit log API | `GET http://localhost:3000/audit/events?limit=20` |
| Admin revoke | `POST http://localhost:3000/admin/users/{id}/revoke` |
| Gateway metrics | `curl http://localhost:3000/metrics` |
| Run OPA tests | `docker run --rm -v $(pwd)/toolkit/policies:/p openpolicyagent/opa test /p -v` |
