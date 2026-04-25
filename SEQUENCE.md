# Sequence Diagrams

## Login Flow (OAuth 2.0 Authorization Code + PKCE)

```mermaid
sequenceDiagram
    actor User
    participant Browser
    participant Client
    participant Gateway
    participant IDPAdapter
    participant IDP as Keycloak
    participant Auth
    participant Trust
    participant Token
    participant Audit

    User ->> Browser: sign-in to client app
    Browser ->> Client: sign-in
    Client ->> Client: generate code_verifier + code_challenge (PKCE)
    Client ->> Client: generate state
    Client ->> Browser: redirect to /authorize?code_challenge=...&state=...&client_id=...
    Browser ->> Gateway: GET /authorize?code_challenge=...&state=...&client_id=...
    Gateway ->> Gateway: store(state → {code_challenge, client_id, ip, ...}, ttl=10min)

    Gateway ->> Trust: anonymousCheck(ip, user_agent, fingerprint)

    alt DENY
        Trust ->> Gateway: DENY
        Gateway ->> Browser: 401 Unauthorized
    else ALLOW
        Trust ->> Gateway: ALLOW
        Gateway ->> IDPAdapter: getLoginURL(state)
        IDPAdapter ->> IDPAdapter: generate idp_code_verifier + idp_code_challenge (PKCE)
        IDPAdapter ->> IDPAdapter: store(state → idp_code_verifier)
        IDPAdapter ->> Gateway: loginURL?code_challenge=idp_code_challenge&state=...
        Gateway ->> Browser: redirect to loginURL

        Browser ->> IDP: GET loginURL
        IDP ->> Browser: login form
        Browser ->> User: render form
        User ->> Browser: enter credentials
        Browser ->> IDP: POST credentials
        IDP ->> IDP: verify credentials
        IDP ->> Browser: redirect to IDPAdapter /callback?code=idp_code&state=...
        Browser ->> IDPAdapter: GET /callback?code=idp_code&state=...

        IDPAdapter ->> IDPAdapter: idp_code_verifier = lookup(state)
        IDPAdapter ->> IDP: POST /token {code=idp_code, code_verifier=idp_code_verifier, client_secret}
        IDP ->> IDPAdapter: id_token {sub, email, roles, acr, amr}

        IDPAdapter ->> Auth: resolveUser(sub)
        Auth ->> IDPAdapter: internal user_id

        IDPAdapter ->> Gateway: POST /internal/continue {state, user_id, roles, requestCtx} (private port)

        Gateway ->> Trust: evaluateTrust(user_id, roles, requestCtx)
        Trust ->> Trust: compute trust_score (device, geo, time, velocity)
        Trust ->> Gateway: trust_score + decision

        alt DENY
            Gateway ->> Browser: 403 Forbidden
        else MFA_REQUIRED
            Gateway ->> Browser: redirect to MFA challenge
            Note over Browser,IDP: MFA flow (TOTP / WebAuthn)
            Browser ->> Gateway: MFA verified
            Gateway ->> Trust: re-evaluateTrust (score updated)
            Trust ->> Gateway: updated trust_score
        else ALLOW
            Gateway ->> Gateway: generate own_code
            Gateway ->> Gateway: store(own_code → {user_id, roles, trust_score, code_challenge}, ttl=60s)
            Gateway ->> Browser: redirect to Client /callback?code=own_code&state=...

            Browser ->> Client: own_code + state
            Client ->> Client: verify state matches original
            Client ->> Gateway: POST /token {code=own_code, code_verifier, client_secret}
            Gateway ->> Gateway: ctx = lookup(own_code) → {user_id, roles, trust_score, code_challenge}
            Gateway ->> Gateway: verify SHA256(code_verifier) == ctx.code_challenge
            Gateway ->> Gateway: verify client_secret
            Gateway ->> Gateway: delete(own_code)
            Gateway ->> Token: issue(ctx.user_id, ctx.roles, ctx.trust_score)
            Token ->> Gateway: access_token (opaque) + refresh_token (opaque)
            Gateway ->> Audit: publish UserLoggedIn
            Gateway ->> Client: access_token + refresh_token
            Client ->> Browser: sign-in finished
            Browser ->> User: sign-in finished
        end
    end
```

---

## API Request Flow (with Token Introspection + OPA)

```mermaid
sequenceDiagram
    participant Client
    participant Gateway
    participant Token as Token Service
    participant Trust
    participant OPA
    participant Resource as Resource Server
    participant Audit

    Client ->> Gateway: GET /api/secrets\nAuthorization: Bearer <opaque_token>
    Gateway ->> Token: POST /introspect {token: <opaque_token>}
    Token ->> Token: lookup token hash in Redis
    Token ->> Trust: re-evaluateTrust(user_id, current requestCtx)
    Trust ->> Token: updated trust_score
    Token ->> Gateway: {active: true, user_id, roles, trust_score, exp}

    Gateway ->> OPA: POST /v1/data/authz/allow\n{user: {roles, trust_score}, resource: "secrets", action: "read"}
    OPA ->> OPA: evaluate Rego policy
    OPA ->> Gateway: {result: true/false}

    alt DENY
        Gateway ->> Audit: publish AccessDenied
        Gateway ->> Client: 403 Forbidden
    else ALLOW
        Gateway ->> Resource: forward request
        Resource ->> Gateway: response
        Gateway ->> Client: response
    end
```

---

## Token Refresh Flow (with Rotation + Reuse Detection)

```mermaid
sequenceDiagram
    participant Client
    participant Gateway
    participant Token as Token Service
    participant Trust
    participant Audit
    participant Notify as Notify Service

    Client ->> Gateway: POST /token\n{grant_type: refresh_token, refresh_token: rt_OLD}
    Gateway ->> Token: refresh(rt_OLD)
    Token ->> Token: lookup hash(rt_OLD) in Redis

    alt status == CONSUMED (reuse detected)
        Token ->> Token: REVOKE entire family_id (all sessions)
        Token ->> Audit: publish TokenReuseAttackDetected
        Token ->> Notify: notify user (email + push)
        Token ->> Gateway: 401 Token reuse detected
        Gateway ->> Client: 401 Unauthorized
    else status == ACTIVE
        Token ->> Token: mark rt_OLD as CONSUMED
        Token ->> Trust: re-evaluateTrust(user_id, requestCtx)
        Trust ->> Token: updated trust_score
        Token ->> Token: issue new access_token + rt_NEW (same family_id)
        Token ->> Gateway: new access_token + rt_NEW
        Gateway ->> Client: new access_token + rt_NEW
    end
```

---

## Logout Flow

```mermaid
sequenceDiagram
    participant Client
    participant Gateway
    participant Token as Token Service
    participant IDP as Keycloak
    participant Audit

    Client ->> Gateway: POST /logout\nAuthorization: Bearer <access_token>
    Gateway ->> Token: revoke(access_token, logout_all=false)
    Token ->> Token: mark access_token REVOKED in Redis
    Token ->> Token: mark current refresh_token REVOKED
    Gateway ->> IDP: backchannel logout (Keycloak session)
    Gateway ->> Audit: publish UserLoggedOut
    Gateway ->> Client: 200 OK
```

---

## Trust Score Computation Detail

```
Signals collected per request:
┌─────────────────┬────────┬───────────────────────────────────────┐
│ Signal          │ Weight │ Source                                │
├─────────────────┼────────┼───────────────────────────────────────┤
│ device_known    │  0.25  │ Redis: trust:devices:{user_id}        │
│ ip_reputation   │  0.20  │ External API (cached Redis 1h)        │
│ geo_anomaly     │  0.30  │ Compare Redis trust:last:{user_id}    │
│ time_of_day     │  0.15  │ PG: trust_working_hours               │
│ velocity        │  0.10  │ Redis: trust:fails:{user_id}          │
└─────────────────┴────────┴───────────────────────────────────────┘

trust_score = Σ(signal.score × signal.weight)

Decisions:
  ≥ 0.80 → ALLOW
  0.50–0.79 → MFA_REQUIRED
  0.30–0.49 → STEP_UP
  < 0.30 → DENY

Impossible travel detection:
  distance_km(last_ip, current_ip) / time_hours > 900 → penalty -0.45
```
