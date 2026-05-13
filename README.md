# Zero Trust Auth

Система аутентификации с нулевым доверием. Каждый запрос к API оценивается по набору сигналов риска: устройство, IP-репутация, геоаномалия, время суток, скорость ввода паролей. Решение о доступе принимается в реальном времени при каждой интроспекции токена.

## Архитектура

```
Browser → Gateway (3000) → Token Service
                         → Trust Service
                         → OPA (политики)
                         → Audit Service
                         → Keycloak
                         → IDPAdapter
```

**Сервисы:**

| Сервис         | Порт | Назначение |
|----------------|------|-----------|
| Gateway        | 3000 | OAuth2 endpoint, интроспекция, API proxy |
| Client App     | 4000 | Демо-приложение |
| Keycloak       | 8080 | Identity Provider |
| IDPAdapter     | 8090 | OIDC callback от Keycloak |
| Trust Service  | 8085 | Оценка доверия |
| Prometheus     | 9090 | Метрики |
| Grafana        | 9091 | Дашборды |

## Запуск

**Требования:** Docker, Docker Compose

```bash
git clone <repo>
cd vkr
cp .env.example .env
```

Отредактируй `.env` — минимум нужно задать:
- `GATEWAY_CLIENT_SECRET` — секрет клиента OAuth2
- `KEYCLOAK_CLIENT_SECRET` — должен совпадать с `GATEWAY_CLIENT_SECRET`

```bash
docker compose up --build
```

Подождать пока Keycloak поднимется (~30 сек), затем открыть [http://localhost:4000](http://localhost:4000).

## Конфигурация

Каждый сервис читает `config.yaml` из рабочей директории. Секреты подставляются из переменных окружения через `${VAR}`. Все параметры оценки доверия — веса сигналов, пороги решений, TTL — задаются в `trust/config/config.yaml`.

```yaml
trust:
  signals:
    device_known:  { weight: 0.25 }
    ip_reputation: { weight: 0.20 }
    geo_anomaly:   { weight: 0.30 }
    time_of_day:   { weight: 0.15 }
    velocity:      { weight: 0.10 }
  thresholds:
    allow: 0.70
    mfa_required: 0.50
    step_up: 0.30
```

## Тестирование

### Client App

Открой [http://localhost:4000](http://localhost:4000), нажми «Login». Keycloak редиректит обратно после аутентификации. Дашборд показывает `trust_score`, сигналы на момент входа и результаты проверки доступа к ресурсам.

Тестовый пользователь создаётся при первом запуске через realm-import: `testuser / testpassword`.

### API напрямую

Получить токены через PKCE:

```bash
python3 -c "
import base64, hashlib, os, urllib.parse
v = base64.urlsafe_b64encode(os.urandom(40)).rstrip(b'=').decode()
c = base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b'=').decode()
s = base64.urlsafe_b64encode(os.urandom(15)).rstrip(b'=').decode()
print('verifier:', v)
print('url: http://localhost:3000/authorize?client_id=zero-trust-app&code_challenge=' + c + '&code_challenge_method=S256&state=' + urllib.parse.quote(s))
print('state:', s)
"
```

Открыть URL в браузере, пройти логин. После редиректа взять `code` из URL и обменять:

```bash
curl -s -X POST http://localhost:3000/token \
  -d grant_type=authorization_code \
  -d code=CODE \
  -d code_verifier=VERIFIER \
  -d client_secret=changeme | jq
```

Интроспекция токена:

```bash
curl -s -X POST http://localhost:3000/introspect \
  -H "Content-Type: application/json" \
  -d '{"token": "ACCESS_TOKEN"}' | jq
```

Ответ содержит `trust_score` с детализацией по каждому сигналу и текущее решение.

### MFA

При `trust_score < 0.70` система требует TOTP. При первом входе показывается QR-код для Google Authenticator / Authy.

Принудительно снизить trust_score можно введя неверный пароль несколько раз перед входом — сигнал `velocity` отразит это в снапшоте `login_signals`.
