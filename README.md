# oncontrol3d-auth-service

Identity provider of OnControl3D: accounts (bcrypt credentials), login, HS256 JWT issuance,
login rate limiting, audit log and the internal provisioning API consumed by the clinical service.

- Stack: Spring Boot 3.5 / Java 21, PostgreSQL, port `8082`.
- It never calls the clinical service (dependency is one-way: clinical -> auth).
- Tests: `./mvnw -B -ntp test` (JUnit, MockMvc, Testcontainers; JaCoCo line gate 70 %).

See the SDD change `auth-service-extraction` for the full contract.

## Configuration

| Variable | Purpose |
|---|---|
| `DB_URL`, `DB_USERNAME`, `DB_PASSWORD` | PostgreSQL database `oncontrol_auth` |
| `JWT_SECRET` | HS256 key, >= 32 bytes, identical to the clinical service |
| `AUTH_INTERNAL_TOKEN` | Token for `/internal/**`, >= 32 bytes, shared with clinical |
| `PORT` | Defaults to `8082` |

The service refuses to start when `JWT_SECRET` or `AUTH_INTERNAL_TOKEN` is blank or shorter than 32 bytes.

## API

- `POST /api/auth/login` (public, rate limited 5/min per IP): 200 slim body, 401 `{"message":"Invalid credentials"}`, 429.
- `GET /api/auth/audit?size=50` (Bearer, role ORGANIZATION): own-organization audit events, newest first.
- `POST /internal/accounts`, `DELETE /internal/accounts/{id}` (header `X-Internal-Token`): provisioning for the clinical service. Never route `/internal/**` through an edge or proxy.
- `GET /health`.
