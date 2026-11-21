# oncontrol3d-auth-service

Identity provider of OnControl3D: accounts (bcrypt credentials), login, HS256 JWT issuance,
login rate limiting, audit log and the internal provisioning API consumed by the clinical service.

- Stack: Spring Boot 3.5 / Java 21, PostgreSQL, port `8082`.
- It never calls the clinical service (dependency is one-way: clinical -> auth).
- Tests: `./mvnw -B -ntp test` (JUnit, MockMvc, Testcontainers; JaCoCo line gate 70 %).

See the SDD change `auth-service-extraction` for the full contract.
