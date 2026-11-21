## Qué cambia y por qué

<!-- Resumen del cambio y la motivación. Enlazar la historia de usuario (HU..) o issue. -->

## Tipo de cambio

- [ ] `feat` nueva funcionalidad
- [ ] `fix` corrección
- [ ] `refactor` / `perf` / `chore`
- [ ] `ci` / `build` / infraestructura
- [ ] `docs` / `test`

## Pruebas y calidad

- [ ] `./mvnw verify` en verde: unitarias, cobertura JaCoCo ≥ 70 % e integración (Testcontainers)
- [ ] Pruebas nuevas o actualizadas para el cambio (unitarias e integración)

## Contratos y despliegue

- [ ] **No cambia contratos** consumidos por clinical o el frontend (claims del JWT, `/api/auth/**`, `/internal/accounts`), o el cambio está coordinado con esos equipos
- [ ] Variables nuevas documentadas en el README (y en los manifiestos de `deploy/` cuando existan)

## Seguridad

- [ ] No hay secretos ni credenciales en el diff (gitleaks en verde); la configuración nueva se documenta en `.env.example` o en `deploy/env/`
- [ ] Sin hallazgos que bloqueen: Semgrep (ERROR), Trivy dependencias e imagen (CRITICAL / HIGH con parche)
- [ ] Dependencias nuevas o actualizadas revisadas (licencia, mantenimiento, CVEs)
- [ ] Validación de entradas y autorización consideradas (IDOR: ¿el usuario puede acceder a este recurso?)

## Revisión

- [ ] Commits con Conventional Commits y descripción que explica el **porqué**
- [ ] Rama actualizada y conversaciones de revisión resueltas
- [ ] Un *code owner* distinto del autor revisó el cambio (lo exige la protección de `main`)
