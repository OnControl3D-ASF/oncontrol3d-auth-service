## Qué cambia y por qué

<!-- Resumen del cambio y la motivación. Enlazar la historia de usuario (HU..) o issue. -->

## Tipo de cambio

- [ ] `feat` nueva funcionalidad
- [ ] `fix` corrección
- [ ] `refactor` / `perf` / `chore`
- [ ] `ci` / `build` / infraestructura
- [ ] `docs` / `test`

## Pruebas y calidad

- [ ] `./mvnw -B -ntp test` en verde: unitarias, integración (Testcontainers) y cobertura JaCoCo ≥ 70 %
- [ ] Pruebas nuevas o actualizadas para el cambio

## Contratos y despliegue

- [ ] **No cambia contratos de API consumidos por clinical/frontend** (rutas, DTOs, claims del JWT, códigos HTTP), o el cambio está coordinado
- [ ] `/internal/**` sigue sin exponerse por ningún edge/proxy

## Seguridad

- [ ] No hay secretos ni credenciales en el diff (gitleaks en verde); la configuración nueva se documenta en el README
- [ ] Sin hallazgos que bloqueen: Semgrep (ERROR), Trivy dependencias e imagen (CRITICAL / HIGH con parche)
- [ ] Contraseñas, hashes y tokens nunca se registran en logs ni en respuestas

## Revisión

- [ ] Commits con Conventional Commits y descripción que explica el **porqué**
- [ ] Un *code owner* distinto del autor revisó el cambio (lo exige la protección de `main`)
