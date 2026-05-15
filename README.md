# Endurecimiento de CI/CD frente a gusanos de supply chain en NPM

Framework reutilizable de seguridad para pipelines de CI/CD basados en
GitHub Actions, diseñado para mitigar la familia de ataques de tipo
"supply chain worm" en el ecosistema npm (vector Shai-Hulud y similares).

Trabajo Fin de Grado — Grado en Ingeniería Informática
Universidad Francisco de Vitoria, convocatoria de [mes] de 2026
Autor: Francisco Jesús Daza Sánchez

## ¿Qué hace este framework?

Aplica cinco controles de defensa sobre cualquier repositorio cliente
que lo invoque mediante `workflow_call`:

1. Bloqueo de dependencias con versión `latest` o wildcard (`*`).
2. Detección de rangos abiertos con caret (`^`) y tilde (`~`).
3. Verificación de la existencia obligatoria de `package-lock.json`.
4. Análisis de flujo de datos (taint tracking) para detectar
   exfiltración de secretos hacia red externa.
5. Instalación reproducible con `npm ci --ignore-scripts`.

## Uso

En tu repositorio cliente, crea `.github/workflows/ci.yml`:

\`\`\`yaml
name: App Pipeline Protected

on:
  push:
    branches: [ "main" ]

jobs:
  security-check:
    uses: CurrJere/TFG---Control-de-la-supply-chain/.github/workflows/secure-npm-pipeline.yml@main
    permissions:
      contents: read
      security-events: write
      actions: read
\`\`\`

Las alertas aparecerán en la pestaña Security → Code scanning del
repositorio cliente.

## Estructura del repositorio

\`\`\`
.github/workflows/secure-npm-pipeline.yml    Pipeline reutilizable
.npmrc                                        Configuración de seguridad de npm
javascript/codeql-pack.yml                    Paquete CodeQL
javascript/src/                               Reglas CodeQL personalizadas
\`\`\`

## Reglas CodeQL incluidas

| Fichero | Severidad | Detecta |
|---|---|---|
| critical-latest-or-wildcard.ql | error | `"dep": "latest"` o `"dep": "*"` |
| high-caret-range.ql | warning | `"dep": "^1.2.3"` |
| medium-tilde-range.ql | warning | `"dep": "~1.2.3"` |
| missing-package-lock.ql | warning | Ausencia de package-lock.json |
| secret-exfiltration.ql | error | Flujo de `process.env` o `.env` hacia red saliente |

## Licencia

MIT. Ver fichero LICENSE.