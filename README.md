## Arquitectura de doble capa

El framework aplica defensa en profundidad combinando dos paradigmas
complementarios, alineados con las mejores prácticas del sector financiero:

### Capa 1 — Validación estructural
`scripts/validate-package-json.sh`

Analiza el manifiesto `package.json` del cliente mediante parsing JSON
nativo, detectando los siguientes vectores de cadena de suministro:

| Hallazgo | Severidad |
|---|---|
| Versión `latest` o wildcard `*` | CRITICAL |
| Rango caret (`^`) | HIGH |
| Rango tilde (`~`) | MEDIUM |
| Ausencia de `package-lock.json` | HIGH |

Las alertas se publican como anotaciones en los logs del pipeline mediante
los comandos `::error::` y `::warning::` de GitHub Actions.

### Capa 2 — Análisis semántico
`javascript/src/secret-exfiltration.ql`

Aplica CodeQL con análisis de flujo de datos (taint tracking) para
detectar flujos desde lectura de variables de entorno o ficheros `.env`
hacia peticiones HTTP/HTTPS salientes (vector de gusano Shai-Hulud).

Las alertas se publican en la pestaña Security → Code scanning del
repositorio cliente.