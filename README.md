# Control de la Supply Chain en NPM

Framework de endurecimiento de pipelines CI/CD frente a gusanos de cadena de
suministro en el ecosistema NPM. Implementa una defensa en profundidad de dos
capas sobre GitHub Actions, diseñada a partir del caso de estudio del gusano
**Shai-Hulud (2025)**.

Trabajo de Fin de Grado — Ingeniería Informática, Universidad Francisco de
Vitoria.

---

## Modelo de amenaza

Los gusanos de cadena de suministro como Shai-Hulud se propagan abusando de dos
mecanismos legítimos del ecosistema NPM:

1. **Scripts de ciclo de vida** (`postinstall`, `preinstall`): ejecución
   automática de código arbitrario durante `npm install`.
2. **Rangos de versión flotantes** (`^`, `~`, `latest`): resolución no
   determinista que permite introducir una versión comprometida sin cambiar el
   manifiesto.

El payload característico exfiltra secretos del entorno de CI (tokens, claves)
hacia un servidor externo y reutiliza esas credenciales para publicar versiones
infectadas de otros paquetes, cerrando el ciclo de propagación.

Este framework ataca ambos vectores: bloquea la ejecución de scripts y detecta
tanto las versiones flotantes (estáticamente) como el flujo de exfiltración
(semánticamente).

---

## Arquitectura

Defensa en profundidad en dos capas independientes. Un fallo en una no
compromete la otra.

### Capa 1 — Validación estructural

`scripts/validate-package-json.sh`

Analiza el manifiesto `package.json` mediante *parsing* JSON con Node.js
(evitando los falsos negativos de `sed`/`awk` ante formateo irregular) y verifica
la política de control de versiones:

| Hallazgo                                    | Severidad |
| ------------------------------------------- | --------- |
| Versión `latest` o wildcard `*`             | CRITICAL  |
| Rango caret (`^`)                           | HIGH      |
| Rango tilde (`~`)                           | MEDIUM    |
| Ausencia de `package-lock.json`             | HIGH      |

Las alertas se emiten como anotaciones nativas del pipeline (`::error::`,
`::warning::`). El modo estricto (`fail-on-findings`) aborta la ejecución cuando
se detectan anomalías.

> **Alcance conocido:** la Capa 1 cubre `*`, `latest`, `^` y `~`. Otros rangos
> abiertos (`>=`, `x`-ranges, rangos con guion, specs `git+`) quedan fuera del
> alcance actual y se documentan como línea de trabajo futura.

### Capa 2 — Análisis semántico

`javascript/src/secret-exfiltration.ql`

Consulta CodeQL con *taint tracking* (análisis de flujo de datos contaminados).
Modela como **fuentes** las lecturas de `process.env` y de ficheros `.env`, y
como **sumideros** las peticiones de red salientes (abstracción `ClientRequest`,
que cubre `http`/`https` nativo, `fetch` y `axios`). Detecta el flujo
fuente -> sumidero característico de la exfiltración de Shai-Hulud.

Los resultados se publican en `Security -> Code scanning` del repositorio cliente.

### Security Gate

El pipeline intercepta los resultados en crudo (SARIF) de la Capa 2 con `jq` y
**aborta el despliegue** si confirma cualquier flujo de exfiltración, antes de
que se instalen las dependencias.

---

## Uso

El framework se consume como *reusable workflow*. En el repositorio cliente,
crea `.github/workflows/security.yml`:

```yaml
name: Security
on: [push, pull_request]

jobs:
  supply-chain:
    uses: CurrJere/TFG---Control-de-la-supply-chain/.github/workflows/secure-pipeline.yml@v1.0.0
    with:
      fail-on-findings: 'true'
```

La referencia por defecto es el tag `v1.0.0`, inmutable por convención. Para
máxima inmutabilidad puedes fijar el SHA del release:

```bash
git rev-list -n 1 v1.0.0
```

### Parámetros

| Input              | Descripción                                                       | Defecto    |
| ------------------ | ----------------------------------------------------------------- | ---------- |
| `framework-repo`   | Repositorio host del framework                                    | `CurrJere/TFG---Control-de-la-supply-chain` |
| `framework-ref`    | Referencia del framework (tag de release)                         | `v1.0.0`   |
| `fail-on-findings` | Aborta el pipeline si la Capa 1 detecta anomalías estructurales   | `false`    |

### Configuración recomendada en el cliente (`.npmrc`)

```properties
ignore-scripts=true   # bloquea scripts de ciclo de vida (vector postinstall)
audit-level=high      # alerta solo de severidad alta/crítica
fund=false
loglevel=warn
```

---

## Diseño autodefensivo

El propio pipeline aplica los controles que propone:

- Todos los `actions` se fijan por **SHA criptográfico** con el tag como
  comentario.
- `permissions` mínimas (`contents: read`, `security-events: write`,
  `actions: read`).
- Instalación con `npm ci --ignore-scripts`: respeta el lockfile y anula la
  propagación automática.

---

## Estructura del repositorio

```
.
├── .github/workflows/secure-pipeline.yml   # Reusable workflow (orquestación)
├── scripts/validate-package-json.sh        # Capa 1
├── javascript/
│   ├── qlpack.yml                           # Definición del CodeQL pack
│   └── src/secret-exfiltration.ql           # Capa 2
└── .npmrc                                    # Configuración de referencia
```

El repositorio complementario
[`npm-supply-chain-sandbox`](https://github.com/CurrJere/npm-supply-chain-sandbox)
contiene el entorno señuelo (*honeypot*) usado para validar la detección.

---

## Licencia

MIT. Véase [`LICENSE`](LICENSE).

---

## Contexto académico

Desarrollado como Trabajo de Fin de Grado en Ingeniería Informática (UFV).
El framework es una prueba de concepto con alcance acotado; las limitaciones
conocidas se documentan en la memoria del proyecto.
