#!/usr/bin/env bash
# =========================================================================
# Capa 1: Validación Estructural del Manifiesto de Dependencias
# 
# Evalúa la presencia del archivo de bloqueo y analiza sintácticamente el
# package.json para detectar rangos de versiones dinámicas o flotantes.
# =========================================================================

set -uo pipefail

PACKAGE_JSON="package.json"
LOCKFILE="package-lock.json"
FAIL_ON_FINDINGS="${FAIL_ON_FINDINGS:-false}"
FINDINGS=0

echo "::group::[Capa 1] Auditoría Estructural"

if [ ! -f "$PACKAGE_JSON" ]; then
  echo "[INFO] No se localizó '$PACKAGE_JSON' en el directorio raíz. Omitiendo validación."
  echo "::endgroup::"
  exit 0
fi

# 1. Control de consistencia del Lockfile
# Mitiga el riesgo de instalaciones indeterministas en el entorno de build.
if [ ! -f "$LOCKFILE" ]; then
  echo "::error file=$PACKAGE_JSON::[CRITICAL] Ausencia de '$LOCKFILE'. El despliegue carece de árbol fijado."
  FINDINGS=$((FINDINGS+1))
fi

# 2. Extracción de dependencias mediante evaluación en línea de Node.js
# Se prefiere esta aproximación frente a parsers de texto plano (sed/awk)
# para evitar falsos negativos por formateo o saltos de línea en el JSON.
output=$(node -e '
  try {
    const pkg = require("./'"$PACKAGE_JSON"'");
    const sections = ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"];
    
    sections.forEach(section => {
      if (pkg[section]) {
        Object.entries(pkg[section]).forEach(([name, ver]) => {
          console.log([section, name, ver].join("\t"));
        });
      }
    });
  } catch (err) {
    console.error("[ERROR] Fallo crítico al parsear el manifiesto: " + err.message);
    process.exit(1);
  }
')

# 3. Análisis de cumplimiento de la política de control de versiones
while IFS=$'\t' read -r section name ver; do
  [ -z "$section" ] && continue
  
  case "$ver" in
    "latest"|"*")
      echo "::error file=$PACKAGE_JSON::[CRITICAL] Versión flotante detectada en ${section}.${name} -> '${ver}'"
      FINDINGS=$((FINDINGS+1))
      ;;
    ^*)
      echo "::warning file=$PACKAGE_JSON::[HIGH] Rango abierto tipo Caret (^) en ${section}.${name} -> '${ver}'"
      FINDINGS=$((FINDINGS+1))
      ;;
    ~*)
      echo "::warning file=$PACKAGE_JSON::[MEDIUM] Rango abierto tipo Tilde (~) en ${section}.${name} -> '${ver}'"
      FINDINGS=$((FINDINGS+1))
      ;;
  esac
done <<< "$output"

echo "::endgroup::"

# 4. Evaluación del Security Gate de la Capa 1
if [ "$FINDINGS" -gt 0 ]; then
  echo "[WARN] Análisis finalizado. Anomalías estructurales detectadas: $FINDINGS"
  
  if [ "$FAIL_ON_FINDINGS" = "true" ]; then
    echo "[CRITICAL] Directiva Fail-Fast activa. Abortando ejecución del pipeline."
    exit 1
  fi
  echo "[INFO] Continuando ejecución del workflow (Modo permisivo)."
else
  echo "[INFO] Validación estructural correcta. El manifiesto se alinea con la política."
fi