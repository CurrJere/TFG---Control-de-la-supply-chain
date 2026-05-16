#!/usr/bin/env bash
# validate-package-json.sh
# Capa 1 del framework: validación estructural del package.json.
# Detecta:
#   - Versiones flotantes ("latest", "*")              [CRITICAL]
#   - Rangos abiertos con caret ("^x.y.z")             [HIGH]
#   - Rangos abiertos con tilde ("~x.y.z")             [MEDIUM]
#   - Ausencia de package-lock.json                    [HIGH]

set -uo pipefail

PACKAGE_JSON="package.json"
LOCKFILE="package-lock.json"
FAIL_ON_FINDINGS="${FAIL_ON_FINDINGS:-false}"
FINDINGS=0

echo "::group::Validación estructural de package.json"

if [ ! -f "$PACKAGE_JSON" ]; then
  echo "::notice::No se encontró $PACKAGE_JSON en la raíz; nada que validar."
  echo "::endgroup::"
  exit 0
fi

# Comprobación del lockfile
if [ ! -f "$LOCKFILE" ]; then
  echo "::error file=$PACKAGE_JSON::[HIGH] Falta $LOCKFILE - dependencias no fijadas"
  FINDINGS=$((FINDINGS+1))
fi

# Recorre todas las secciones de dependencias con Node (más fiable que sed/awk)
output=$(node -e '
  const pkg = require("./'"$PACKAGE_JSON"'");
  const sections = ["dependencies","devDependencies","peerDependencies","optionalDependencies"];
  for (const s of sections) {
    if (!pkg[s]) continue;
    for (const [name,ver] of Object.entries(pkg[s])) {
      console.log([s,name,ver].join("\t"));
    }
  }
')

while IFS=$'\t' read -r section name ver; do
  [ -z "$section" ] && continue
  case "$ver" in
    "latest"|"*")
      echo "::error file=$PACKAGE_JSON::[CRITICAL] ${section}.${name} usa versión flotante '${ver}'"
      FINDINGS=$((FINDINGS+1))
      ;;
    ^*)
      echo "::warning file=$PACKAGE_JSON::[HIGH] ${section}.${name} usa rango caret '${ver}'"
      FINDINGS=$((FINDINGS+1))
      ;;
    ~*)
      echo "::warning file=$PACKAGE_JSON::[MEDIUM] ${section}.${name} usa rango tilde '${ver}'"
      FINDINGS=$((FINDINGS+1))
      ;;
  esac
done <<< "$output"

echo "::endgroup::"

if [ "$FINDINGS" -gt 0 ]; then
  echo "🔴 Total de hallazgos: $FINDINGS"
  if [ "$FAIL_ON_FINDINGS" = "true" ]; then
    exit 1
  fi
else
  echo "✅ package.json conforme con la política de versionado"
fi