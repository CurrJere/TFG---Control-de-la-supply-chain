/**
 * @name TFG: Falta package-lock.json en repositorio
 * @description Detecta proyectos npm que no incluyen el archivo package-lock.json, impidiendo el pinning de dependencias. Contramedida de inmutabilidad.
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id currjere/javascript/missing-package-lock
 * @tags security, external/cwe/cwe-1104, owasp-a06, software-supply-chain, tfg
 * @security-severity 5.0
 */

import javascript
import semmle.javascript.Files

/**
 * Existe package.json en el repositorio.
 */

 predicate hasPackageJson() {
  exists(File f | f.getRelativePath() = "package.json")
}
/**
 * No existe package-lock.json.
 */predicate missingPackageLock() {
  not exists(File f | f.getRelativePath() = "package-lock.json")
}
/**
 Devolvemos el package.json como ubicación del hallazgo.
 */
from File pkg
where pkg.getRelativePath() = "package.json"
  and hasPackageJson()
  and missingPackageLock()
select pkg,
  "Este repositorio contiene package.json pero no package-lock.json. "
  + "Las dependencias no están fijadas y se recomienda incluir un lock file para evitar riesgos SCA."