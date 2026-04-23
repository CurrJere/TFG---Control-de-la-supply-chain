/**
 * @name TFG: NPM dependencia con versión latest o '*'
 * @description La dependencia en package.json usa 'latest' o '*'. Vector crítico de Dependency Confusion. Fija una versión exacta inmediatamente.
 * @kind problem
 * @problem.severity error
 * @precision high
 * @id currjere/javascript/npm-latest-or-star
 * @tags security, software-supply-chain, tfg
 * @security-severity 9.0
 */

import javascript
import semmle.javascript.NPM

/**
 * Devuelve (pkgJson, tipo, nombre, version) para todas las dependencias:
 *  tipo ∈ "", "dev", "bundled", "opt", "peer"
 */
predicate depEntry(PackageJson pj, string kind, string name, string ver) {
  pj.getADependenciesObject(kind).getADependency(name, ver)
  or kind = "peer" and pj.getPeerDependencies().getADependency(name, ver)
}

from PackageJson pj, string kind, string name, string ver
where depEntry(pj, kind, name, ver) and (ver = "latest" or ver = "*")
select pj,
  "Dependencia '" + name + "' (" + kind + ") usa versión '" + ver +
  "'. Fija una versión exacta."
