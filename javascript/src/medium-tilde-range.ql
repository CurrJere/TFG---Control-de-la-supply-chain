/**
 * @name TFG: NPM dependencia con rango tilde (~)
 * @description La dependencia en package.json usa rango tilde (~). Fija una versión exacta para reducir riesgos en la cadena de suministro.
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id currjere/javascript/npm-tilde-range
 * @tags security, software-supply-chain, tfg
 * @security-severity 5.0
 */

import javascript
import semmle.javascript.NPM

predicate depEntry(PackageJson pj, string kind, string name, string ver) {
  pj.getADependenciesObject(kind).getADependency(name, ver)
  or kind = "peer" and pj.getPeerDependencies().getADependency(name, ver)
}

from PackageJson pj, string kind, string name, string ver
where depEntry(pj, kind, name, ver) and ver.regexpMatch("^~")
select pj,
  "Dependencia '" + name + "' (" + kind + ") usa rango tilde '" + ver +
  "'. Fija una versión exacta."
