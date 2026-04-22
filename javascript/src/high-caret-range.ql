/**
 * @name NPM dependencia con rango caret (^)
 * @description La dependencia en package.json usa rango con caret (^). Fija una versión exacta para reducir riesgo en la cadena de suministro.
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id bbva/javascript/npm-caret-range
 * @tags security, software-supply-chain
 * @security-severity 5.0
 */

import javascript

from PackageJson pkg, string depName, JsonValue depNode, string depVersion
where
  pkg.getDependencies().getPropValue(depName) = depNode and
  depVersion = depNode.getStringValue() and
  depVersion.regexpMatch("^\\^.*")
select depNode,
  "Dependencia '" + depName + "' usa rango caret '" + depVersion + "'. Fija una versión exacta para evitar ataques de Supply Chain."