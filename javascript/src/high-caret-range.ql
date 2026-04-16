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
import semmle.javascript.packages.PackageJson

from PackageJsonDependency dep
where dep.getVersion().regexpMatch("^\\^")
select dep,
  "Dependencia '" + dep.getPackageName() + "' usa rango caret '" + dep.getVersion() + "'. Fija una versión exacta para evitar ataques de Supply Chain."