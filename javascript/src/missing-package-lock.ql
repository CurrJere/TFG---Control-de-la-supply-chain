/**
 * @name TFG: Falta package-lock.json en repositorio
 * @description Detecta proyectos npm que no incluyen package-lock.json en la
 *              misma carpeta que el package.json, impidiendo el pinning
 *              reproducible de dependencias.
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id currjere/javascript/missing-package-lock
 * @tags security, external/cwe/cwe-1104, owasp-a06, software-supply-chain, tfg
 * @security-severity 5.0
 */

import javascript

from File pkg, Folder dir
where
  pkg.getBaseName() = "package.json" and
  pkg.getParentContainer() = dir and
  not exists(File lock |
    lock.getBaseName() = "package-lock.json" and
    lock.getParentContainer() = dir
  )
select pkg,
  "Este repositorio contiene package.json pero no package-lock.json en la misma carpeta. "
  + "Las dependencias no están fijadas; se recomienda incluir un lock file."