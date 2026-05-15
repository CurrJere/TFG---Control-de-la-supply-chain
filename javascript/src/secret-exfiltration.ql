/**
 * @name TFG: Exfiltración de secretos a red externa
 * @description Detecta flujo desde lectura de variables de entorno
 *              o .env hacia peticiones HTTP salientes. Vector típico
 *              de gusano de supply chain (Shai-Hulud).
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id currjere/javascript/secret-exfiltration
 * @tags security, software-supply-chain, tfg, external/cwe/cwe-200
 * @security-severity 9.5
 */

import javascript
import semmle.javascript.dataflow.TaintTracking

/**
 * Lugares de los que parte la información sensible (sources):
 *   - process.env.<lo-que-sea>
 *   - fs.readFileSync('.env', ...) y similares
 */
class SecretSource extends DataFlow::Node {
  SecretSource() {
    // process.env.X o process.env['X']
    this = DataFlow::globalVarRef("process").getAPropertyRead("env").getAPropertyRead(_)
    or
    // fs.readFileSync('.env'), fs.readFile('.env'), etc.
    exists(DataFlow::CallNode call |
      call = DataFlow::moduleMember("fs", _).getACall() and
      call.getArgument(0).asExpr().(StringLiteral).getValue().regexpMatch(".*\\.env.*") and
      this = call
    )
  }
}

/**
 * Lugares peligrosos a los que NO debe llegar la información (sinks):
 *   - http.request / https.request (módulo nativo)
 *   - fetch (Node 18+) y librerías de red (axios, got, request, ...)
 */
class NetworkSink extends DataFlow::Node {
  NetworkSink() {
    this = any(ClientRequest req).getUrl()
    or
    this = any(ClientRequest req).getADataNode()
  }
}

module ExfilConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof SecretSource }
  predicate isSink(DataFlow::Node n)   { n instanceof NetworkSink   }
}

module ExfilFlow = TaintTracking::Global<ExfilConfig>;
import ExfilFlow::PathGraph

from ExfilFlow::PathNode source, ExfilFlow::PathNode sink
where ExfilFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Posible exfiltración: dato sensible originado en $@ alcanza una petición de red.",
  source.getNode(), "esta lectura"