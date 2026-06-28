/**
 * @name TFG: Exfiltración de secretos a red externa
 * @description Detecta el flujo de datos desde la lectura de variables de entorno 
 * o archivos .env hacia peticiones HTTP de salida. Vector de ataque 
 * característico de gusanos de cadena de suministro como Shai-Hulud.
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
 * Fuentes de información sensible (Sources)
 * Mapeamos los puntos de entrada donde se cargan o leen credenciales del sistema.
 */
class SecretSource extends DataFlow::Node {
  SecretSource() {
    // Captura lecturas del tipo process.env.TOKEN o process.env['PASSWORD']
    this = DataFlow::globalVarRef("process").getAPropertyRead("env").getAPropertyRead(_)
    or
    // Captura llamadas al módulo nativo 'fs' que involucren archivos de entorno (.env)
    exists(DataFlow::CallNode call |
      call = DataFlow::moduleMember("fs", _).getACall() and
      call.getArgument(0).asExpr().(StringLiteral).getValue().regexpMatch(".*\\.env.*") and
      this = call
    )
  }
}

/**
 * Puntos de salida de riesgo (Sinks)
 * Modelamos el envío de información mediante peticiones de red salientes.
 */
class NetworkSink extends DataFlow::Node {
  NetworkSink() {
    // Utilizamos la abstracción ClientRequest para cubrir tanto las funciones HTTP/HTTPS 
    // nativas como abstracciones de alto nivel (fetch, axios, etc.)
    this = any(ClientRequest req).getUrl()
    or
    this = any(ClientRequest req).getADataNode()
  }
}

// Configuración del motor de Taint Tracking (Análisis de flujo de datos contaminados)
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