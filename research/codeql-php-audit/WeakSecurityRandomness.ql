/**
 * @name Weak randomness used to derive a security secret or token
 * @description A value from a predictable PRNG (rand / mt_rand / lcg_value) is fed — directly or via
 *              `uniqid()` — into a hash (md5 / sha1 / hash / hash_hmac / crypt) whose result becomes a
 *              security secret: a cookie value, or a token / secret / CSRF / session / password /
 *              secure-key field. Hashing adds no entropy, so the secret is guessable, enabling e.g. a
 *              predictable password-reset token and account takeover. Use random_bytes() /
 *              random_int() instead.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision high
 * @id php/weak-security-randomness
 * @tags security
 *       external/cwe/cwe-338
 *       external/cwe/cwe-330
 */

import codeql.php.AST
import codeql.php.DataFlow
import codeql.php.TaintTracking
import codeql.php.Concepts

/** A call to a non-cryptographic PRNG whose output is predictable. */
class WeakRandomCall extends FunctionCall {
  WeakRandomCall() { this.getName() = ["rand", "mt_rand", "lcg_value"] }
}

/** Holds if `name` denotes a security-sensitive secret/token (strong indicators only). */
bindingset[name]
predicate isSecretName(string name) {
  name.regexpMatch("(?i).*(token|secret|csrf|nonce|api_?key|passwd|password|secure_?key|session_?id).*")
}

/** Holds if expression `e` (typically a hash call) is used as a security secret. */
predicate inSecurityContext(Expr e) {
  // assigned to a secret/token variable or property: `$this->secure_key = <e>`
  exists(AssignExpr a | a.getRhs() = e |
    isSecretName(a.getLhs().(VariableAccess).getName()) or
    isSecretName(a.getLhs().(FieldAccess).getFieldName())
  )
  or
  // used as a cookie value: `setcookie($name, <e>, …)`
  exists(FunctionCall c | c.getName() = "setcookie" and c.getArgument(1) = e)
}

/**
 * The sink is the value flowing INTO a hash whose result is a security secret — i.e. the hash's
 * argument. Sinking here (not on the hash result) is deliberate: `md5`/`sha1`/… are global taint
 * sanitizers (correct for injection queries), so taint does not survive the hash; the predictable
 * *input* is what makes the derived secret guessable.
 */
class WeakSecretSink extends DataFlow::Node {
  WeakSecretSink() {
    exists(FunctionCall h |
      h.getName() = ["md5", "sha1", "hash", "hash_hmac", "crypt"] and
      this.asExpr() = h.getAnArgument() and
      inSecurityContext(h)
    )
  }
}

module Cfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n.asExpr() instanceof WeakRandomCall }

  predicate isSink(DataFlow::Node n) { n instanceof WeakSecretSink }

  /**
   * `uniqid($prefix)` only prepends a microtime suffix to `$prefix`, so a weak `$prefix` stays
   * predictable — pass taint through it. Also step through the `(string)` cast in the common
   * `uniqid((string) mt_rand(...))` idiom. (No step through md5/sha1/… — we sink before them.)
   */
  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(FunctionCall u | u.getName() = "uniqid" and pred.asExpr() = u.getAnArgument() and succ.asExpr() = u)
    or
    exists(CastExpr c | pred.asExpr() = c.getOperand() and succ.asExpr() = c)
  }
}

module Flow = TaintTracking::Global<Cfg>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This security secret is derived from a predictable PRNG value ($@), making it guessable.",
  source.getNode(), "weak randomness"
