/**
 * @name Weak randomness used to derive a security secret or token
 * @description A value from a predictable PRNG (rand / mt_rand / uniqid / lcg_value) reaches a
 *              security-sensitive context (a cookie value, or a token / secret / CSRF / session /
 *              password / reset-key field) — optionally after hashing, which does not add entropy.
 *              The resulting secret is guessable, enabling e.g. a predictable password-reset token
 *              and account takeover. Use random_bytes() / random_int() instead.
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

/**
 * A call to a non-cryptographic PRNG whose output is predictable. `uniqid` is deliberately excluded:
 * it folds in the current time and (with `$more_entropy`) the pid, so `md5(uniqid())` — the ubiquitous
 * PHP filename/cache-key idiom — is not the target and would swamp the query with noise.
 */
class WeakRandomCall extends FunctionCall {
  WeakRandomCall() { this.getName() = ["rand", "mt_rand", "lcg_value"] }
}

/**
 * Holds if `name` denotes a security-sensitive secret/token. Kept to *strong* indicators only —
 * broad words like `reset`, `salt`, `_key`, `activation` matched too many ordinary fields.
 */
bindingset[name]
predicate isSecretName(string name) {
  name.regexpMatch("(?i).*(token|secret|csrf|nonce|api_?key|passwd|password|secure_?key|session_?id).*")
}

/**
 * A security-sensitive sink: the value of a cookie, or the value assigned to a variable/property
 * whose name denotes a secret/token. (Non-secret uses of `md5(uniqid(mt_rand()))` — filenames,
 * cache keys, checksums — do NOT reach one of these, which is what keeps the query precise.)
 */
class SecuritySink extends DataFlow::Node {
  SecuritySink() {
    exists(FunctionCall c | c.getName() = "setcookie" and this.asExpr() = c.getArgument(1))
    or
    exists(AssignExpr a | this.asExpr() = a.getRhs() |
      isSecretName(a.getLhs().(VariableAccess).getName()) or
      isSecretName(a.getLhs().(FieldAccess).getFieldName())
    )
  }
}

module Cfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n.asExpr() instanceof WeakRandomCall }

  predicate isSink(DataFlow::Node n) { n instanceof SecuritySink }

  /** Hashing does not remove predictability — let taint pass through md5/sha1/hash/crypt. */
  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(FunctionCall h |
      h.getName() = ["md5", "sha1", "hash", "hash_hmac", "crypt"] and
      pred.asExpr() = h.getAnArgument() and
      succ.asExpr() = h
    )
  }
}

module Flow = TaintTracking::Global<Cfg>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This secret/token is derived from a predictable PRNG value ($@), making it guessable.",
  source.getNode(), "weak randomness"
