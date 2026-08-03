/**
 * @name Weak randomness used to derive a security secret or token
 * @description A value from a predictable PRNG (rand / mt_rand / uniqid / lcg_value) is used as the
 *              material for a security hash (md5 / sha1 / hash / hash_hmac / crypt). The resulting
 *              secret is guessable — e.g. a predictable password-reset or CSRF token, which enables
 *              account takeover. Use random_bytes() / random_int() instead.
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
  WeakRandomCall() { this.getName() = ["rand", "mt_rand", "uniqid", "lcg_value"] }
}

/** An argument of a hashing call — the material a secret/token is derived from. */
class SecurityHashArg extends DataFlow::Node {
  SecurityHashArg() {
    exists(FunctionCall fc |
      fc.getName() = ["md5", "sha1", "hash", "hash_hmac", "crypt"] and
      this.asExpr() = fc.getAnArgument()
    )
  }
}

module Cfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n.asExpr() instanceof WeakRandomCall }

  predicate isSink(DataFlow::Node n) { n instanceof SecurityHashArg }
}

module Flow = TaintTracking::Global<Cfg>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This security hash is derived from a predictable PRNG value ($@), yielding a guessable secret/token.",
  source.getNode(), "weak randomness"
