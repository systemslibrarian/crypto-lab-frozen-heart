/**
 * The Schnorr verifier — hand-rolled, and deliberately honest to a fault.
 *
 * It does exactly one cryptographic thing: recompute the challenge from the transcript
 * (using the SAME field policy the prover used) and check the verification equation
 *
 *     [s]G  ==  R + [c]pk .
 *
 * It does NOT know or care whether the proof came from an honest prover or a forger. That
 * is the whole lesson: the verifier's algebra is correct in every case. Soundness lives in
 * *what the challenge covers*, not in the checking equation. So this file never renders a
 * "secure/insecure" judgement — it returns the raw boolean. The security verdict is
 * computed separately (see `verdict.ts`) precisely so the two are never collapsed.
 */
import { mulG, mul, add, eq, L, type Scalar } from './group'
import { challenge } from './fiatshamir'
import type { Proof, Statement, TranscriptFields } from './types'

export interface VerifyResult {
  /** The raw return value: did the verification equation balance? */
  equationHolds: boolean
  /** The challenge the verifier recomputed from the transcript (for display / inspection). */
  c: Scalar
  /** Reason a proof was rejected on structural grounds, if any (fail-closed, before algebra). */
  rejectedReason?: string
}

/** True iff s is a canonically-reduced scalar in [0, L). Fail-closed on out-of-range responses. */
function scalarInRange(s: Scalar): boolean {
  return s >= 0n && s < L
}

/**
 * Verify a proof of knowledge of the discrete log of `statement.pk`, under `fields`.
 * Fail-closed: a structurally malformed proof is rejected before any algebra.
 */
export function verify(
  statement: Statement,
  proof: Proof,
  message: Uint8Array,
  fields: TranscriptFields,
): VerifyResult {
  if (!scalarInRange(proof.s)) {
    return { equationHolds: false, c: 0n, rejectedReason: 'response s is out of range [0, L)' }
  }
  const c = challenge(statement.pk, proof.R, message, fields)
  // [s]G  ==  R + [c]pk
  const lhs = mulG(proof.s)
  const rhs = add(proof.R, mul(c, statement.pk))
  return { equationHolds: eq(lhs, rhs), c }
}
