/**
 * The honest Schnorr prover — hand-rolled, the teaching subject.
 *
 * Proves knowledge of x such that pk = [x]G, in three moves:
 *   1. commit:   pick a random nonce k, send R = [k]G
 *   2. challenge: c = H(transcript)            (Fiat-Shamir; the verifier's coin is a hash)
 *   3. respond:   s = k + c·x  (mod L)
 *
 * The verifier later checks [s]G == R + [c]pk. It balances because
 *   [s]G = [k + c·x]G = [k]G + [c·x]G = R + [c]([x]G) = R + [c]pk.
 *
 * The honest prover ALWAYS knows the witness x and ALWAYS commits to R before computing c.
 * That ordering is what Fiat-Shamir must preserve by hashing R — see `forge.ts` for what
 * happens when it doesn't.
 */
import { mulG, scAdd, scMul, randomScalar, type Scalar } from './group'
import { challenge } from './fiatshamir'
import type { Proof, Statement, TranscriptFields, Witness } from './types'

/** Generate a fresh keypair: secret x, public pk = [x]G. */
export function keygen(): { statement: Statement; witness: Witness } {
  const x = randomScalar()
  return { statement: { pk: mulG(x) }, witness: { x } }
}

/** Step 1 — commit. Returns the nonce (kept secret) and the commitment R (public). */
export function commit(): { k: Scalar; R: ReturnType<typeof mulG> } {
  const k = randomScalar()
  return { k, R: mulG(k) }
}

/** Step 3 — respond. s = k + c·x (mod L). */
export function respond(k: Scalar, c: Scalar, x: Scalar): Scalar {
  return scAdd(k, scMul(c, x))
}

/**
 * Produce a complete non-interactive proof honestly, under a given transcript policy.
 * An optional fixed nonce makes the flow reproducible for the stepped UI and for tests.
 */
export function prove(
  statement: Statement,
  witness: Witness,
  message: Uint8Array,
  fields: TranscriptFields,
  fixedNonce?: Scalar,
): Proof {
  const k = fixedNonce ?? randomScalar()
  const R = mulG(k)
  const c = challenge(statement.pk, R, message, fields)
  const s = respond(k, c, witness.x)
  return { R, s }
}
