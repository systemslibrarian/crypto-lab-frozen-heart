/**
 * The forgery — hand-rolled, learner-driven, and run against the REAL verifier.
 *
 * None of these functions ever decide "accepted" or "rejected": they only build a
 * candidate proof using pure algebra. Whether it verifies is decided by `verify.ts`, the
 * same verifier an honest proof faces (constraint D). Crucially, no function here takes a
 * witness — the forger genuinely does not know the secret key of the target it attacks.
 *
 * THE ONE FATAL OMISSION: the commitment R.
 * In the interactive protocol the prover must send R *before* the verifier reveals c.
 * Fiat-Shamir preserves that ordering only by hashing R into c. If R is left out of the
 * hash, then c is fully determined before R exists — so the forger can pick the response s
 * first and then *solve for* the commitment:
 *
 *     want:  [s]G = R + [c]pk        (the verification equation)
 *     so:    R = [s]G - [c]pk        (c known, because R wasn't hashed)
 *
 * The resulting (R, s) satisfies the verifier's equation for ANY target pk — including a
 * key whose discrete log the forger does not know. That is a genuine algebraic forgery,
 * not a simulation.
 */
import { mulG, mul, sub, scSub, scInv, scMul, randomScalar, type Point } from './group'
import { challenge } from './fiatshamir'
import type { Proof, Statement, TranscriptFields } from './types'

export interface ForgeAttempt {
  /**
   * Whether the standard algebraic technique (pick s, solve for R) is available under this
   * transcript policy. It is available iff the commitment R is NOT hashed. This is the
   * forger's *claim*; the verifier still has the final word.
   */
  techniqueApplies: boolean
  /** The forged proof, if a technique was available. Always fed to the real verifier by the caller. */
  proof: Proof | null
  /** Plain-language note on why the technique does or does not apply. */
  note: string
}

/**
 * Forge a proof of knowledge for `targetPk` WITHOUT its witness, under `fields`.
 *
 * If R is omitted from the hash, this returns a proof that will make the real verifier's
 * equation balance for the target key. If R is included, the technique is unavailable and
 * this returns a best-effort proof that the real verifier will reject — because to satisfy
 * the equation with R hashed, the forger would need the discrete log it does not have.
 */
export function forgeAgainstTarget(
  targetPk: Point,
  message: Uint8Array,
  fields: TranscriptFields,
): ForgeAttempt {
  if (!fields.R) {
    // c does not depend on R, so it is fixed before we choose R.
    const s = randomScalar()
    const c = challenge(targetPk, /* R unused: not hashed */ mulG(0n), message, fields)
    // Solve the verification equation for the commitment: R = [s]G - [c]pk.
    const R = sub(mulG(s), mul(c, targetPk))
    return {
      techniqueApplies: true,
      proof: { R, s },
      note: 'Commitment R is not in the hash, so the challenge is fixed before R is chosen. Pick s, then solve R = [s]G − [c]pk.',
    }
  }
  // R is hashed: c depends on R, so we cannot pick s and back-solve R (the equation is
  // circular through the hash). Emit a proof that will fail, to prove the verifier rejects it.
  const s = randomScalar()
  const R = mulG(randomScalar())
  return {
    techniqueApplies: false,
    proof: { R, s },
    note: 'Commitment R is inside the hash, so the challenge changes with every R. There is no way to pick a response first and back-solve the commitment — forging this needs the secret key.',
  }
}

/**
 * DROP-MESSAGE demonstration: not a forgery, but a real weakness of a different kind.
 * When the message is not hashed, the challenge — and therefore a whole honest proof —
 * carries no binding to *what it is about*. The same (R, s) that an honest prover made for
 * `messageA` also verifies verbatim under `messageB`: a replay / missing domain separation.
 * Returns the two messages so the caller can show the real verifier accepting both.
 */
export function replayAcrossMessages(honestProof: Proof): { proof: Proof } {
  // No algebra needed — the same bytes are simply presented under a different message.
  return { proof: honestProof }
}

/**
 * DROP-STATEMENT demonstration: when pk is omitted (but R is still hashed), the standard
 * fixed-target forgery FAILS — you cannot forge against a *given* victim's key. What breaks
 * instead is *binding*: a proof is not tied to any particular public key. A forger with no
 * witness can mint a fresh (public key, proof) pair for a key it conjures on the spot, so a
 * verifying proof says nothing about a pre-existing identity.
 *
 * Pick k and s freely, set R = [k]G, compute c (which does not depend on pk), then output
 * the unique key the proof happens to satisfy: pk' = [(s − k)·c⁻¹]G.
 */
export function mintUnboundStatement(
  message: Uint8Array,
  fields: TranscriptFields,
): { pk: Point; proof: Proof } {
  const k = randomScalar()
  const R = mulG(k)
  const s = randomScalar()
  // c must not depend on pk for this to work; it may depend on R. We pass a placeholder pk;
  // if pk were actually hashed this key would not satisfy the equation and the caller's
  // real verifier would reject — which is the correct, honest outcome.
  const cFieldsNoPk: TranscriptFields = { ...fields, pk: false }
  const placeholderPk = mulG(0n)
  const c = challenge(placeholderPk, R, message, cFieldsNoPk)
  // [s]G = R + [c]pk'  ->  pk' = [(s - k) · c^{-1}]G
  const witnessOfMintedKey = scMul(scSub(s, k), scInv(c))
  const pk = mulG(witnessOfMintedKey)
  return { pk, proof: { R, s } }
}

/** A convenience: the target public key used across the demo has no witness known to the forger. */
export function targetStatement(pk: Point): Statement {
  return { pk }
}
