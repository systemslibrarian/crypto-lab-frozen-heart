/**
 * The omission ladder.
 *
 * Start from the strong transcript H(G, pk, R, message) and drop exactly one field. Each
 * rung's verdict is computed here by running the REAL forger against the REAL verifier — no
 * outcome is hard-coded. The point the lab is built to make honestly: not every omission is
 * fatal, and knowing which is which is the expert payoff.
 *
 *   drop message  -> proof of knowledge still sound, but the proof no longer binds to a
 *                    context: an honest proof replays verbatim under another message.
 *   drop pk       -> no fixed-target forgery, but the proof binds to no particular key; a
 *                    witness-free (key, proof) pair can be minted at will.
 *   drop R        -> FATAL. Universal forgery against any target key. This is Frozen Heart.
 *   drop G        -> harmless in a single fixed group (G is a public constant); would only
 *                    matter under attacker-chosen group parameters, which is out of scope.
 */
import { STRONG_FIELDS, type TranscriptFields, type Statement } from './types'
import { verify } from './verify'
import { forgeAgainstTarget, replayAcrossMessages, mintUnboundStatement } from './forge'
import { prove, keygen } from './prover'

export type RungKey = 'strong' | 'dropMessage' | 'dropPk' | 'dropR' | 'dropG'
export type Severity = 'sound' | 'context-loss' | 'unbound' | 'fatal'

export interface Rung {
  key: RungKey
  /** Which field (if any) this rung drops from the strong transcript. */
  fields: TranscriptFields
  /** Short label for the field dropped. */
  dropped: string
  /** The FS formula shown to the reader. */
  formula: string
  /** MEASURED: did a witness-free forgery against a fixed target key verify? */
  fixedTargetForged: boolean
  /** MEASURED: did one honest proof verify verbatim under a second, different message? */
  replayVerifies: boolean
  /** MEASURED: did a witness-free (key, proof) pair minted on the spot verify? */
  unboundMintVerifies: boolean
  /** DERIVED FROM THE THREE MEASUREMENTS ABOVE — never switched on `key`. */
  severity: Severity
  /** One-line consequence, selected by the measured outcome. */
  consequence: string
  /**
   * Standing commentary about this particular omission. Explanatory only: it is keyed to
   * the rung and is NOT a verdict. The verdict is `severity` + `consequence`.
   */
  commentary: string
}

const without = (f: Partial<TranscriptFields>): TranscriptFields => ({ ...STRONG_FIELDS, ...f })

/** Append a one-byte discriminator so the two replay messages differ in their bytes. */
function tagged(base: Uint8Array, tag: number): Uint8Array {
  const out = new Uint8Array(base.length + 1)
  out.set(base, 0)
  out[base.length] = tag
  return out
}

/**
 * Evaluate one rung against a target public key whose witness the forger does not know.
 * `message` is the context string the honest system would use.
 *
 * Every part of the verdict is MEASURED by running the real forger and the real verifier
 * under this rung's transcript policy. Nothing is switched on the rung name: if the group
 * law, the challenge construction, or the forgery algebra were wrong, the severity chip
 * would change rather than keep reading the answer we expected.
 */
export function evaluateRung(key: RungKey, target: Statement, message: Uint8Array): Rung {
  const spec: Record<
    RungKey,
    { fields: TranscriptFields; dropped: string; formula: string; commentary: string }
  > = {
    strong: {
      fields: without({}),
      dropped: 'nothing',
      formula: 'c = H(G, pk, R, m)',
      commentary: 'Every public value is bound; this is the transform as specified.',
    },
    dropMessage: {
      fields: without({ message: false }),
      dropped: 'message m',
      formula: 'c = H(G, pk, R)',
      commentary:
        'The proof of knowledge itself is untouched; what is lost is any binding to what the proof is about.',
    },
    dropPk: {
      fields: without({ pk: false }),
      dropped: 'public key pk',
      formula: 'c = H(G, R, m)',
      commentary:
        'This is the rung the textbook phrase "weak Fiat-Shamir = c = H(R)" actually describes: adaptive soundness (Bernhard-Pereira-Warinschi, 2012), not universal forgery.',
    },
    dropR: {
      fields: without({ R: false }),
      dropped: 'commitment R',
      formula: 'c = H(G, pk, m)',
      commentary:
        'The challenge is fixed before R exists, so the prover rather than the hash chooses it. This is the Frozen Heart pattern.',
    },
    dropG: {
      fields: without({ g: false }),
      dropped: 'generator G',
      formula: 'c = H(pk, R, m)',
      commentary:
        'G is a public constant of one fixed group, so omitting it changes the hash but binds nothing less. It would only matter under attacker-chosen group parameters, which this lab does not model.',
    },
  }
  const { fields, dropped, formula, commentary } = spec[key]

  // MEASUREMENT 1 — fixed-target forgery: real forger, real verifier, no witness.
  const attempt = forgeAgainstTarget(target.pk, message, fields)
  const fixedTargetForged = attempt.proof
    ? verify(target, attempt.proof, message, fields).equationHolds
    : false

  // MEASUREMENT 2 — replay: make ONE honest proof about messageA with a key we do own, then
  // hand those exact bytes to the verifier under messageB.
  const replayKey = keygen()
  const messageA = tagged(message, 0x41)
  const messageB = tagged(message, 0x42)
  const honest = prove(replayKey.statement, replayKey.witness, messageA, fields)
  const honestVerifies = verify(replayKey.statement, honest, messageA, fields).equationHolds
  const replayVerifies =
    honestVerifies && verify(replayKey.statement, honest, messageB, fields).equationHolds

  // MEASUREMENT 3 — unbound minting: conjure a (key, proof) pair with no witness and ask
  // the real verifier whether it accepts the pair.
  const minted = mintUnboundStatement(message, fields)
  const unboundMintVerifies = verify({ pk: minted.pk }, minted.proof, message, fields).equationHolds

  // The verdict is a function of the three measurements, in decreasing order of damage.
  let severity: Severity
  let consequence: string
  if (fixedTargetForged) {
    severity = 'fatal'
    consequence =
      'Universal forgery: a proof just verified for a key whose secret nobody holds. Measured against the real verifier.'
  } else if (unboundMintVerifies) {
    severity = 'unbound'
    consequence =
      'No fixed-target forgery — the victim key held. But a witness-free (key, proof) pair minted on the spot verified, so a passing proof says nothing about a pre-existing identity.'
  } else if (replayVerifies) {
    severity = 'context-loss'
    consequence =
      'No forgery of any kind: the proof of knowledge is still sound. But one honest proof just verified verbatim under a second, different message — it binds to no context.'
  } else {
    severity = 'sound'
    consequence =
      'The forgery attempt was rejected, no unbound pair verified, and an honest proof did not replay under a different message.'
  }

  return {
    key,
    fields,
    dropped,
    formula,
    fixedTargetForged,
    replayVerifies,
    unboundMintVerifies,
    severity,
    consequence,
    commentary,
  }
}

export const RUNG_ORDER: RungKey[] = ['strong', 'dropG', 'dropMessage', 'dropPk', 'dropR']

/** Build the full ladder against a fresh unknown-witness target. */
export function buildLadder(target: Statement, message: Uint8Array): Rung[] {
  return RUNG_ORDER.map((k) => evaluateRung(k, target, message))
}

/** Re-export the special demonstrations so the UI can drive them directly. */
export { replayAcrossMessages, mintUnboundStatement, prove, keygen }
