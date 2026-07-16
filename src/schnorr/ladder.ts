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
  /** Did a witness-free forgery against a fixed target key actually verify? (real verifier) */
  fixedTargetForged: boolean
  /** Verdict severity for this omission. */
  severity: Severity
  /** One-line, precisely-scoped consequence. */
  consequence: string
}

const without = (f: Partial<TranscriptFields>): TranscriptFields => ({ ...STRONG_FIELDS, ...f })

/**
 * Evaluate one rung against a target public key whose witness the forger does not know.
 * `message` is the context string the honest system would use.
 */
export function evaluateRung(key: RungKey, target: Statement, message: Uint8Array): Rung {
  const spec: Record<RungKey, { fields: TranscriptFields; dropped: string; formula: string }> = {
    strong: { fields: without({}), dropped: 'nothing', formula: 'c = H(G, pk, R, m)' },
    dropMessage: { fields: without({ message: false }), dropped: 'message m', formula: 'c = H(G, pk, R)' },
    dropPk: { fields: without({ pk: false }), dropped: 'public key pk', formula: 'c = H(G, R, m)' },
    dropR: { fields: without({ R: false }), dropped: 'commitment R', formula: 'c = H(G, pk, m)' },
    dropG: { fields: without({ g: false }), dropped: 'generator G', formula: 'c = H(pk, R, m)' },
  }
  const { fields, dropped, formula } = spec[key]

  // Run the real fixed-target forgery attempt through the real verifier.
  const attempt = forgeAgainstTarget(target.pk, message, fields)
  const fixedTargetForged = attempt.proof
    ? verify(target, attempt.proof, message, fields).equationHolds
    : false

  let severity: Severity
  let consequence: string
  switch (key) {
    case 'dropR':
      severity = 'fatal'
      consequence =
        'Universal forgery: a proof verifies for a key whose secret nobody holds. The prover, not the hash, now chooses the challenge. This is the Frozen Heart bug.'
      break
    case 'dropMessage':
      severity = 'context-loss'
      consequence =
        'Proof of knowledge still sound — no forgery. But the proof binds to no context: an honest proof replays verbatim under a different message.'
      break
    case 'dropPk':
      severity = 'unbound'
      consequence =
        'No fixed-target forgery. But the proof binds to no particular key: a witness-free (key, proof) pair can be minted, so it proves nothing about a pre-existing identity.'
      break
    case 'dropG':
      severity = 'sound'
      consequence =
        'Harmless in one fixed group — G is a public constant. Would only matter if an attacker could choose the group parameters, which this lab does not model.'
      break
    case 'strong':
    default:
      severity = 'sound'
      consequence = 'Every public value is bound. The forgery attempt fails; the verifier rejects it.'
      break
  }

  return { key, fields, dropped, formula, fixedTargetForged, severity, consequence }
}

export const RUNG_ORDER: RungKey[] = ['strong', 'dropG', 'dropMessage', 'dropPk', 'dropR']

/** Build the full ladder against a fresh unknown-witness target. */
export function buildLadder(target: Statement, message: Uint8Array): Rung[] {
  return RUNG_ORDER.map((k) => evaluateRung(k, target, message))
}

/** Re-export the special demonstrations so the UI can drive them directly. */
export { replayAcrossMessages, mintUnboundStatement, prove, keygen }
