/**
 * VERDICT SEPARATION (constraint A).
 *
 * The cryptographic result and the security verdict are two different things and are
 * rendered by two different indicators. The verifier returns a raw boolean: did the
 * equation balance? That is `equationHolds`. The security verdict asks a different
 * question: is the *system* behaving as it should? Colour tracks system integrity, never
 * the raw return value.
 *
 *   honest proof,  equation holds   -> SOUND   (integrity intact)         — safe
 *   forgery,       equation FAILS   -> HELD    (verifier rejected it)     — safe
 *   forgery,       equation HOLDS   -> ALARM   (a forgery was accepted)   — danger
 *
 * The signature-valid-but-verdict-reject pairing is the whole lab: "equation holds ✓" next
 * to "ALARM ✗". A forged-but-accepted proof is never green.
 */
import type { Verdict } from './types'

export type Intent = 'honest' | 'forgery'

export function judge(intent: Intent, equationHolds: boolean): Verdict {
  if (intent === 'honest') {
    return equationHolds
      ? { equationHolds, integrity: 'sound', label: 'Sound — a legitimate proof, accepted as it should be.' }
      : { equationHolds, integrity: 'alarm', label: 'Broken — a legitimate proof was rejected.' }
  }
  // intent === 'forgery'
  return equationHolds
    ? { equationHolds, integrity: 'alarm', label: 'Forged — the verifier accepted a proof for a key nobody holds.' }
    : { equationHolds, integrity: 'held', label: 'Held — the verifier rejected the forgery. The transcript binding did its job.' }
}
