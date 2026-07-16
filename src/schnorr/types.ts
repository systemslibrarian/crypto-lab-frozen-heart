import type { Point, Scalar } from './group'

/**
 * The statement being proved: "I know x such that pk = [x]G."
 * pk is public; x (the witness) is known only to an honest prover.
 */
export interface Statement {
  /** The public key pk = [x]G. */
  pk: Point
}

/** A witness for a statement: the secret scalar x with [x]G = pk. */
export interface Witness {
  x: Scalar
}

/**
 * A Schnorr proof of knowledge of a discrete log.
 * R is the prover's commitment; s is the response. The challenge c is NOT transmitted —
 * the verifier recomputes it from the transcript, which is the entire point of the lab.
 */
export interface Proof {
  R: Point
  s: Scalar
}

/**
 * Which fields the Fiat-Shamir hash covers when it manufactures the challenge.
 * The *strong* transform covers all four. Each `false` is an omission — the knob the lab
 * exists to poke. Whether an omission is fatal, merely context-losing, or harmless is the
 * expert payoff, and every verdict here is decided by running the real verifier, never asserted.
 */
export interface TranscriptFields {
  /** The generator G (a fixed public parameter of the group). */
  g: boolean
  /** The public key pk — the *statement* being proved. */
  pk: boolean
  /** The commitment R — the value the prover must commit to *before* the challenge. */
  R: boolean
  /** The message / context string m — domain separation and what the proof is "about". */
  message: boolean
}

export const STRONG_FIELDS: TranscriptFields = { g: true, pk: true, R: true, message: true }

/** The independently-rendered halves of a verdict (constraint A: never collapse these). */
export interface Verdict {
  /** The raw cryptographic return: did the verification equation s·G = R + c·pk hold? */
  equationHolds: boolean
  /** The security interpretation, which tracks system integrity, not the raw return value. */
  integrity: 'sound' | 'held' | 'alarm'
  /** Human-readable one-liner for the integrity state. */
  label: string
}

export type { Point, Scalar }
