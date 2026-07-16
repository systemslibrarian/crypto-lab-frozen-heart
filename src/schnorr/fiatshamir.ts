/**
 * The Fiat-Shamir challenge.
 *
 * In the INTERACTIVE protocol the verifier picks the challenge c at random *after* seeing
 * the commitment R. Fiat-Shamir removes the verifier: it sets c = H(transcript). The
 * transform is sound only if that hash covers the whole transcript — crucially the
 * commitment R, so the prover cannot choose R *after* the challenge is fixed.
 *
 * This function is the one place where "what counts as the transcript" is decided. The
 * `fields` flags select which values feed the hash. Prover, verifier, and forger all call
 * THIS function, so whatever the implementer decided the transcript is, everyone agrees on
 * it — which is exactly how the Frozen Heart bugs slipped through review: the spec said
 * "hash the transcript" and each implementer decided for themselves what that meant.
 */
import { encodePoint, hashToScalar, concat, G, type Point, type Scalar } from './group'
import type { TranscriptFields } from './types'

const enc = new TextEncoder()

/** Fixed domain-separation tag so this challenge can't collide with another protocol's. */
const DOMAIN = enc.encode('crypto-lab-frozen-heart/schnorr-ristretto255/v1')

/** A length-prefixed field so concatenation is unambiguous (no field-boundary confusion). */
function field(tag: number, body: Uint8Array): Uint8Array {
  const header = new Uint8Array(5)
  header[0] = tag
  new DataView(header.buffer).setUint32(1, body.length, false)
  return concat(header, body)
}

/**
 * Compute the Fiat-Shamir challenge c for a proof, hashing exactly the fields marked true.
 *
 * @param pk       the statement (public key)
 * @param R        the commitment
 * @param message  the context/message bytes
 * @param fields   which of {g, pk, R, message} are folded into the hash
 */
export function challenge(pk: Point, R: Point, message: Uint8Array, fields: TranscriptFields): Scalar {
  const parts: Uint8Array[] = [field(0, DOMAIN)]
  if (fields.g) parts.push(field(1, encodePoint(G)))
  if (fields.pk) parts.push(field(2, encodePoint(pk)))
  if (fields.R) parts.push(field(3, encodePoint(R)))
  if (fields.message) parts.push(field(4, message))
  return hashToScalar(concat(...parts))
}

/**
 * Compute the challenge WITHOUT the commitment R — the value a forger needs when R has
 * been omitted, because then c is fully determined before R exists. Behaves identically to
 * `challenge` whenever `fields.R` is already false; provided so the forgery code can make
 * the "c is fixed before R" step explicit and inspectable.
 */
export function challengeWithoutR(pk: Point, message: Uint8Array, fields: TranscriptFields): Scalar {
  return challenge(pk, G /* ignored: R not hashed */, message, { ...fields, R: false })
}
