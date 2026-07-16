/**
 * The group layer: ristretto255, a prime-order group built over Curve25519.
 *
 * WHY A LIBRARY HERE, HAND-ROLLED ABOVE:
 * Elliptic-curve point arithmetic is the *primitive underneath* this lab, not its
 * subject. We use @noble/curves — a widely-audited implementation — for the field and
 * point operations, exactly as §0.1 of the Crypto Lab standard allows ("a named,
 * justified library for the actual operations"). Everything that teaches — the Schnorr
 * sigma protocol, the Fiat-Shamir challenge, the prover, the verifier, and the forgery —
 * is hand-rolled in the sibling files so the internals are inspectable.
 *
 * ristretto255 (RFC 9496) is chosen over a raw curve because it is a *prime-order* group:
 * every non-identity element is a generator, there is no cofactor, and scalar arithmetic
 * is clean modulo the single group order L. That removes cofactor subtleties that would
 * distract from the one idea the lab exists to teach.
 */
import { RistrettoPoint, ed25519 } from '@noble/curves/ed25519'
import { sha512 } from '@noble/hashes/sha512'
import { bytesToNumberLE, numberToBytesLE, bytesToHex, hexToBytes, concatBytes } from '@noble/curves/abstract/utils'
import { mod, invert } from '@noble/curves/abstract/modular'

/** A point in the group. Immutable wrapper type alias over the library point. */
export type Point = InstanceType<typeof RistrettoPoint>
/** A scalar in Z_L, the field of exponents. Always reduced mod L. */
export type Scalar = bigint

/** The prime order L of ristretto255 = 2^252 + 27742317777372353535851937790883648493. */
export const L: bigint = ed25519.CURVE.n

/** The standard generator B (base point) of the group. */
export const G: Point = RistrettoPoint.BASE

/** The identity element. */
export const IDENTITY: Point = RistrettoPoint.ZERO

/** Reduce any integer into the scalar field Z_L (handles negatives). */
export function sc(x: bigint): Scalar {
  return mod(x, L)
}

/** Scalar addition mod L. */
export function scAdd(a: Scalar, b: Scalar): Scalar {
  return mod(a + b, L)
}

/** Scalar multiplication mod L. */
export function scMul(a: Scalar, b: Scalar): Scalar {
  return mod(a * b, L)
}

/** Scalar subtraction mod L. */
export function scSub(a: Scalar, b: Scalar): Scalar {
  return mod(a - b, L)
}

/** Modular inverse of a scalar mod L. Throws on 0 (no inverse exists). */
export function scInv(a: Scalar): Scalar {
  return invert(mod(a, L), L)
}

/** Point addition. */
export function add(p: Point, q: Point): Point {
  return p.add(q)
}

/** Point subtraction. */
export function sub(p: Point, q: Point): Point {
  return p.subtract(q)
}

/** Scalar-by-point multiplication [k]P. Reduces k first; [0]P is the identity. */
export function mul(k: Scalar, p: Point): Point {
  const r = mod(k, L)
  if (r === 0n) return IDENTITY
  return p.multiply(r)
}

/** [k]G — a fresh public element from a scalar. */
export function mulG(k: Scalar): Point {
  return mul(k, G)
}

export function eq(p: Point, q: Point): boolean {
  return p.equals(q)
}

/** Canonical 32-byte encoding of a point (RFC 9496). */
export function encodePoint(p: Point): Uint8Array {
  return p.toRawBytes()
}

/** Decode a canonical 32-byte ristretto encoding. Throws on a non-canonical / invalid encoding. */
export function decodePoint(bytes: Uint8Array): Point {
  return RistrettoPoint.fromHex(bytes)
}

/** 32-byte little-endian encoding of a scalar (already reduced). */
export function encodeScalar(s: Scalar): Uint8Array {
  return numberToBytesLE(mod(s, L), 32)
}

export function scalarFromBytesLE(bytes: Uint8Array): Scalar {
  return mod(bytesToNumberLE(bytes), L)
}

/**
 * Hash an arbitrary byte string to a scalar in Z_L.
 * SHA-512 gives 64 bytes of output; reducing a 512-bit integer mod the ~253-bit L keeps
 * the bias negligible (< 2^-259). This is the "H(...)" that Fiat-Shamir substitutes for
 * the verifier's coin flips.
 */
export function hashToScalar(bytes: Uint8Array): Scalar {
  return mod(bytesToNumberLE(sha512(bytes)), L)
}

/** Deterministic-length concatenation helper for building transcripts. */
export function concat(...parts: Uint8Array[]): Uint8Array {
  return concatBytes(...parts)
}

/** A cryptographically-random scalar in [1, L). Used for honest nonces and secret keys. */
export function randomScalar(): Scalar {
  // Rejection-free: draw 512 bits and reduce; bias is negligible as above.
  const buf = new Uint8Array(64)
  crypto.getRandomValues(buf)
  let s = mod(bytesToNumberLE(buf), L)
  if (s === 0n) s = 1n
  return s
}

export { bytesToHex, hexToBytes }
