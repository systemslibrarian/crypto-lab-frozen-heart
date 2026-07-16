import { describe, it, expect } from 'vitest'
import { sha512 } from '@noble/hashes/sha512'
import { G, IDENTITY, mul, decodePoint, encodePoint, bytesToHex, hexToBytes, L, sc } from './group'

/**
 * KATs — proving the group layer is the real ristretto255, not a stand-in.
 *
 * These are the canonical encodings of the small multiples [k]B of the generator from
 * RFC 9496, Appendix A.1 ("Multiples of the generator"). Matching them end-to-end means
 * our point arithmetic and canonical encoding agree with the spec bit-for-bit.
 */
const RFC9496_MULTIPLES: string[] = [
  '0000000000000000000000000000000000000000000000000000000000000000', // [0]B (identity)
  'e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76', // [1]B
  '6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919', // [2]B
  '94741f5d5d52755ece4f23f044ee27d5d1ea1e2bd196b462166b16152a9d0259', // [3]B
  'da80862773358b466ffadfe0b3293ab3d9fd53c5ea6c955358f568322daf6a57', // [4]B
  'e882b131016b52c1d3337080187cf768423efccbb517bb495ab812c4160ff44e', // [5]B
  'f64746d3c92b13050ed8d80236a7f0007c3b3f962f5ba793d19a601ebb1df403', // [6]B
  '44f53520926ec81fbd5a387845beb7df85a96a24ece18738bdcfa6a7822a176d', // [7]B
  '903293d8f2287ebe10e2374dc1a53e0bc887e592699f02d077d5263cdd55601c', // [8]B
  '02622ace8f7303a31cafc63f8fc48fdc16e1c8c8d234b2f0d6685282a9076031', // [9]B
  '20706fd788b2720a1ed2a5dad4952b01f413bcf0e7564de8cdc816689e2db95f', // [10]B
  'bce83f8ba5dd2fa572864c24ba1810f9522bc6004afe95877ac73241cafdab42', // [11]B
  'e4549ee16b9aa03099ca208c67adafcafa4c3f3e4e5303de6026e3ca8ff84460', // [12]B
  'aa52e000df2e16f55fb1032fc33bc42742dad6bd5a8fc0be0167436c5948501f', // [13]B
  '46376b80f409b29dc2b5f6f0c52591990896e5716f41477cd30085ab7f10301e', // [14]B
  'e0c418f7c8d9c4cdd7395b93ea124f3ad99021bb681dfc3302a9d99a2e53e64e', // [15]B
]

describe('ristretto255 group — RFC 9496 known-answer tests', () => {
  RFC9496_MULTIPLES.forEach((expected, k) => {
    it(`encodes [${k}]B to the RFC 9496 vector`, () => {
      const point = k === 0 ? IDENTITY : mul(sc(BigInt(k)), G)
      expect(bytesToHex(encodePoint(point))).toBe(expected)
    })
  })

  it('round-trips every RFC 9496 encoding through decode/encode', () => {
    for (const hex of RFC9496_MULTIPLES.slice(1)) {
      const p = decodePoint(hexToBytes(hex))
      expect(bytesToHex(encodePoint(p))).toBe(hex)
    }
  })

  it('rejects a non-canonical / invalid encoding (fail-closed)', () => {
    expect(() => decodePoint(hexToBytes('ff'.repeat(32)))).toThrow()
  })

  it('the order L is the ristretto255 prime order', () => {
    expect(L).toBe(2n ** 252n + 27742317777372353535851937790883648493n)
  })
})

describe('SHA-512 — NIST known-answer tests', () => {
  const enc = new TextEncoder()
  it('SHA-512("") matches the NIST vector', () => {
    expect(bytesToHex(sha512(new Uint8Array(0)))).toBe(
      'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce' +
        '47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e',
    )
  })
  it('SHA-512("abc") matches the NIST vector', () => {
    expect(bytesToHex(sha512(enc.encode('abc')))).toBe(
      'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a' +
        '2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f',
    )
  })
})
