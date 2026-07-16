import { describe, it, expect } from 'vitest'
import { keygen, prove, commit, respond } from './prover'
import { verify } from './verify'
import { challenge } from './fiatshamir'
import { STRONG_FIELDS } from './types'
import { mulG, mul, add, eq, scAdd, L, randomScalar } from './group'

const enc = new TextEncoder()
const MSG = enc.encode('transfer 10 coins to alice')

describe('honest Schnorr proof of knowledge (strong Fiat-Shamir)', () => {
  it('an honest proof verifies (round-trip)', () => {
    const { statement, witness } = keygen()
    const proof = prove(statement, witness, MSG, STRONG_FIELDS)
    expect(verify(statement, proof, MSG, STRONG_FIELDS).equationHolds).toBe(true)
  })

  it('the verification equation is exactly [s]G = R + [c]pk', () => {
    const { statement, witness } = keygen()
    const { k, R } = commit()
    const c = challenge(statement.pk, R, MSG, STRONG_FIELDS)
    const s = respond(k, c, witness.x)
    const lhs = mulG(s)
    const rhs = add(R, mul(c, statement.pk))
    expect(eq(lhs, rhs)).toBe(true)
  })

  it('s = k + c·x holds by construction', () => {
    const { statement, witness } = keygen()
    const { k, R } = commit()
    const c = challenge(statement.pk, R, MSG, STRONG_FIELDS)
    const s = respond(k, c, witness.x)
    expect(s).toBe(scAdd(k, (c * witness.x) % L))
  })

  it('100 independent honest proofs all verify', () => {
    for (let i = 0; i < 100; i++) {
      const { statement, witness } = keygen()
      const proof = prove(statement, witness, MSG, STRONG_FIELDS)
      expect(verify(statement, proof, MSG, STRONG_FIELDS).equationHolds).toBe(true)
    }
  })
})

describe('the verifier rejects every bad proof (fail-closed)', () => {
  it('rejects a tampered response s', () => {
    const { statement, witness } = keygen()
    const proof = prove(statement, witness, MSG, STRONG_FIELDS)
    const bad = { R: proof.R, s: scAdd(proof.s, 1n) }
    expect(verify(statement, bad, MSG, STRONG_FIELDS).equationHolds).toBe(false)
  })

  it('rejects a tampered commitment R', () => {
    const { statement, witness } = keygen()
    const proof = prove(statement, witness, MSG, STRONG_FIELDS)
    const bad = { R: add(proof.R, mulG(1n)), s: proof.s }
    expect(verify(statement, bad, MSG, STRONG_FIELDS).equationHolds).toBe(false)
  })

  it('rejects a proof checked against the wrong message', () => {
    const { statement, witness } = keygen()
    const proof = prove(statement, witness, MSG, STRONG_FIELDS)
    const other = enc.encode('transfer 10 coins to mallory')
    expect(verify(statement, proof, other, STRONG_FIELDS).equationHolds).toBe(false)
  })

  it('rejects a proof checked against the wrong public key', () => {
    const { statement, witness } = keygen()
    const proof = prove(statement, witness, MSG, STRONG_FIELDS)
    const wrong = keygen().statement
    expect(verify(wrong, proof, MSG, STRONG_FIELDS).equationHolds).toBe(false)
  })

  it('rejects an out-of-range response s (>= L)', () => {
    const { statement, witness } = keygen()
    const proof = prove(statement, witness, MSG, STRONG_FIELDS)
    const bad = { R: proof.R, s: proof.s + L }
    const res = verify(statement, bad, MSG, STRONG_FIELDS)
    expect(res.equationHolds).toBe(false)
    expect(res.rejectedReason).toMatch(/out of range/)
  })

  it('a proof made with a nonce someone else picked still needs the real witness', () => {
    // Prove the witness truly matters: same nonce, wrong secret -> rejected.
    const { statement } = keygen()
    const k = randomScalar()
    const R = mulG(k)
    const c = challenge(statement.pk, R, MSG, STRONG_FIELDS)
    const wrongWitness = randomScalar()
    const s = respond(k, c, wrongWitness)
    expect(verify(statement, { R, s }, MSG, STRONG_FIELDS).equationHolds).toBe(false)
  })
})
