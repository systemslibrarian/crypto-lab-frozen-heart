import { describe, it, expect } from 'vitest'
import { keygen, prove } from './prover'
import { verify } from './verify'
import { forgeAgainstTarget, mintUnboundStatement, replayAcrossMessages } from './forge'
import { buildLadder, evaluateRung } from './ladder'
import { STRONG_FIELDS, type TranscriptFields } from './types'

const enc = new TextEncoder()
const MSG = enc.encode('I am the holder of key pk')

const drop = (f: Partial<TranscriptFields>): TranscriptFields => ({ ...STRONG_FIELDS, ...f })

describe('the fatal omission: drop the commitment R', () => {
  it('forges a proof for a target key whose witness the forger does NOT know — real verifier ACCEPTS', () => {
    // A victim key: we generate it, but the forger only ever receives the public part.
    const victim = keygen().statement
    const weak = drop({ R: false })

    const attempt = forgeAgainstTarget(victim.pk, MSG, weak)
    expect(attempt.techniqueApplies).toBe(true)
    expect(attempt.proof).not.toBeNull()

    // The REAL verifier, unmodified, accepts the forgery. This is the ALARM condition.
    const result = verify(victim, attempt.proof!, MSG, weak)
    expect(result.equationHolds).toBe(true)
  })

  it('the forgery is genuinely witness-free: it works for a random target every time', () => {
    const weak = drop({ R: false })
    for (let i = 0; i < 50; i++) {
      const victim = keygen().statement // fresh unknown witness each time
      const attempt = forgeAgainstTarget(victim.pk, MSG, weak)
      expect(verify(victim, attempt.proof!, MSG, weak).equationHolds).toBe(true)
    }
  })
})

describe('strong Fiat-Shamir resists the same attack', () => {
  it('the forgery technique is unavailable and the real verifier REJECTS', () => {
    const victim = keygen().statement
    const attempt = forgeAgainstTarget(victim.pk, MSG, STRONG_FIELDS)
    expect(attempt.techniqueApplies).toBe(false)
    const result = verify(victim, attempt.proof!, MSG, STRONG_FIELDS)
    expect(result.equationHolds).toBe(false)
  })

  it('50 forgery attempts against strong FS are all rejected', () => {
    for (let i = 0; i < 50; i++) {
      const victim = keygen().statement
      const attempt = forgeAgainstTarget(victim.pk, MSG, STRONG_FIELDS)
      expect(verify(victim, attempt.proof!, MSG, STRONG_FIELDS).equationHolds).toBe(false)
    }
  })
})

describe('the omission ladder — every verdict is the real verifier speaking', () => {
  const victim = keygen().statement
  const ladder = buildLadder(victim, MSG)

  it('exactly one rung — drop R — yields a verifying fixed-target forgery', () => {
    const forgeable = ladder.filter((r) => r.fixedTargetForged).map((r) => r.key)
    expect(forgeable).toEqual(['dropR'])
  })

  it('strong binds everything: no forgery', () => {
    expect(evaluateRung('strong', victim, MSG).fixedTargetForged).toBe(false)
  })

  it('drop G is harmless (fixed group): no forgery', () => {
    expect(evaluateRung('dropG', victim, MSG).fixedTargetForged).toBe(false)
  })

  it('drop message does not enable a forgery', () => {
    expect(evaluateRung('dropMessage', victim, MSG).fixedTargetForged).toBe(false)
  })

  it('drop pk does not enable a fixed-target forgery', () => {
    expect(evaluateRung('dropPk', victim, MSG).fixedTargetForged).toBe(false)
  })

  it('drop R is marked fatal, everything else is not', () => {
    for (const rung of ladder) {
      if (rung.key === 'dropR') expect(rung.severity).toBe('fatal')
      else expect(rung.severity).not.toBe('fatal')
    }
  })
})

describe('drop the message: replay, not forgery', () => {
  it('an honest proof made under one message verifies verbatim under another', () => {
    const { statement, witness } = keygen()
    const noMsg = drop({ message: false })
    const m1 = enc.encode('pay alice 5')
    const m2 = enc.encode('pay mallory 5000')

    const honest = prove(statement, witness, m1, noMsg)
    // Sanity: it verifies under its own message.
    expect(verify(statement, honest, m1, noMsg).equationHolds).toBe(true)

    // Replay: the SAME proof verifies under a different message, because m is not bound.
    const { proof } = replayAcrossMessages(honest)
    expect(verify(statement, proof, m2, noMsg).equationHolds).toBe(true)
  })

  it('under strong FS the same replay FAILS (message is bound)', () => {
    const { statement, witness } = keygen()
    const m1 = enc.encode('pay alice 5')
    const m2 = enc.encode('pay mallory 5000')
    const honest = prove(statement, witness, m1, STRONG_FIELDS)
    expect(verify(statement, honest, m2, STRONG_FIELDS).equationHolds).toBe(false)
  })
})

describe('drop the public key: unbound statement, not a fixed-target forgery', () => {
  const noPk = drop({ pk: false })

  it('a witness-free (key, proof) pair can be minted and the real verifier ACCEPTS it', () => {
    const { pk, proof } = mintUnboundStatement(MSG, noPk)
    expect(verify({ pk }, proof, MSG, noPk).equationHolds).toBe(true)
  })

  it('but a chosen victim key still cannot be forged against', () => {
    const victim = keygen().statement
    const attempt = forgeAgainstTarget(victim.pk, MSG, noPk)
    expect(verify(victim, attempt.proof!, MSG, noPk).equationHolds).toBe(false)
  })
})
