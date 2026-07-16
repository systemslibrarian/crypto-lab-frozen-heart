import { describe, it, expect } from 'vitest'
import { judge } from './verdict'

describe('verdict separation — colour tracks integrity, not the raw return', () => {
  it('honest + equation holds -> SOUND', () => {
    expect(judge('honest', true).integrity).toBe('sound')
  })
  it('forgery + equation FAILS -> HELD (safe: verifier rejected it)', () => {
    expect(judge('forgery', false).integrity).toBe('held')
  })
  it('forgery + equation HOLDS -> ALARM (a forgery was accepted; never green)', () => {
    const v = judge('forgery', true)
    expect(v.integrity).toBe('alarm')
    expect(v.equationHolds).toBe(true) // the crypto result and the verdict disagree — the point
  })
  it('honest + equation FAILS -> ALARM (a legitimate proof was rejected)', () => {
    expect(judge('honest', false).integrity).toBe('alarm')
  })
})
