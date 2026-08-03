/**
 * FUNCTIONAL claims gate.
 *
 * The a11y spec proves the page is reachable; this one proves it is *right*. Every
 * headline verdict, every failure path, and the omission ladder's severity chips are
 * asserted against what the page actually computed and rendered — not against a string
 * we hoped it would print.
 *
 * Where possible an assertion re-derives the page's own numbers with the repo's real
 * group code (`src/schnorr/group.ts`), so a wrong algebra in the app shows up as a wrong
 * *value*, not just a wrong label.
 */
import { expect, test, type Locator, type Page } from '@playwright/test'
import {
  mulG,
  mul,
  sub,
  scInv,
  scalarFromBytesLE,
  decodePoint,
  encodePoint,
  bytesToHex,
  hexToBytes,
} from '../src/schnorr/group'
import { challenge } from '../src/schnorr/fiatshamir'

test.describe.configure({ mode: 'parallel' })
// Every rung of the ladder runs a real forgery, a real honest proof and a mint against the
// real verifier on load. Give the crypto room rather than weakening what we assert.
test.setTimeout(90_000)

const STRONG_FORMULA = 'c = H(G, pk, R, m)'

async function open(page: Page, hash = ''): Promise<void> {
  await page.goto('.' + hash)
  await expect(page.locator('html')).toHaveAttribute('data-app-ready', 'true')
}

/** The two independently-rendered halves of the break panel's verdict. */
function indicators(page: Page): { crypto: Locator; security: Locator } {
  const row = page.locator('#break-result .verdict-row')
  return { crypto: row.locator('.indicator').nth(0), security: row.locator('.indicator').nth(1) }
}

async function selectPreset(page: Page, label: string): Promise<void> {
  await page.locator('.presets button', { hasText: new RegExp(`^${label}`) }).click()
  await expect(page.locator('.presets button[aria-pressed="true"] .preset-label')).toHaveText(label)
}

async function forge(page: Page): Promise<void> {
  await page.getByRole('button', { name: /^Forge Alice/ }).click()
  await expect(page.locator('#break-result .verdict-row')).toBeVisible()
}

async function proveHonestly(page: Page): Promise<void> {
  await page.getByRole('button', { name: /^Make an honest proof/ }).click()
  await expect(page.locator('#break-result .verdict-row')).toBeVisible()
}

/** The attempt's own explanation of why the technique did or did not apply. */
function techniqueNote(page: Page): Locator {
  return page.locator('#break-result > div > p.indicator-note')
}

/** Full hex behind one of the algebra derivation lines (the visible chip is elided). */
async function algebraValue(page: Page, index: number): Promise<string> {
  const line = page.locator('.algebra-line').nth(index)
  const sr = await line.locator('.algebra-val .sr-only').textContent()
  return (sr ?? '').replace(/^equals\s+/, '').trim()
}

/* ============================================================================
   1. THE HEADLINE VERDICT — forged proof accepted, and never shown as green
   ============================================================================ */

test('drop R: the real verifier ACCEPTS the forgery and the security verdict alarms', async ({ page }) => {
  await open(page)
  await selectPreset(page, 'Drop R')
  await expect(page.locator('#fs-formula')).toHaveText('c = H(G, pk, m)')
  await forge(page)

  const { crypto, security } = indicators(page)
  // Two INDEPENDENT indicators (README exhibit 3): the raw result says the equation
  // balanced; the security verdict still refuses to call that a good outcome.
  await expect(crypto.locator('.indicator-value')).toHaveText(/Equation HOLDS/)
  await expect(crypto.locator('.indicator-value')).toHaveClass(/is-holds/)
  await expect(security.locator('.indicator-value')).toHaveText(/ALARM/)
  await expect(security.locator('.indicator-value')).toHaveClass(/is-alarm/)
  // "a forged proof that verifies is never green"
  await expect(security).toHaveClass(/\balarm\b/)
  await expect(security).not.toHaveClass(/\bgood\b/)
  // …and it says WHY.
  await expect(security.locator('.indicator-note')).toHaveText(
    /accepted a proof for a key nobody holds/,
  )
  await expect(techniqueNote(page)).toHaveText(
    /Commitment R is not in the hash, so the challenge is fixed before R is chosen/,
  )
  // The order of operations inverted — that is the mechanism, not decoration.
  await expect(page.locator('.ordering')).toHaveClass(/alarm/)
  await expect(page.locator('.ordering-tag')).toHaveText('forgeable')
  await expect(page.locator('.ordering-steps')).toHaveText(/solve R = \[s\]G − \[c\]pk/)
})

test('the forged proof is real algebra against the advertised target key', async ({ page }) => {
  await open(page)
  // The public key the page says it is attacking (only a prefix is rendered).
  const advertised = (await page.locator('#sec-break > p.lead code').textContent()) ?? ''
  const pkPrefix = advertised.replace(/^pk\s*=\s*/, '').replace(/…$/, '').trim()
  expect(pkPrefix).toMatch(/^[0-9a-f]{12}$/)

  const message = 'transfer 10 BTC to mallory'
  await page.locator('.custom-transcript summary').click()
  await page.locator('#break-msg').fill(message)
  await selectPreset(page, 'Drop R')
  await forge(page)

  // The three values the page claims it used.
  await expect(page.locator('.algebra-line')).toHaveCount(3)
  const s = scalarFromBytesLE(hexToBytes(await algebraValue(page, 0)))
  const c = scalarFromBytesLE(hexToBytes(await algebraValue(page, 1)))
  const R = decodePoint(hexToBytes(await algebraValue(page, 2)))

  // The verification equation is [s]G = R + [c]pk, so the key this proof actually
  // satisfies is pk = [c⁻¹]([s]G − R). Recomputed here with the repo's real group code.
  const recoveredPk = mul(scInv(c), sub(mulG(s), R))
  const recoveredHex = bytesToHex(encodePoint(recoveredPk))
  // It is Alice's key — the forgery targets the key the page advertised, not a key of
  // the forger's choosing.
  expect(recoveredHex.startsWith(pkPrefix)).toBe(true)

  // And the challenge really is the hash of the transcript minus R, over that same key.
  const expectedC = challenge(recoveredPk, R, new TextEncoder().encode(message), {
    g: true,
    pk: true,
    R: false,
    message: true,
  })
  expect(c).toBe(expectedC)
})

/* ============================================================================
   2. EVERY FAILURE / TAMPER PATH THE PAGE OFFERS
   ============================================================================ */

const HOLDING_PRESETS: { label: string; formula: string }[] = [
  { label: 'Strong', formula: STRONG_FORMULA },
  { label: 'Drop m', formula: 'c = H(G, pk, R)' },
  { label: 'Drop pk', formula: 'c = H(G, R, m)' },
  { label: 'Drop G', formula: 'c = H(pk, R, m)' },
]

for (const { label, formula } of HOLDING_PRESETS) {
  test(`forgery under "${label}" is REJECTED, and the page says why`, async ({ page }) => {
    await open(page)
    await selectPreset(page, label)
    await expect(page.locator('#fs-formula')).toHaveText(formula)
    await forge(page)

    const { crypto, security } = indicators(page)
    await expect(crypto.locator('.indicator-value')).toHaveText(/Equation FAILS/)
    await expect(crypto.locator('.indicator-value')).toHaveClass(/is-fails/)
    await expect(security.locator('.indicator-value')).toHaveText(/HELD/)
    await expect(security).toHaveClass(/\bheld\b/)
    await expect(security.locator('.indicator-note')).toHaveText(
      /verifier rejected the forgery. The transcript binding did its job/,
    )
    // The reason: R is still hashed, so the challenge stays circular.
    await expect(techniqueNote(page)).toHaveText(
      /Commitment R is inside the hash.*forging this needs the secret key/s,
    )
    // No derivation panel — there was no technique to show.
    await expect(page.locator('.algebra')).toHaveCount(0)
    await expect(page.locator('.ordering-tag')).toHaveText('sound')
  })
}

test('an honest prover holds under every preset — the forgery is what changes, not the protocol', async ({
  page,
}) => {
  await open(page)
  for (const label of ['Strong', 'Drop G', 'Drop m', 'Drop pk', 'Drop R']) {
    await selectPreset(page, label)
    await proveHonestly(page)
    const { crypto, security } = indicators(page)
    await expect(crypto.locator('.indicator-value'), label).toHaveText(/Equation HOLDS/)
    await expect(security.locator('.indicator-value'), label).toHaveText(/SOUND/)
    await expect(security, label).toHaveClass(/\bgood\b/)
  }
})

test('custom toggles reach the same failure as the preset: unchecking R alone forges', async ({
  page,
}) => {
  await open(page)
  await page.locator('.custom-transcript summary').click()
  await page.locator('#ft-R').uncheck()
  await expect(page.locator('#fs-formula')).toHaveText('c = H(G, pk, m)')
  await forge(page)
  await expect(indicators(page).security.locator('.indicator-value')).toHaveText(/ALARM/)

  // Re-checking R closes the hole again — the failure path is reversible and real.
  await page.locator('#ft-R').check()
  await expect(page.locator('#fs-formula')).toHaveText(STRONG_FORMULA)
  await expect(page.locator('#break-result')).toHaveText(/Run an attempt/)
  await forge(page)
  await expect(indicators(page).security.locator('.indicator-value')).toHaveText(/HELD/)
})

test('the empty transcript c = H() is forgeable too, and the derivation names it correctly', async ({
  page,
}) => {
  await open(page)
  await page.locator('.custom-transcript summary').click()
  for (const id of ['#ft-g', '#ft-pk', '#ft-R', '#ft-message']) await page.locator(id).uncheck()
  await expect(page.locator('#fs-formula')).toHaveText('c = H()')
  await forge(page)
  await expect(indicators(page).security.locator('.indicator-value')).toHaveText(/ALARM/)
  // REGRESSION: the derivation used to hardcode "c = H(G, pk, m)" no matter which fields
  // were actually hashed, contradicting the live formula directly above it.
  await expect(page.locator('.algebra-line').nth(1).locator('.algebra-expr')).toHaveText('c = H()')
})

test('the derivation formula tracks the fields actually hashed, not a fixed string', async ({
  page,
}) => {
  await open(page)
  await page.locator('.custom-transcript summary').click()
  await page.locator('#ft-R').uncheck()
  await page.locator('#ft-g').uncheck()
  await expect(page.locator('#fs-formula')).toHaveText('c = H(pk, m)')
  await forge(page)
  await expect(page.locator('.algebra-line').nth(1).locator('.algebra-expr')).toHaveText('c = H(pk, m)')
})

test('editing the message discards the stale result rather than showing it under a new transcript', async ({
  page,
}) => {
  await open(page)
  await selectPreset(page, 'Drop R')
  await forge(page)
  await expect(indicators(page).security.locator('.indicator-value')).toHaveText(/ALARM/)
  await page.locator('.custom-transcript summary').click()
  await page.locator('#break-msg').fill('a different context string')
  await expect(page.locator('#break-result')).toHaveText(/Run an attempt/)
  await expect(page.locator('#break-result .verdict-row')).toHaveCount(0)
})

/* ============================================================================
   3. THE MEASURED LADDER — every chip re-derived from its own readings
   ============================================================================ */

type Reading = { forged: boolean; mint: boolean; replay: boolean }

function severityFrom(r: Reading): string {
  // The rule the page documents: strictly decreasing order of damage.
  if (r.forged) return 'fatal'
  if (r.mint) return 'unbound'
  if (r.replay) return 'context-loss'
  return 'sound'
}

async function readRung(rung: Locator): Promise<Reading & { sev: string; label: string }> {
  const measures = await rung.locator('.rung-measure').allTextContents()
  expect(measures).toHaveLength(3)
  const yes = (i: number): boolean => {
    const m = /:\s*(yes|no)\s*$/.exec(measures[i])
    expect(m, `unparseable measurement: ${measures[i]}`).not.toBeNull()
    return m![1] === 'yes'
  }
  const sevClass = (await rung.locator('.sev').getAttribute('class')) ?? ''
  return {
    forged: yes(0),
    mint: yes(1),
    replay: yes(2),
    sev: sevClass.replace(/^sev\s+/, '').trim(),
    label: ((await rung.locator('.sev').textContent()) ?? '').replace(/[^A-Za-z ]/g, '').trim(),
  }
}

test('every severity chip is exactly the function of the three readings printed beside it', async ({
  page,
}) => {
  await open(page)
  const rungs = page.locator('.rung')
  await expect(rungs).toHaveCount(5)

  const labelFor: Record<string, string> = {
    fatal: 'Fatal',
    unbound: 'Unbound',
    'context-loss': 'Context loss',
    sound: 'Sound',
  }
  const seen: string[] = []
  let forgedCount = 0

  for (let i = 0; i < 5; i++) {
    const rung = rungs.nth(i)
    const formula = (await rung.locator('.rung-formula').textContent()) ?? ''
    const r = await readRung(rung)
    seen.push(r.sev)
    if (r.forged) forgedCount++

    // The chip is a reading, not a name: derive it ourselves and demand a match.
    expect(r.sev, `severity chip for ${formula}`).toBe(severityFrom(r))
    expect(r.label, `severity label for ${formula}`).toBe(labelFor[r.sev])

    // The prose headline must agree with the same measurement it is summarising.
    await expect(rung.locator('.rung-consequence strong')).toHaveText(
      r.forged ? /Real verifier ACCEPTS a witness-free forgery/ : /Real verifier REJECTS the forgery attempt/,
    )
    await expect(rung.locator('.rung-consequence strong')).toHaveClass(r.forged ? /is-alarm/ : /is-held/)

    // Each reading's own colour must match its own yes/no.
    for (const [idx, hit] of [r.forged, r.mint, r.replay].entries()) {
      await expect(rung.locator('.rung-measure').nth(idx)).toHaveClass(hit ? /is-alarm/ : /is-held/)
    }
  }

  // README: "the omission ladder confirms exactly one rung (drop R) yields a verifying
  // fixed-target forgery."
  expect(forgedCount).toBe(1)
  expect(seen.filter((s) => s === 'fatal')).toHaveLength(1)
  const fatalIndex = seen.indexOf('fatal')
  await expect(rungs.nth(fatalIndex).locator('.rung-formula')).toHaveText(
    /drop commitment R · c = H\(G, pk, m\)/,
  )
  // …and every distinct severity the lab teaches is actually on the page.
  expect(new Set(seen)).toEqual(new Set(['sound', 'context-loss', 'unbound', 'fatal']))
})

test('the ladder drops each field exactly once — the rungs partition the strong transcript', async ({
  page,
}) => {
  await open(page)
  const formulas = await page.locator('.rung .rung-formula').allTextContents()
  const strong = formulas.filter((f) => f.startsWith('strong · '))
  expect(strong).toHaveLength(1)
  expect(strong[0]).toContain(STRONG_FORMULA)

  const all = ['G', 'pk', 'R', 'm']
  const omitted: string[] = []
  for (const f of formulas.filter((x) => !x.startsWith('strong · '))) {
    const inside = /c = H\(([^)]*)\)/.exec(f)![1]
    const present = inside.split(',').map((t) => t.trim())
    // exactly one field short of the whole
    expect(present).toHaveLength(3)
    const missing = all.filter((n) => !present.includes(n))
    expect(missing).toHaveLength(1)
    omitted.push(missing[0])
  }
  // the four drop-rungs together account for every field, none twice
  expect(omitted.sort()).toEqual([...all].sort())
})

test('the drop-message rung demonstrates the replay its own chip measured', async ({ page }) => {
  await open(page)
  const rung = page.locator('.rung', { hasText: 'drop message m' })
  const r = await readRung(rung)
  expect(r.replay).toBe(true)
  expect(r.sev).toBe('context-loss')

  await rung.locator('summary', { hasText: 'replay' }).click()
  await rung.getByRole('button', { name: 'See the replay' }).click()
  const out = rung.locator('.compare')
  // An honest proof about one message verifies…
  await expect(out.locator('.compare-line').nth(0)).toHaveText(/accepted/)
  await expect(out.locator('.compare-line').nth(0).locator('span').nth(1)).toHaveClass(/is-holds/)
  // …and the SAME bytes verify under a different, hostile message. That is the failure.
  await expect(out.locator('.compare-line').nth(1)).toHaveText(/pay Mallory 5000/)
  await expect(out.locator('.compare-line').nth(1)).toHaveText(/ALSO accepted — replayed/)
  await expect(out.locator('.compare-line').nth(1).locator('span').nth(1)).toHaveClass(/is-alarm/)
})

test('the drop-pk rung mints an unbound key+proof yet still cannot forge the victim key', async ({
  page,
}) => {
  await open(page)
  const rung = page.locator('.rung', { hasText: 'drop public key pk' })
  const r = await readRung(rung)
  expect(r.mint).toBe(true)
  expect(r.forged).toBe(false)
  expect(r.sev).toBe('unbound')

  await rung.locator('summary', { hasText: 'unbound' }).click()
  await rung.getByRole('button', { name: 'See the unbound proof' }).click()
  const out = rung.locator('.compare')
  await expect(out.locator('.compare-line').nth(0)).toHaveText(/accepted — not bound to any identity/)
  await expect(out.locator('.compare-line').nth(0).locator('span').nth(1)).toHaveClass(/is-alarm/)
  // The precision the README insists on: this is NOT a fixed-target forgery.
  await expect(out.locator('.compare-line').nth(1)).toHaveText(/still safe — cannot forge a chosen key/)
  await expect(out.locator('.compare-line').nth(1).locator('span').nth(1)).toHaveClass(/is-held/)
})

/* ============================================================================
   4. THE HEADLINE ONE-FIELD COMPARISON
   ============================================================================ */

test('the one-field comparison is measured: strong holds, weak is forged', async ({ page }) => {
  await open(page)
  const cols = page.locator('.cmp-col')
  await expect(cols).toHaveCount(2)

  const strong = cols.nth(0)
  await expect(strong).toHaveClass(/good/)
  await expect(strong.locator('code')).toHaveText(STRONG_FORMULA)
  await expect(strong).toHaveText(/verifier REJECTS/)
  // The class is computed from a real forgery attempt; the text beside it is the claim.
  await expect(strong.locator('.cmp-row').nth(2).locator('span').nth(1)).toHaveClass(/is-held/)

  const weak = cols.nth(1)
  await expect(weak).toHaveClass(/alarm/)
  await expect(weak.locator('code')).toHaveText('c = H(G, pk, m)')
  await expect(weak).toHaveText(/verifier ACCEPTS/)
  await expect(weak.locator('.cmp-row').nth(2).locator('span').nth(1)).toHaveClass(/is-alarm/)

  await expect(page.locator('.cmp-delta')).toHaveText('− R')
})

/* ============================================================================
   5. THE STEPPED TRANSFORM — both modes, verdict checked against the printed sides
   ============================================================================ */

async function stepToVerify(page: Page): Promise<void> {
  const sec = page.locator('#sec-transform')
  for (const name of ['Start: Commit', 'Next: Challenge', 'Next: Respond', 'Next: Verify']) {
    const btn = sec.getByRole('button', { name, exact: true })
    if ((await btn.count()) === 0) continue
    await btn.click()
  }
  await expect(sec.getByRole('button', { name: 'Done', exact: true })).toBeDisabled()
}

for (const mode of ['interactive', 'noninteractive'] as const) {
  test(`stepped ${mode} proof: the verdict matches the two sides the page printed`, async ({
    page,
  }) => {
    await open(page)
    const sec = page.locator('#sec-transform')
    if (mode === 'noninteractive') {
      await sec.getByRole('button', { name: /^Non-interactive/ }).click()
      await expect(sec.locator('.flow-self')).toHaveText(/c = H\(G, pk, R, m\)/)
    } else {
      await expect(sec.locator('.flow')).toHaveAttribute(
        'aria-label',
        /verifier sends back a random challenge c, chosen after seeing R/,
      )
    }
    await stepToVerify(page)

    const sides = await sec.locator('.eq-hex').allTextContents()
    expect(sides).toHaveLength(2)
    expect(sides[0]).toMatch(/^[0-9a-f]{64}$/)
    // Compute-both-sides-and-compare: the rendered verdict must be the comparison of the
    // two rendered values, not an assertion sitting next to them.
    const identical = sides[0] === sides[1]
    expect(identical).toBe(true)
    await expect(sec.locator('.eq-verdict')).toHaveText(
      identical ? /Both sides are byte-for-byte identical/ : /The two sides differ/,
    )
    await expect(sec.locator('.eq-verdict')).toHaveClass(identical ? /match/ : /nomatch/)

    const row = sec.locator('.verdict-row')
    await expect(row.locator('.indicator').nth(0).locator('.indicator-value')).toHaveText(
      /Equation HOLDS/,
    )
    await expect(row.locator('.indicator').nth(1).locator('.indicator-value')).toHaveText(/SOUND/)
    await expect(row.locator('.indicator').nth(1)).toHaveClass(/\bgood\b/)
  })
}

test('Reset returns the stepper to Ready and clears the verdict', async ({ page }) => {
  await open(page)
  const sec = page.locator('#sec-transform')
  await stepToVerify(page)
  await expect(sec.locator('.eqcompare')).toHaveCount(1)
  await sec.getByRole('button', { name: 'Reset', exact: true }).click()
  await expect(sec.locator('.step-explainer-title')).toHaveText('Ready')
  await expect(sec.locator('.eqcompare')).toHaveCount(0)
  await expect(sec.getByRole('button', { name: 'Start: Commit', exact: true })).toBeEnabled()
})

/* ============================================================================
   6. THE GUIDED EXPLOIT AND SHAREABLE STATE
   ============================================================================ */

test('the hero CTA drives the whole exploit and lands on ALARM', async ({ page }) => {
  await open(page)
  await page.getByRole('button', { name: /Show me the bug/ }).click()

  const banner = page.locator('.guide-banner')
  await expect(banner).toHaveText(/Step 1 of 4/)
  await expect(banner).toHaveText(/Step 2 of 4/, { timeout: 20_000 })
  // Step 2 forges under the STRONG transcript — the verifier must refuse.
  await expect(indicators(page).security.locator('.indicator-value')).toHaveText(/HELD/)
  await expect(banner).toHaveText(/Step 3 of 4/, { timeout: 20_000 })
  await expect(banner).toHaveText(/Step 4 of 4/, { timeout: 20_000 })
  // Same verifier, one field removed, opposite outcome.
  await expect(page.locator('#fs-formula')).toHaveText('c = H(G, pk, m)')
  await expect(indicators(page).crypto.locator('.indicator-value')).toHaveText(/Equation HOLDS/)
  await expect(indicators(page).security.locator('.indicator-value')).toHaveText(/ALARM/)
})

test('the transcript policy round-trips through the URL', async ({ page }) => {
  await open(page)
  await selectPreset(page, 'Drop pk')
  await page.locator('.custom-transcript summary').click()
  await page.locator('#break-msg').fill('shared state check')
  await expect(page.locator('#fs-formula')).toHaveText('c = H(G, R, m)')
  const shared = await page.evaluate(() => location.href)
  expect(shared).toContain('#c=grm')

  // A fresh load of that link must reconstruct the same policy and message.
  const fresh = await page.context().newPage()
  await fresh.goto(shared)
  await expect(fresh.locator('html')).toHaveAttribute('data-app-ready', 'true')
  await expect(fresh.locator('#fs-formula')).toHaveText('c = H(G, R, m)')
  await expect(fresh.locator('#break-msg')).toHaveValue('shared state check')
  await expect(fresh.locator('.presets button[aria-pressed="true"] .preset-label')).toHaveText('Drop pk')
  await fresh.close()
})

/* ============================================================================
   7. SCOPE HONESTY — the claim the README says the lab is careful never to make
   ============================================================================ */

test('the page scopes the forgery as authentication-only, not key recovery', async ({ page }) => {
  await open(page)
  const para = page.locator('.what-isnt')
  await expect(para).toHaveText(/not.{0,20}recover that key/s)
  await expect(para).toHaveText(/not.{0,20}break the discrete-log problem/s)
  await expect(para).toHaveText(/authentication forgery, not key recovery/)
})
