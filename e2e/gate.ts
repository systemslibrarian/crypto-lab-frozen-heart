import AxeBuilder from '@axe-core/playwright'
import { expect, type Page, type Locator } from '@playwright/test'
import { auditContrast, formatContrastFailures } from './contrast'
import { auditNonText } from './nontext';
import { NONTEXT_BASELINE } from './nontext-baseline';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 }

/**
 * Shared machinery for the WCAG gate.
 *
 * Three rules govern everything here:
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN. The spec this file
 *     replaces opened with
 *     `addStyleTag('*{animation:none!important;transition:none!important}')`,
 *     which does not exercise the page's motion policy — it overrides it. This
 *     lab's animations are correctly gated behind
 *     `@media (prefers-reduced-motion: no-preference)`, and the only way to
 *     confirm that is to set the preference and look, not to blanket-kill
 *     animation from outside. The same spec then force-opened every `<details>`,
 *     stripped `[hidden]` from every element and added `.active`/`.is-active`/
 *     `.open` to each one — fabricating a page no visitor can reach, since the
 *     guide banner is `hidden` until the guided run narrates into it.
 *
 *  2. EVERY SCAN ASSERTS ITS CONTENT IS PRESENT FIRST, and there are scans well
 *     past first paint. The replaced spec drove the page by clicking every
 *     button whose label matched a regex, in DOM order, with `.catch(() => {})`
 *     swallowing every failure — and then scanned ONCE at the end. Every state
 *     it built was thrown away unmeasured, and a click that silently did nothing
 *     was indistinguishable from one that worked.
 *
 *  3. `violations` IS NOT THE WHOLE ORACLE. See `scan`.
 */

/**
 * Soft-gate collection mode.
 *
 * With `A11Y_COLLECT=1` an assertion records its failure and returns instead of
 * throwing, so one run reports EVERY defect across all four configurations
 * rather than stopping at the first. `reportCollected()` then fails the test —
 * a collecting run can never be mistaken for a passing gate.
 */
const COLLECTING = process.env.A11Y_COLLECT === '1'
const collected: string[] = []

function softExpect(actual: unknown, message: string): void {
  if (!COLLECTING) {
    expect(actual, message).toEqual([])
    return
  }
  const list = actual as unknown[]
  if (Array.isArray(list) && list.length === 0) return
  collected.push(`${message}\n    ${JSON.stringify(actual)}`)
}

export function reportCollected(): void {
  if (!COLLECTING) return
  console.log(`\n===== collected ${collected.length} finding(s) =====`)
  for (const line of collected) console.log(`  - ${line}`)
  expect(collected, 'A11Y_COLLECT=1 was set: this is a collection run, not a passing gate').toEqual(
    [],
  )
}

/**
 * Wait for every running animation and transition to drain.
 *
 * Transitions drain in waves, not in one batch, so a poll for "nothing running
 * right now" can exit through a gap between waves. Require quiescence to hold
 * for several consecutive frames instead.
 */
export async function settle(page: Page): Promise<void> {
  await page.waitForFunction(
    () => {
      const w = window as unknown as { __quietFrames?: number }
      const running = document.getAnimations().filter((a) => a.playState === 'running')
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0
      return w.__quietFrames >= 6
    },
    undefined,
    { timeout: 20_000, polling: 'raf' },
  )
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion handling
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set. This page's
 * `tok-drop` keyframe ends at `opacity: 0` and is applied to a `.tok.dropping`
 * span, so the shape exists here; it is safe only because the class is removed
 * by a timer rather than by the animation, which is exactly the kind of thing
 * an injected `animation: none` hides instead of proving.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = []
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim()
      if (!own) continue
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue
      let effective = 1
      let node: Element | null = el
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity)
        node = node.parentElement
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`)
      }
    }
    return Array.from(new Set(out))
  })
  softExpect(invisible, `no visible text may render at opacity 0 in state: ${label}`)
}

/**
 * Load the page in a known theme with reduced motion actually in effect, and
 * assert the content — and the DEFAULTS — every later step relies on.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.1, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page.
 *
 * The default assertions matter more here than usual, because this lab's whole
 * subject is a policy that can be flipped. The transcript starts STRONG and the
 * transform starts INTERACTIVE at step 0; a gate that assumed the other half
 * would be scanning the forgeable page and never the sound one, or vice versa.
 * The URL hash can also override the field policy on load, so the drive asserts
 * the page really came up with the shipped defaults before it changes anything.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  await page.emulateMedia({ reducedMotion: 'reduce' })
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme)
  await page.goto('.')
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect',
  ).toBe(true)
  // index.html's anti-flash script stamps `data-theme` unconditionally, falling
  // back to 'dark', so the attribute is present in both themes.
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme)
  await expect(page.locator('html')).toHaveAttribute('data-app-ready', 'true')

  await expect(page.locator('h1.cl-hero-title')).toHaveText('Frozen Heart')

  // Shipped defaults, asserted rather than assumed.
  await expect(page.locator('#fs-formula')).toHaveText('c = H(G, pk, R, m)')
  await expect(page.locator('.ordering-tag')).toHaveText('sound')
  await expect(page.locator('.step-explainer-title')).toHaveText('Ready')
  await expect(page.locator('.btn-row[aria-label="Protocol mode"] button').first()).toHaveAttribute(
    'aria-pressed',
    'true',
  )
  await expect(page.locator('#break-result .indicator-note')).toHaveText(
    'Run an attempt to see the two independent indicators.',
  )
  await expect(page.locator('.guide-banner')).toBeHidden()
  // Every `<details>` on the page ships CLOSED; the drive opens each one.
  expect(
    await page
      .locator('#app details')
      .evaluateAll((els) => els.filter((e) => (e as HTMLDetailsElement).open).length),
    'no <details> may ship open',
  ).toBe(0)
  await expect(page.locator('.ladder .rung')).toHaveCount(5)

  await settle(page)
  await expectNotBlank(page, `${theme} first paint`)
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all, and this lab is a
 * plausible offender: it prints 64-character hex points and scalars, a
 * two-column comparison, a two-column verdict row, and code blocks of
 * fixed-width source.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement
    // `body { overflow-x: hidden }` propagates to the viewport when `html`
    // leaves `overflow` at `visible`, so `scrollWidth` stays equal to
    // `clientWidth` even when content is CUT OFF — a worse 1.4.10 outcome than
    // a scrollbar, and invisible to the standard check. Detect the clipping
    // directly instead of trusting the scroll geometry.
    const clippedByViewport = ['hidden', 'clip'].includes(
      getComputedStyle(document.body).overflowX,
    )
    if (!clippedByViewport && doc.scrollWidth <= doc.clientWidth) return null

    // Only elements that actually push the DOCUMENT sideways are culprits. A
    // wide code block inside an `overflow-x: auto` wrapper has a huge bounding
    // rect but is clipped by its scroller and contributes nothing to the
    // document's scroll width — naming it sends you off fixing the wrong thing.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement
      // Stop BEFORE <body>. When `body { overflow-x: hidden }` propagates to the
      // viewport, body itself answers "hidden" to this walk — so every element
      // on the page reads as clipped, `escaping` is always empty, and the oracle
      // reports nothing at all. That is the failure this whole check exists to
      // avoid: a viewport-level clip is the DEFECT, not a legitimate scroller.
      // Only a genuine scrolling container INSIDE the page excuses an overflow.
      while (n && n !== doc && n !== document.body) {
        const ox = getComputedStyle(n).overflowX
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true
        n = n.parentElement
      }
      return false
    }

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right)
    // Anything inside a real scroller is reachable and is not a finding; only
    // what escapes the viewport with no way back is.
    const escaping = over.filter((x) => !clipped(x.el))
    if (!escaping.length) return null
    const widest = escaping[0]
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest:
        `${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
        `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
        ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`,
    }
  })
  softExpect(
    overflow === null ? [] : [overflow],
    `page must not scroll horizontally in state: ${label}`,
  )
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1).
 * If it holds no focusable content it needs `tabindex="0"`, so it becomes a
 * focus target arrow keys can then scroll.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,[tabindex]:not([tabindex="-1"])'
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el)
        return (
          ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY)
        )
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`,
      )
  })
  softExpect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`,
  )
}

/**
 * Scan the page as it currently stands.
 *
 * Five assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - `violations` — the usual WCAG A/AA rule failures.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those
 *    ratios arithmetically. Everything else in that bucket is a real result
 *    axe simply could not finish — including `aria-prohibited-attr`, which is
 *    where an `aria-label` on a role-less div hides, a defect that never
 *    reaches the violations array at all.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 */
/**
 * WCAG 1.4.11 and generated content, ratcheted against a per-repo baseline.
 *
 * Neither class has ANY other oracle: axe has no rule for non-text contrast,
 * and the arithmetic text walk cannot reach a control's boundary or a
 * `::before` glyph, because a pseudo-element is not an element and owns no text
 * node. Both were being found by hand-sampling screenshot pixels, which does
 * not regress-test.
 *
 * The backlog is real, so this does not block on it — but a check that merely
 * logs is not a gate, and this sweep has spent its whole length deleting checks
 * that could not fail. So it ratchets instead: anything NOT in the baseline
 * fails, anything in the baseline that got WORSE fails, and anything in the
 * baseline that has been FIXED fails until its entry is deleted. That last rule
 * is what stops the allowlist becoming a permanent exemption.
 */
const nonTextSeen = new Set<string>();

export async function expectNoNewNonTextFailures(page: Page, label: string): Promise<void> {
  const found = await auditNonText(page);
  // Capture mode: emit every finding and assert nothing, so a baseline can be
  // generated by the SAME path that checks it. Opt-in via env, and the run is
  // deliberately left failing at the end by `expectBaselineNotStale` so a
  // capture pass can never be mistaken for a passing gate.
  if (process.env.NT_BASELINE_CAPTURE) {
    for (const f of found) {
      console.log(`NTCAP|${f.kind}|${f.selector}|${f.ratio}|${f.required}|${/POSITIONED/.test(f.detail)}`);
    }
    return;
  }
  const problems: string[] = [];
  for (const f of found) {
    const key = `${f.kind}|${f.selector}`;
    nonTextSeen.add(key);
    const base = NONTEXT_BASELINE[key];
    if (!base) {
      problems.push(`NEW ${f.ratio}:1 (needs ${f.required}:1) [${f.kind}] ${f.selector} — ${f.detail}`);
    } else if (f.ratio < base.ratio - 0.01) {
      problems.push(
        `WORSE ${f.selector}: ${f.ratio}:1, baseline recorded ${base.ratio}:1`
      );
    }
  }
  expect(problems, `new or worsened non-text contrast in state: ${label}`).toEqual([]);
}

/**
 * Fail if a baselined finding never appeared during the whole drive.
 *
 * It has either been fixed — in which case delete the entry, which is the point
 * — or the drive stopped reaching the state that shows it, which is a coverage
 * regression worth knowing about. Call once, after `driveAllStates`.
 */
export function expectBaselineNotStale(): void {
  const unseen = Object.keys(NONTEXT_BASELINE).filter((k) => !nonTextSeen.has(k));
  expect(
    unseen,
    'baselined non-text findings that no longer appear — delete them from nontext-baseline.ts (or restore the drive state that showed them)'
  ).toEqual([]);
}

export async function scan(page: Page, label: string): Promise<void> {
  await settle(page)
  await expectNotBlank(page, label)
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze()

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }))
  softExpect(violations, `axe violations in state: ${label}`)

  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }))
  softExpect(unexplainedIncomplete, `axe incomplete results in state: ${label}`)

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))))
  softExpect(contrast, `measured contrast failures in state: ${label}`)

  await expectScrollersReachable(page, label)
  await expectNoHorizontalOverflow(page, label)
  await expectNoNewNonTextFailures(page, label);
}

/**
 * Wait out the formula's drop-out re-render.
 *
 * `renderFormula(prev)` paints the departing field as a `.tok.dropping` span and
 * schedules a second `renderFormula()` 580ms later to remove it. A scan started
 * inside that window is measuring a page that mutates underneath it — axe and
 * the contrast walk can disagree about what was on screen, which is exactly how
 * a gate becomes flaky. Every scan below waits for the settled formula instead.
 */
async function settleFormula(page: Page): Promise<void> {
  await expect(page.locator('#fs-formula .tok.dropping')).toHaveCount(0)
}

/** Open a `<details>` by clicking its summary — never by setting `.open`. */
async function openDetails(d: Locator): Promise<void> {
  if (await d.evaluate((e) => (e as HTMLDetailsElement).open)) return
  await d.locator('> summary').click()
  await expect(d).toHaveAttribute('open', '')
}

/**
 * Drive the lab through every state that renders content, scanning each.
 *
 * The page is a single long document with no tabs, so the branching lives in
 * five places: the interactive/non-interactive mode fork on the transform
 * stepper (each with five steps and a Reset), the five transcript presets and
 * the free-form field toggles beneath them, the forge/honest fork on the break
 * panel, the two ladder demonstrations, and the hero's guided run — which is
 * the only thing that ever renders the narration banner.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  const s = (label: string): Promise<void> => scan(page, `${theme} / ${label}`)

  await s('first paint')

  // --- The transform stepper, INTERACTIVE branch (the shipped default) --------
  // Scoped by label: the ACTIVE mode button also carries `.primary`, so
  // `#sec-transform button.primary` alone matches two elements.
  const next = page.locator('#sec-transform button.primary', { hasText: /^(Start|Next|Done)/ })
  const labels = ['Start: Commit', 'Next: Challenge', 'Next: Respond', 'Next: Verify']
  for (let i = 0; i < labels.length; i++) {
    await expect(next).toHaveText(labels[i]!)
    await next.click()
    await s(`interactive transform, step ${i + 1}`)
  }
  await expect(next).toBeDisabled()
  await expect(page.locator('.eqcompare')).toBeVisible()
  await s('interactive transform, verification equation shown')

  // Reset is a real state: the diagram returns to `pending` with no values.
  await page.locator('#sec-transform button', { hasText: 'Reset' }).click()
  await expect(page.locator('.step-explainer-title')).toHaveText('Ready')
  await s('transform reset')

  // --- The NON-INTERACTIVE branch --------------------------------------------
  const modeButtons = page.locator('.btn-row[aria-label="Protocol mode"] button')
  await modeButtons.nth(1).click()
  await expect(modeButtons.nth(1)).toHaveAttribute('aria-pressed', 'true')
  await expect(page.locator('.flow')).toHaveClass(/\bni\b/)
  await s('non-interactive mode, step 0')

  for (let i = 0; i < labels.length; i++) {
    await next.click()
    await s(`non-interactive transform, step ${i + 1}`)
  }
  await expect(page.locator('.eqcompare')).toBeVisible()

  // Switching mode mid-run clamps the step back to 1 — a real transition.
  await modeButtons.nth(0).click()
  await expect(page.locator('.step-explainer-title')).toContainText('Step 1')
  await s('mode switched mid-run, step clamped')

  // --- Every disclosure. All seven ship closed, and every mode/step click above
  // called `renderApp()`, which rebuilds the document and closes them again — so
  // this pass belongs AFTER the stepper, not before it. Nothing from here on
  // re-renders the whole app, so they stay open for the rest of the drive.
  const details = page.locator('#app details')
  const detailCount = await details.count()
  expect(detailCount, 'the page must still have its disclosures').toBeGreaterThanOrEqual(7)
  for (let i = 0; i < detailCount; i++) {
    await openDetails(details.nth(i))
  }
  await s('every disclosure open')

  // --- The transcript presets. Each is a distinct rendering of the formula, the
  // ordering strip and the preset row's pressed state.
  const presets = page.locator('.preset')
  const presetNames = ['Strong', 'Drop R', 'Drop m', 'Drop pk', 'Drop G']
  await expect(presets).toHaveCount(presetNames.length)
  for (let i = 0; i < presetNames.length; i++) {
    await presets.nth(i).click()
    await expect(presets.nth(i)).toHaveAttribute('aria-pressed', 'true')
    await settleFormula(page)
    await s(`preset: ${presetNames[i]}`)

    // Forge under this policy, then make an honest proof under it. Both render
    // the two-indicator verdict; only the forgery path renders the algebra.
    await page.locator('button.danger').click()
    await expect(page.locator('.verdict-row')).toBeVisible()
    await s(`preset: ${presetNames[i]} — forgery attempt`)

    await page.locator('#sec-break button', { hasText: 'Make an honest proof' }).click()
    await expect(page.locator('.verdict-row')).toBeVisible()
    await s(`preset: ${presetNames[i]} — honest proof`)
  }

  // --- The free-form field toggles, driven to their extreme: every field out of
  // the hash. No preset reaches this state, and `c = H()` is a real rendering.
  const toggles = page.locator('.field-toggle input')
  await expect(toggles).toHaveCount(4)
  for (let i = 0; i < 4; i++) await toggles.nth(i).uncheck()
  await settleFormula(page)
  await expect(page.locator('#fs-formula')).toHaveText('c = H()')
  await s('every field dropped from the hash')

  await page.locator('button.danger').click()
  await expect(page.locator('.verdict-row')).toBeVisible()
  await s('forgery with an empty transcript')

  for (let i = 0; i < 4; i++) await toggles.nth(i).check()
  await settleFormula(page)
  await expect(page.locator('#fs-formula')).toHaveText('c = H(G, pk, R, m)')

  // --- The message input's extremes ------------------------------------------
  const msg = page.locator('#break-msg')
  await msg.fill('')
  await expect(msg).toHaveValue('')
  await s('empty message')
  // An unbroken 140-character token is the reflow stress case for this input and
  // for the hex values a proof over it produces.
  await msg.fill('m'.repeat(140))
  await page.locator('button.danger').click()
  await expect(page.locator('.verdict-row')).toBeVisible()
  await s('very long message, forgery attempt')
  await msg.fill('login as alice@bank — session 4f9c')

  // --- "Copy link to this state". In a headless context the clipboard write is
  // rejected, so this exercises the FAILURE label — the branch a happy-path
  // drive never reaches.
  // The label reverts on a 1.6s timer, so asserting the branch ran and THEN
  // scanning the settled state keeps the scan off a page that is still changing.
  const copy = page.locator('button.ghost')
  await copy.click()
  await expect(copy).toHaveText(/Copied ✓|Copy failed/)
  await expect(copy).toHaveText('Copy link to this state')
  await s('copy-link button after its post-click label reverted')

  // --- The two ladder demonstrations -----------------------------------------
  await page.locator('button', { hasText: 'See the replay' }).click()
  await expect(page.locator('.rung .compare .compare-line').first()).toBeVisible()
  await s('ladder: replay across messages demonstrated')

  await page.locator('button', { hasText: 'See the unbound proof' }).click()
  await s('ladder: unbound (key, proof) pair demonstrated')

  // --- The hero's guided run. It is the only route to the narration banner, and
  // it ends on the alarm tone with the forgery accepted.
  // The guided run advances itself on ~6s of timers, so its intermediate
  // narrations are ASSERTED but not scanned: a scan takes longer than a step,
  // and measuring a page that is rewriting itself mid-scan is how a gate starts
  // reporting different results on identical source. The settled end state is
  // scanned for real.
  await page.locator('.cta').click()
  const banner = page.locator('.guide-banner')
  await expect(banner).toBeVisible()
  await expect(banner).toContainText('Step 1 of 4')
  await expect(banner).toContainText('Step 2 of 4', { timeout: 20_000 })
  await expect(banner).toContainText('Step 3 of 4', { timeout: 20_000 })
  await expect(banner).toContainText('Step 4 of 4', { timeout: 20_000 })
  await expect(page.locator('.indicator.alarm')).toBeVisible()
  await settleFormula(page)
  await s('guided run complete — forgery accepted, verdict ALARM')

  // --- Focus-revealed skip link. It parks off-screen until focused, so the
  // visible rendering only exists in this state.
  await page.locator('.cl-skip-link').focus()
  await expect(page.locator('.cl-skip-link')).toBeFocused()
  await s('skip link focused')

  // --- A disabled control is a state with its own colours.
  await page.locator('#sec-transform button', { hasText: 'Reset' }).click()
  for (let i = 0; i < 4; i++) await next.click()
  await expect(next).toBeDisabled()
  // Stepping re-rendered the app and closed the disclosures again; re-open them
  // so this final scan covers the same surface as the rest of the drive.
  for (let i = 0; i < detailCount; i++) await openDetails(details.nth(i))
  await s('transform stepper exhausted — Next disabled')
}
