import { test } from '@playwright/test'
import { boot, driveAllStates, expectBaselineNotStale, NARROW, reportCollected } from './gate'

/**
 * WCAG A/AA gate.
 *
 * Four configurations, {dark, light} x {1280, 380}, each driven through the
 * whole lab rather than scanned once at the end: both branches of the
 * interactive/non-interactive fork and all five of their steps, every
 * transcript preset with both a forgery and an honest proof under it, the
 * empty-hash extreme no preset reaches, both ladder demonstrations, the guided
 * run that is the only route to the narration banner, and the disabled state of
 * the stepper.
 *
 * Reduced motion is EMULATED, never injected. This lab gates its animation
 * behind `@media (prefers-reduced-motion: no-preference)`, which is the correct
 * pattern — and the only way to show that it holds is to set the preference and
 * measure, rather than to blanket-kill `animation` from outside and prove
 * nothing.
 */

test.describe('WCAG A/AA gate', () => {
  test.beforeEach(({ page }) => {
    page.setDefaultTimeout(20_000)
  })

  test.afterAll(() => {
    reportCollected()
    // The baseline's third rule: a listed finding that no longer appears fails
    // until its entry is deleted, so a fixed defect cannot linger as a
    // permanent exemption. `expectBaselineNotStale` was exported and never
    // called, so that rule had never run and the file could only grow.
    //
    // It belongs in `afterAll` rather than at the end of each test.
    // `nonTextSeen` is module state and this config leaves `fullyParallel`
    // unset, so all four configurations share one worker and accumulate into
    // one set; the hook runs once, after the last of them, and therefore sees
    // the union of all four drives. Per test it would instead assert the whole
    // baseline against a partial drive.
    expectBaselineNotStale()
  })

  test('dark theme, desktop width', async ({ page }) => {
    test.slow()
    await boot(page, 'dark')
    await driveAllStates(page, 'dark @1280')
  })

  test('light theme, desktop width', async ({ page }) => {
    test.slow()
    await boot(page, 'light')
    await driveAllStates(page, 'light @1280')
  })

  test('dark theme, 380px reflow width', async ({ page }) => {
    test.slow()
    await page.setViewportSize(NARROW)
    await boot(page, 'dark')
    await driveAllStates(page, 'dark @380')
  })

  test('light theme, 380px reflow width', async ({ page }) => {
    test.slow()
    await page.setViewportSize(NARROW)
    await boot(page, 'light')
    await driveAllStates(page, 'light @380')
  })
})
