import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { execFileSync, spawnSync } from 'node:child_process'
import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { test } from 'node:test'
import { deploymentUrl, validateManifest, verifyFiles, verifyReport } from './verify-public-deployment.mjs'

const url = 'https://systemslibrarian.github.io/crypto-lab-frozen-heart/'
const identity = { repository: 'systemslibrarian/crypto-lab-frozen-heart',
  sourceSha: 'a'.repeat(40), lockSha256: 'b'.repeat(64) }
const bytes = Buffer.from('<h1>Frozen Heart</h1>')
const manifest = () => ({ version: 1, ...identity, files: [{ path: 'index.html',
  bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex') }] })
const report = () => ({ suites: [{ title: 'claims.spec.ts', specs: Array.from({ length: 24 }, (_, i) => ({
  file: 'claims.spec.ts', title: `control ${i}`, ok: true,
  tests: [{ projectName: '', expectedStatus: 'passed', status: 'expected',
    results: [{ status: 'passed', errors: [] }] }],
})) }], errors: [], stats: { expected: 24, unexpected: 0, skipped: 0, flaky: 0 } })
const fixtureFetch = async (requested) => ({ status: 200, url: requested,
  arrayBuffer: async () => bytes })

test('accepts the actual HTTPS deployment URL and rejects other targets', () => {
  assert.equal(deploymentUrl(url), url)
  for (const wrong of ['http://systemslibrarian.github.io/crypto-lab-frozen-heart/',
    'https://example.com/crypto-lab-frozen-heart/', 'https://systemslibrarian.github.io/',
    `${url}?other=1`, `${url}#other`, 'https://user@systemslibrarian.github.io/crypto-lab-frozen-heart/']) {
    assert.throws(() => deploymentUrl(wrong))
  }
})

test('accepts exact source and lock identity; rejects stale, empty and opaque build evidence', () => {
  assert.deepEqual(validateManifest(manifest(), identity), manifest())
  for (const bad of [null, { ...manifest(), sourceSha: 'c'.repeat(40) },
    { ...manifest(), lockSha256: 'd'.repeat(64) }, { ...manifest(), files: [] },
    { ...manifest(), files: [{ ...manifest().files[0], path: '../index.html' }] },
    { ...manifest(), files: [manifest().files[0], manifest().files[0]] },
    { ...manifest(), files: [{ ...manifest().files[0], sha256: null }] }]) {
    assert.throws(() => validateManifest(bad, identity))
  }
  for (const badIdentity of [{ ...identity, sourceSha: undefined },
    { ...identity, sourceSha: 'short' }, { ...identity, lockSha256: undefined },
    { ...identity, lockSha256: 'short' }]) {
    assert.throws(() => validateManifest({ ...manifest(), ...badIdentity }, badIdentity))
  }
})

test('checks real downloaded bytes and rejects changed, missing or redirected pages', async () => {
  assert.equal((await verifyFiles(manifest(), identity, url, fixtureFetch)).files.length, 1)
  for (const response of [
    { status: 200, url: `${url}index.html`, arrayBuffer: async () => Buffer.from('old deployment') },
    { status: 404, url: `${url}index.html`, arrayBuffer: async () => bytes },
    { status: 200, url: 'https://example.com/index.html', arrayBuffer: async () => bytes },
  ]) await assert.rejects(verifyFiles(manifest(), identity, url, async () => response))
})

test('a wrong URL or source identity stops collection before any request', async () => {
  let requests = 0
  const collect = async () => { requests++; throw new Error('Should not request') }
  await assert.rejects(verifyFiles(manifest(), identity, 'https://example.com/', collect))
  await assert.rejects(verifyFiles(manifest(), { ...identity, sourceSha: 'c'.repeat(40) }, url, collect))
  assert.equal(requests, 0)
})

test('unreadable network or timeout cannot establish successful deployment', async () => {
  await assert.rejects(verifyFiles(manifest(), identity, url, async () => {
    throw new Error('Network timeout')
  }), /timeout/)
})

test('a successful first download cannot hide an unreadable second file', async () => {
  const twoFiles = manifest()
  twoFiles.files.push({ ...twoFiles.files[0], path: 'assets/application.js' })
  let requests = 0
  await assert.rejects(verifyFiles(twoFiles, identity, url, async (requested) => {
    requests++
    if (requests === 1) return fixtureFetch(requested)
    return { status: 404, url: requested, arrayBuffer: async () => bytes }
  }), /Unreadable deployed file/)
  assert.equal(requests, 2)
})

test('requires successful execution and the complete original browser membership', () => {
  assert.equal(verifyReport(report(), report(), 0).passed, 24)
  for (const exit of [1, null, undefined, NaN]) assert.throws(() => verifyReport(report(), report(), exit))
  for (const bad of [null, {}, { ...report(), errors: [{ message: 'Uncaught error' }] },
    { ...report(), suites: [] }]) assert.throws(() => verifyReport(report(), bad, 0))
  const partial = report(); partial.suites[0].specs.pop(); partial.stats.expected = 23
  assert.throws(() => verifyReport(report(), partial, 0), /membership/)
  assert.throws(() => verifyReport(partial, partial, 0), /original full-suite/)
  const changed = report(); changed.suites[0].specs[0].title = 'Different test'
  assert.throws(() => verifyReport(report(), changed, 0), /membership/)
  const duplicate = report(); duplicate.suites[0].specs[1].title = duplicate.suites[0].specs[0].title
  assert.throws(() => verifyReport(report(), duplicate, 0), /duplicate/)
})

test('zero process exit cannot hide failed, skipped, unfinished, flaky or unreadable tests', () => {
  for (const status of ['failed', 'timedOut', 'skipped', 'interrupted', undefined]) {
    const bad = report(); bad.suites[0].specs[0].tests[0].results[0].status = status
    assert.throws(() => verifyReport(report(), bad, 0))
  }
  for (const count of ['unexpected', 'skipped', 'flaky']) {
    const bad = report(); bad.stats[count] = 1
    assert.throws(() => verifyReport(report(), bad, 0))
  }
  const unread = report(); unread.suites[0].specs[0].tests[0].results = []
  assert.throws(() => verifyReport(report(), unread, 0))
  const retried = report(); retried.suites[0].specs[0].tests[0].results.unshift({ status: 'failed' })
  assert.throws(() => verifyReport(report(), retried, 0))
})

test('actual capture pins Git bytes, rejects a changed checkout/lock, and installs or runs no lifecycle code', () => {
  const directory = mkdtempSync(resolve(tmpdir(), 'frozen-public-control-'))
  const cli = fileURLToPath(new URL('./verify-public-deployment.mjs', import.meta.url))
  const git = (...args) => execFileSync('git', args, { cwd: directory, encoding: 'utf8' }).trim()
  try {
    git('init', '--quiet')
    writeFileSync(resolve(directory, 'package-lock.json'), '{"lockfileVersion":3}\n')
    writeFileSync(resolve(directory, 'package.json'), JSON.stringify({ name: 'synthetic-control',
      scripts: { postinstall: 'touch lifecycle-ran', prepare: 'touch lifecycle-ran' } }))
    mkdirSync(resolve(directory, 'src'))
    writeFileSync(resolve(directory, 'src/main.ts'), 'export const original = true\n')
    git('add', 'package.json', 'package-lock.json', 'src/main.ts')
    git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '--quiet', '-m', 'Fixture')
    const sourceSha = git('rev-parse', 'HEAD')
    mkdirSync(resolve(directory, 'dist'))
    writeFileSync(resolve(directory, 'dist/index.html'), bytes)
    const env = { ...process.env, GITHUB_REPOSITORY: identity.repository, GITHUB_SHA: sourceSha,
      GITHUB_OUTPUT: resolve(directory, 'workflow-output') }
    const capture = (overrides = {}) => spawnSync(process.execPath, [cli, 'capture'], {
      cwd: directory, env: { ...env, ...overrides }, encoding: 'utf8' })
    assert.equal(capture().status, 0)
    const evidence = JSON.parse(readFileSync(resolve(directory, 'public-build-evidence.json'), 'utf8'))
    assert.equal(evidence.sourceSha, sourceSha)
    assert.equal(evidence.lockSha256, createHash('sha256').update(git('show', `${sourceSha}:package-lock.json`) + '\n').digest('hex'))
    assert.equal(existsSync(resolve(directory, 'node_modules')), false)
    assert.equal(existsSync(resolve(directory, 'lifecycle-ran')), false)
    // Same HEAD and lock, different source bytes must not be labelled exact.
    writeFileSync(resolve(directory, 'src/main.ts'), 'export const original = false\n')
    assert.notEqual(capture().status, 0)
    git('add', 'src/main.ts')
    assert.notEqual(capture().status, 0)
    writeFileSync(resolve(directory, 'src/main.ts'), 'export const original = true\n')
    assert.notEqual(capture().status, 0) // clean worktree bytes, dirty index
    git('add', 'src/main.ts')
    assert.equal(capture().status, 0)
    assert.notEqual(capture({ GITHUB_SHA: 'f'.repeat(40) }).status, 0)
    writeFileSync(resolve(directory, 'package-lock.json'), '{"lockfileVersion":2}\n')
    assert.notEqual(capture().status, 0)
    assert.equal(JSON.parse(readFileSync(resolve(directory, 'public-verification-error.json'), 'utf8')).completed, false)
    writeFileSync(resolve(directory, 'package-lock.json'), '{"lockfileVersion":3}\n')
    symlinkSync(resolve(directory, 'package-lock.json'), resolve(directory, 'dist/opaque'))
    assert.notEqual(capture().status, 0)
  } finally { rmSync(directory, { recursive: true, force: true }) }
})
