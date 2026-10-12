import { createHash } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { appendFileSync, readFileSync, readdirSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { pathToFileURL } from 'node:url'

const repository = 'systemslibrarian/crypto-lab-frozen-heart'
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex')
const requireEvidence = (condition, message) => { if (!condition) throw new Error(message) }

export function deploymentUrl(value) {
  const url = new URL(value)
  requireEvidence(url.protocol === 'https:' && url.hostname === 'systemslibrarian.github.io'
    && url.pathname === '/crypto-lab-frozen-heart/' && !url.port && !url.username
    && !url.password && !url.search && !url.hash, 'Unexpected deployment URL')
  return url.href
}

function sourceIdentity() {
  const sha = execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim()
  requireEvidence(/^[a-f0-9]{40}$/.test(sha) && sha === process.env.GITHUB_SHA,
    'Checkout does not match the workflow source SHA')
  requireEvidence(process.env.GITHUB_REPOSITORY === repository, 'Unexpected repository')
  // HEAD alone does not establish the bytes being built/tested. This checks
  // both staged and unstaged tracked changes; unreadable Git state fails too.
  execFileSync('git', ['diff', '--quiet', '--no-ext-diff', 'HEAD', '--'])
  execFileSync('git', ['diff', '--quiet', '--cached', '--no-ext-diff', 'HEAD', '--'])
  const capturedLock = execFileSync('git', ['show', `${sha}:package-lock.json`])
  requireEvidence(sha256(readFileSync('package-lock.json')) === sha256(capturedLock),
    'Working lock differs from the immutable source lock')
  return { repository, sourceSha: sha, lockSha256: sha256(capturedLock) }
}

function artifactFiles(directory, relative = '') {
  return readdirSync(resolve(directory, relative), { withFileTypes: true })
    .sort((a, b) => a.name.localeCompare(b.name)).flatMap((entry) => {
      const path = relative ? `${relative}/${entry.name}` : entry.name
      requireEvidence(!entry.isSymbolicLink(), `Opaque artifact entry: ${path}`)
      if (entry.isDirectory()) return artifactFiles(directory, path)
      requireEvidence(entry.isFile(), `Unreadable artifact entry: ${path}`)
      const bytes = readFileSync(resolve(directory, path))
      return [{ path, bytes: bytes.length, sha256: sha256(bytes) }]
    })
}

export function validateManifest(manifest, identity) {
  requireEvidence(identity?.repository === repository && /^[a-f0-9]{40}$/.test(identity.sourceSha)
    && /^[a-f0-9]{64}$/.test(identity.lockSha256), 'Missing or malformed source identity')
  requireEvidence(manifest?.version === 1 && manifest.repository === identity.repository
    && manifest.sourceSha === identity.sourceSha && manifest.lockSha256 === identity.lockSha256,
  'Build evidence does not match the checked-out source and lock')
  requireEvidence(Array.isArray(manifest.files) && manifest.files.length > 0
    && manifest.files.some((file) => file.path === 'index.html'), 'Missing build files')
  const paths = new Set()
  for (const file of manifest.files) {
    requireEvidence(typeof file.path === 'string' && file.path !== ''
      && !file.path.startsWith('/') && !file.path.includes('\\')
      && !file.path.split('/').some((part) => part === '' || part === '.' || part === '..')
      && !/[\u0000-\u001f]/.test(file.path) && !paths.has(file.path), 'Invalid or duplicate artifact path')
    requireEvidence(Number.isSafeInteger(file.bytes) && file.bytes >= 0
      && /^[a-f0-9]{64}$/.test(file.sha256), 'Unreadable artifact hash or size')
    paths.add(file.path)
  }
  return manifest
}

export async function verifyFiles(manifest, identity, pageUrl, fetchFile = fetch) {
  validateManifest(manifest, identity)
  const base = deploymentUrl(pageUrl)
  requireEvidence(process.env.NODE_TLS_REJECT_UNAUTHORIZED !== '0', 'TLS verification is disabled')
  const files = []
  for (const file of manifest.files) {
    const url = new URL(file.path.split('/').map(encodeURIComponent).join('/'), base).href
    const response = await fetchFile(url, { redirect: 'error', cache: 'no-store',
      signal: AbortSignal.timeout(30_000) })
    requireEvidence(response.status === 200 && response.url === url, `Unreadable deployed file: ${file.path}`)
    const bytes = new Uint8Array(await response.arrayBuffer())
    const actual = { path: file.path, bytes: bytes.length, sha256: sha256(bytes) }
    requireEvidence(actual.bytes === file.bytes && actual.sha256 === file.sha256,
      `Deployment differs from this build: ${file.path}`)
    files.push(actual)
  }
  return { version: 1, ...identity, pageUrl: base, verifiedAt: new Date().toISOString(), files }
}

function testsIn(report) {
  requireEvidence(report && Array.isArray(report.suites) && Array.isArray(report.errors)
    && report.errors.length === 0, 'Missing, malformed or errored browser report')
  const tests = []
  function visit(suites, parents = []) {
    for (const suite of suites) {
      requireEvidence(Array.isArray(suite.specs), 'Malformed browser suite')
      for (const spec of suite.specs) {
        requireEvidence(typeof spec.file === 'string' && typeof spec.title === 'string'
          && Array.isArray(spec.tests) && spec.tests.length > 0, 'Malformed browser spec')
        for (const test of spec.tests) {
          requireEvidence(typeof test.projectName === 'string', 'Missing browser project identity')
          tests.push({ key: JSON.stringify([spec.file, ...parents, suite.title, spec.title,
            test.projectName]), spec, test })
        }
      }
      if (suite.suites) visit(suite.suites, [...parents, suite.title])
    }
  }
  visit(report.suites)
  requireEvidence(tests.length > 0 && new Set(tests.map((test) => test.key)).size === tests.length,
    'Empty or duplicate browser membership')
  return tests
}

export function verifyReport(discovery, report, exitCode) {
  requireEvidence(exitCode === 0, 'Browser process did not succeed')
  const expected = testsIn(discovery), actual = testsIn(report)
  requireEvidence(expected.length === 24, 'Unexpected original full-suite membership; review the gate')
  const keys = new Set(expected.map((test) => test.key))
  requireEvidence(actual.length === expected.length && actual.every((test) => keys.has(test.key)),
    'Incomplete or changed browser membership')
  requireEvidence(report.stats?.expected === actual.length && report.stats.unexpected === 0
    && report.stats.skipped === 0 && report.stats.flaky === 0, 'Browser results are not fully successful')
  for (const { spec, test } of actual) {
    requireEvidence(spec.ok === true && test.expectedStatus === 'passed' && test.status === 'expected'
      && Array.isArray(test.results) && test.results.length > 0
      && test.results.every((result) => result.status === 'passed' && !result.error
        && (!result.errors || result.errors.length === 0)), 'Failed, skipped, unreadable or unfinished test')
  }
  return { verifiedAt: new Date().toISOString(), expected: expected.length, passed: actual.length }
}

async function main() {
  const [command, ...args] = process.argv.slice(2)
  if (command === 'capture') {
    const identity = sourceIdentity()
    const manifest = validateManifest({ version: 1, ...identity, files: artifactFiles('dist') }, identity)
    writeFileSync('public-build-evidence.json', `${JSON.stringify(manifest, null, 2)}\n`)
    requireEvidence(process.env.GITHUB_OUTPUT, 'Missing workflow output destination')
    appendFileSync(process.env.GITHUB_OUTPUT, `evidence=${JSON.stringify(manifest)}\n`)
  } else if (command === 'files') {
    const identity = sourceIdentity()
    const manifest = JSON.parse(process.env.EXPECTED_DEPLOYMENT_EVIDENCE)
    const results = await verifyFiles(manifest, identity, process.env.PUBLIC_DEPLOYMENT_URL)
    writeFileSync('public-file-results.json', `${JSON.stringify(results, null, 2)}\n`)
  } else if (command === 'report') {
    const results = verifyReport(JSON.parse(readFileSync(args[0], 'utf8')),
      JSON.parse(readFileSync(args[1], 'utf8')), Number(args[2]))
    writeFileSync('public-verification-results.json', `${JSON.stringify({ ...sourceIdentity(),
      pageUrl: deploymentUrl(process.env.PUBLIC_DEPLOYMENT_URL), ...results }, null, 2)}\n`)
    console.log(JSON.stringify(results))
  } else throw new Error('Use capture, files or report')
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch((error) => {
    writeFileSync('public-verification-error.json', `${JSON.stringify({ completed: false,
      stage: process.argv[2], expectedSourceSha: process.env.GITHUB_SHA ?? null,
      recordedAt: new Date().toISOString(), error: error.message }, null, 2)}\n`)
    console.error(error.message)
    process.exitCode = 1
  })
}
