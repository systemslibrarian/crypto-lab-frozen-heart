import './style.css'
import {
  G,
  mulG,
  randomScalar,
  encodePoint,
  encodeScalar,
  bytesToHex,
  type Scalar,
  type Point,
} from './schnorr/group'
import { keygen, commit, respond, prove } from './schnorr/prover'
import { verify } from './schnorr/verify'
import { challenge } from './schnorr/fiatshamir'
import { forgeAgainstTarget, mintUnboundStatement } from './schnorr/forge'
import { buildLadder, evaluateRung, type RungKey } from './schnorr/ladder'
import { judge } from './schnorr/verdict'
import { STRONG_FIELDS, type TranscriptFields, type Statement, type Proof } from './schnorr/types'

const enc = new TextEncoder()

/* ------------------------------- tiny DOM kit ------------------------------- */
type Attrs = Record<string, string | boolean | number | undefined>
function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Attrs = {},
  children: (Node | string)[] = [],
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag)
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === false) continue
    if (k === 'class') node.className = String(v)
    else if (k === 'html') node.innerHTML = String(v)
    else if (v === true) node.setAttribute(k, '')
    else node.setAttribute(k, String(v))
  }
  for (const c of children) node.append(c)
  return node
}
const $ = <T extends HTMLElement>(sel: string): T => document.querySelector(sel) as T

/* --------------------------------- helpers ---------------------------------- */
function hexPoint(p: Point): string {
  return bytesToHex(encodePoint(p))
}
function hexScalar(s: Scalar): string {
  return bytesToHex(encodeScalar(s))
}
/** A monospace hex chip with the full value available on hover / to assistive tech. */
function hexChip(label: string, hex: string): HTMLElement {
  const short = hex.length > 26 ? `${hex.slice(0, 16)}…${hex.slice(-8)}` : hex
  return el('div', { class: 'compare-line', title: hex }, [
    el('span', { class: 'compare-key' }, [label + ' ']),
    el('span', { 'aria-label': `${label} equals ${hex}` }, [short]),
  ])
}

/* ---------------------------------- state ----------------------------------- */
// The forgery target: a public key whose witness the forger never receives.
// We generate it and DISCARD the secret immediately — the forge code below is only ever
// handed `target.pk`, proving the forgery is genuinely witness-free.
const target: Statement = (() => {
  const kp = keygen()
  return kp.statement
})()

// A separate key the *learner* owns, for the honest-path contrast.
const own = keygen()

// The live transcript policy the break-it panel and the formula read from. Starts strong.
const fields: TranscriptFields = { ...STRONG_FIELDS }

/* ---------------------------- named transcript presets ---------------------- */
type PresetTone = 'good' | 'warn' | 'alarm'
interface Preset {
  label: string
  fields: TranscriptFields
  tone: PresetTone
  hint: string
}
const PRESETS: Preset[] = [
  { label: 'Strong', fields: { ...STRONG_FIELDS }, tone: 'good', hint: 'every value bound' },
  { label: 'Drop R', fields: { ...STRONG_FIELDS, R: false }, tone: 'alarm', hint: 'forgery' },
  { label: 'Drop m', fields: { ...STRONG_FIELDS, message: false }, tone: 'warn', hint: 'replay' },
  { label: 'Drop pk', fields: { ...STRONG_FIELDS, pk: false }, tone: 'warn', hint: 'unbound proof' },
  { label: 'Drop G', fields: { ...STRONG_FIELDS, g: false }, tone: 'good', hint: 'harmless here' },
]

/* ------------------------- shareable state via URL hash --------------------- */
function encodeState(): string {
  const letters = (fields.g ? 'g' : '') + (fields.pk ? 'p' : '') + (fields.R ? 'r' : '') + (fields.message ? 'm' : '')
  return `#c=${letters || '-'}&m=${encodeURIComponent(breakState.message)}`
}
function applyStateFromHash(): void {
  const h = location.hash.replace(/^#/, '')
  if (!h) return
  const params = new URLSearchParams(h)
  const c = params.get('c')
  if (c) {
    fields.g = c.includes('g')
    fields.pk = c.includes('p')
    fields.R = c.includes('r')
    fields.message = c.includes('m')
  }
  const m = params.get('m')
  if (m !== null) breakState.message = m
}
function persistState(): void {
  history.replaceState(null, '', encodeState())
}

/* ---------- controller the hero CTA / guided flow drives the break panel with ---------- */
interface BreakController {
  setFields(next: TranscriptFields, animate?: boolean): void
  forge(): void
  reveal(): void
  narrate(text: string, tone: PresetTone | 'info'): void
  clearNarration(): void
}
let breakCtrl: BreakController | null = null
let guideRunning = false
const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms))

/** The guided 60-second path to the exploit — the single highest-leverage entry point. */
async function runGuidedExploit(): Promise<void> {
  if (!breakCtrl || guideRunning) return
  guideRunning = true
  const c = breakCtrl
  try {
    c.reveal()
    await sleep(550)
    c.narrate('Step 1 of 4 — Strong transcript: every public value is inside the hash.', 'good')
    c.setFields({ ...STRONG_FIELDS })
    await sleep(1600)
    c.narrate('Step 2 of 4 — Try to forge Alice’s proof. The real verifier rejects it.', 'info')
    c.forge()
    await sleep(2200)
    c.narrate('Step 3 of 4 — Drop just the commitment R from the hash. Nothing else changes.', 'alarm')
    c.setFields({ ...STRONG_FIELDS, R: false }, true)
    await sleep(2000)
    c.narrate('Step 4 of 4 — Forge again. Same verifier — now it ACCEPTS. Equation HOLDS, verdict ALARM.', 'alarm')
    c.forge()
  } finally {
    guideRunning = false
  }
}

/* ============================================================================
   HERO
   ============================================================================ */
function hero(): HTMLElement {
  const cta = el('button', { type: 'button', class: 'primary cta' }, [
    el('span', { 'aria-hidden': 'true' }, ['▶ ']),
    'Show me the bug',
  ])
  cta.addEventListener('click', () => void runGuidedExploit())
  return el('header', { class: 'cl-hero' }, [
    el('div', { class: 'cl-hero-main' }, [
      el('h1', { class: 'cl-hero-title' }, ['Frozen Heart']),
      el('p', { class: 'cl-hero-sub' }, ['Weak Fiat-Shamir · transcript binding in NIZKs']),
      el('p', { class: 'cl-hero-desc' }, [
        'Runs a real hand-rolled Schnorr proof over ristretto255, turns it non-interactive with Fiat-Shamir, then lets you drop one value from the challenge hash and forge a proof the real verifier accepts.',
      ]),
      el('div', { class: 'cl-hero-cta' }, [
        cta,
        el('span', { class: 'cl-hero-cta-note' }, ['Runs the whole exploit in ~10 seconds, against the real verifier.']),
      ]),
    ]),
    el('aside', { class: 'cl-hero-why', 'aria-label': 'Why it matters' }, [
      el('span', { class: 'cl-hero-why-label' }, ['WHY IT MATTERS']),
      el('p', { class: 'cl-hero-why-text' }, [
        'In 2022 the same one-line mistake — a Fiat-Shamir hash missing part of the transcript — let attackers forge proofs across independent production systems. The proof math was correct; the hash input was one value short.',
      ]),
    ]),
  ])
}

/** Sticky in-page navigator so a long demo feels guided, not scroll-linear. */
function jumpNav(): HTMLElement {
  const links: [string, string][] = [
    ['#sec-transform', 'The transform'],
    ['#sec-break', 'Break the verifier'],
    ['#sec-ladder', 'Omission ladder'],
    ['#sec-audit', 'Audit checklist'],
    ['#sec-frozen', 'Frozen Heart'],
  ]
  return el('nav', { class: 'jump', 'aria-label': 'Jump to section' }, [
    el(
      'ul',
      {},
      links.map(([href, label]) => el('li', {}, [el('a', { href }, [label])])),
    ),
  ])
}

/* ============================================================================
   INTRO — plain language, zero math
   ============================================================================ */
function intro(): HTMLElement {
  return el('section', {}, [
    el('div', { class: 'card' }, [
      el('span', { class: 'section-kicker' }, ['What is this']),
      el('h2', {}, ['A proof that convinces without revealing']),
      el('p', { class: 'lead' }, [
        'A zero-knowledge proof lets you convince someone you know a secret — a password, a private key — without showing it. A "Schnorr proof" does exactly that for a private key. Normally it needs a live back-and-forth: you commit, the verifier throws a random challenge, you answer.',
      ]),
      el('p', { class: 'lead' }, [
        'The ',
        el('strong', {}, ['Fiat-Shamir transform']),
        ' removes the live verifier by replacing that random challenge with a hash. That is what makes proofs postable, on-chain, offline. It is safe only if the hash covers the whole conversation so far. Leave one value out, and the person proving gets to pick the challenge instead of the hash — and can forge a proof for a secret they do not have. This lab lets you cause exactly that failure, against a real verifier.',
      ]),
    ]),
  ])
}

/* ============================================================================
   THE TRANSFORM — the headline mechanism, stepped
   ============================================================================ */
type TMode = 'interactive' | 'noninteractive'
const tState = {
  mode: 'interactive' as TMode,
  step: 0, // 0 none, 1 commit, 2 challenge, 3 respond, 4 verify
  k: 0n as Scalar,
  R: G as Point,
  c: 0n as Scalar,
  s: 0n as Scalar,
}
const TMSG = enc.encode('I know the secret key behind pk')

function transformPanel(): HTMLElement {
  const body = el('div', {})
  const section = el('section', { id: 'sec-transform' }, [
    el('span', { class: 'section-kicker' }, ['The one idea']),
    el('h2', {}, ['Interactive → non-interactive: who chooses the challenge?']),
    el('p', { class: 'lead' }, [
      'Step through a real Schnorr proof of knowledge of a private key. Watch what the Fiat-Shamir transform actually substitutes — the verifier’s coin flip becomes a hash — and note the ordering that keeps it honest: the commitment ',
      el('code', {}, ['R']),
      ' is fixed before the challenge exists.',
    ]),
    el('details', { class: 'notation' }, [
      el('summary', {}, ['New to the notation? Read this first']),
      el('ul', {}, [
        el('li', {}, [
          el('code', {}, ['[k]G']),
          ' — the generator ',
          el('code', {}, ['G']),
          ' added to itself ',
          el('code', {}, ['k']),
          ' times (“scalar multiplication”). Easy to compute forwards; recovering ',
          el('code', {}, ['k']),
          ' from ',
          el('code', {}, ['[k]G']),
          ' is the hard discrete-log problem.',
        ]),
        el('li', {}, [
          el('code', {}, ['pk = [x]G']),
          ' — the public key is the secret ',
          el('code', {}, ['x']),
          ' times ',
          el('code', {}, ['G']),
          '. Knowing ',
          el('code', {}, ['pk']),
          ' does not reveal ',
          el('code', {}, ['x']),
          '.',
        ]),
        el('li', {}, [
          el('code', {}, ['H(…)']),
          ' — a hash (SHA-512 here), reduced ',
          el('code', {}, ['mod L']),
          ', where ',
          el('code', {}, ['L']),
          ' is the group’s size; ',
          el('code', {}, ['mod L']),
          ' just means “wrap around” at ',
          el('code', {}, ['L']),
          '.',
        ]),
      ]),
    ]),
    el('div', { class: 'card' }, [
      el('div', { class: 'btn-row', role: 'group', 'aria-label': 'Protocol mode' }, [
        modeButton('interactive', 'Interactive (live verifier)'),
        modeButton('noninteractive', 'Non-interactive (Fiat-Shamir)'),
      ]),
      body,
      el('details', {}, [
        el('summary', {}, ['Wait — isn’t this just a Schnorr signature?']),
        el('p', {}, [
          'Almost exactly. A Schnorr signature ',
          el('em', {}, ['is']),
          ' this proof with the message folded into the challenge: ',
          el('code', {}, ['c = H(…, R, m)']),
          ', and the signature is the pair ',
          el('code', {}, ['(R, s)']),
          '. So “which values go in the hash” is not an abstract question — it is the difference between a signature scheme that binds the signer and public key and one an attacker can forge. Real schemes such as EdDSA and BIP-340 also bind the public key into the hash for exactly the reasons this lab demonstrates.',
        ]),
      ]),
    ]),
  ])
  renderTransform(body)
  return section
}

function modeButton(mode: TMode, label: string): HTMLButtonElement {
  const b = el('button', { type: 'button', 'aria-pressed': String(tState.mode === mode) }, [label])
  if (tState.mode === mode) b.classList.add('primary')
  b.addEventListener('click', () => {
    if (tState.mode === mode) return
    tState.mode = mode
    tState.step = Math.min(tState.step, 1) // keep commit, redo challenge under new rule
    renderApp()
  })
  return b
}

/**
 * The interactive sequence diagram — one graphic that IS the stepper. Stepping lights up
 * the active message and reveals its real value in place; toggling the mode morphs the
 * Verifier lane into a Hash box and the returned-challenge arrow into a value the hash
 * computes on its own side. It is a single graphic (role="img") with a text alternative;
 * live values and the current-step prose are announced through a separate status region.
 * All motion is tied to the Next button and the mode toggle — never idle.
 */
function flowDiagram(mode: TMode, step: number): HTMLElement {
  const ni = mode === 'noninteractive'
  const desc = ni
    ? 'Sequence diagram. The prover sends commitment R to the hash side. The challenge c is computed as H of G, pk, R and the message — by the hash, not sent as a message. The prover sends response s. Because R is inside the hash, the challenge still depends on the committed R.'
    : 'Sequence diagram. The prover sends commitment R to the verifier. The verifier sends back a random challenge c, chosen after seeing R. The prover sends response s.'

  const stateCls = (n: number): string => (step === n ? ' active' : step > n ? ' done' : ' pending')
  const valChip = (v: string | null): Node =>
    v ? el('span', { class: 'flow-val' }, [`${v.slice(0, 14)}…${v.slice(-6)}`]) : document.createTextNode('')

  const msgRow = (
    n: number,
    dir: 'to-right' | 'to-left',
    label: string,
    cap: string,
    value: string | null,
    hl = false,
  ) =>
    el('div', { class: `flow-msg ${dir}${stateCls(n)}` }, [
      el('span', { class: 'flow-node' }),
      el('span', { class: 'flow-line' }, [
        el('span', { class: `flow-chip${hl ? ' hl' : ''}` }, [label]),
        el('span', { class: 'flow-cap' }, [cap]),
        valChip(value),
        el('span', { class: 'flow-arrow', 'aria-hidden': 'true' }, [dir === 'to-right' ? '▶' : '◀']),
      ]),
      el('span', { class: 'flow-node' }),
    ])

  const rVal = step >= 1 ? hexPoint(tState.R) : null
  const cVal = step >= 2 ? hexScalar(tState.c) : null
  const sVal = step >= 3 ? hexScalar(tState.s) : null

  return el('div', { class: `flow${ni ? ' ni' : ''}`, role: 'img', 'aria-label': desc }, [
    el('div', { class: 'flow-lanes', 'aria-hidden': 'true' }, [
      el('div', { class: 'flow-lane' }, [
        el('span', { class: 'flow-actor' }, ['Prover']),
        el('span', { class: 'flow-actor-sub' }, ['knows secret x']),
      ]),
      el('div', { class: 'flow-lane right' }, [
        el('span', { class: 'flow-actor' }, [ni ? 'Hash  H' : 'Verifier']),
        el('span', { class: 'flow-actor-sub' }, [ni ? 'stands in for the verifier' : 'picks a random challenge']),
      ]),
    ]),
    el('div', { class: 'flow-msgs', 'aria-hidden': 'true' }, [
      msgRow(1, 'to-right', 'R = [k]G', 'commit', rVal),
      ni
        ? el('div', { class: `flow-self${stateCls(2)}` }, [
            el('span', { class: 'flow-chip accent' }, ['c = H(G, pk, R, m)']),
            el('span', { class: 'flow-self-note' }, ['computed by the hash — nothing is sent']),
            valChip(cVal),
          ])
        : msgRow(2, 'to-left', 'c', 'random challenge', cVal, true),
      msgRow(3, 'to-right', 's = k + c·x', 'respond', sVal),
    ]),
  ])
}

/** The single, progressive explainer — one step at a time, not four cards at once. */
function stepExplainer(): HTMLElement {
  const ni = tState.mode === 'noninteractive'
  const items: { title: string; body: (Node | string)[] }[] = [
    { title: 'Ready', body: ['Press ', el('strong', {}, ['Start']), ' to run a real proof one move at a time.'] },
    {
      title: 'Step 1 · Prover commits',
      body: [
        'The prover picks a secret nonce ',
        el('code', {}, ['k']),
        ' and publishes ',
        el('code', {}, ['R = [k]G']),
        '. ',
        el('code', {}, ['k']),
        ' never leaves the prover — ',
        el('code', {}, ['R']),
        ' is now locked in.',
      ],
    },
    {
      title: ni ? 'Step 2 · The hash is the challenge' : 'Step 2 · Verifier challenges',
      body: ni
        ? [
            'No verifier to ask: ',
            el('code', {}, ['c = H(G, pk, R, m)']),
            '. Because ',
            el('code', {}, ['R']),
            ' is inside the hash, ',
            el('code', {}, ['c']),
            ' is still pinned to the commitment — the hash faithfully imitates a verifier who moved second.',
          ]
        : [
            'The verifier picks a fresh random ',
            el('code', {}, ['c']),
            ' — ',
            el('em', {}, ['after']),
            ' seeing ',
            el('code', {}, ['R']),
            ', so the prover cannot tune ',
            el('code', {}, ['R']),
            ' to a challenge it already knows.',
          ],
    },
    {
      title: 'Step 3 · Prover responds',
      body: [
        'The prover answers ',
        el('code', {}, ['s = k + c·x  (mod L)']),
        ', folding the private key ',
        el('code', {}, ['x']),
        ' into the nonce. This is the only step that uses the secret.',
      ],
    },
    {
      title: 'Step 4 · Verifier checks',
      body: [
        'The verifier recomputes both sides of ',
        el('code', {}, ['[s]G = R + [c]pk']),
        ' and compares them byte-for-byte — no secret needed to check.',
      ],
    },
  ]
  const it = items[tState.step]
  return el('div', { class: 'step-explainer', role: 'status', 'aria-live': 'polite' }, [
    el('div', { class: 'step-explainer-title' }, [it.title]),
    el('p', { class: 'step-explainer-body' }, it.body),
  ])
}

/**
 * Compute-both-sides-and-compare, not assert (the §2 rule): render both sides of the
 * verification equation in full and colour the byte-for-byte verdict.
 */
function equalityCompare(aHex: string, bHex: string): HTMLElement {
  const holds = aHex === bHex
  return el('div', { class: 'eqcompare', role: 'group', 'aria-label': 'Both sides of the verification equation' }, [
    el('div', { class: 'eq-side' }, [el('span', { class: 'eq-key' }, ['[s]G']), el('span', { class: 'eq-hex' }, [aHex])]),
    el('div', { class: 'eq-side' }, [
      el('span', { class: 'eq-key' }, ['R + [c]pk']),
      el('span', { class: 'eq-hex' }, [bHex]),
    ]),
    el('div', { class: `eq-verdict ${holds ? 'match' : 'nomatch'}` }, [
      el('span', { class: 'badge-icon', 'aria-hidden': 'true' }, [holds ? '=' : '≠']),
      el('span', {}, [holds ? 'Both sides are byte-for-byte identical' : 'The two sides differ']),
    ]),
  ])
}

function renderTransform(body: HTMLElement): void {
  body.replaceChildren()
  body.append(flowDiagram(tState.mode, tState.step))
  body.append(stepExplainer())

  if (tState.step >= 4) {
    const lhs = mulG(tState.s)
    const rhsReal = tState.R.add(own.statement.pk.multiply(tState.c === 0n ? 1n : tState.c))
    const holds = hexPoint(lhs) === hexPoint(rhsReal)
    body.append(
      el('div', { style: 'margin-top:0.9rem' }, [
        equalityCompare(hexPoint(lhs), hexPoint(rhsReal)),
        indicatorPair(judge('honest', holds), holds),
      ]),
    )
  }

  const next = el('button', { type: 'button', class: 'primary' }, [nextLabel()])
  next.disabled = tState.step >= 4
  next.addEventListener('click', () => {
    advanceTransform()
    renderApp()
  })
  const reset = el('button', { type: 'button' }, ['Reset'])
  reset.addEventListener('click', () => {
    tState.step = 0
    renderApp()
  })
  body.append(el('div', { class: 'btn-row', style: 'margin-top:0.9rem' }, [next, reset]))
}

function nextLabel(): string {
  return ['Start: Commit', 'Next: Challenge', 'Next: Respond', 'Next: Verify', 'Done'][tState.step]
}

function advanceTransform(): void {
  const s = tState.step
  if (s === 0) {
    const c = commit()
    tState.k = c.k
    tState.R = c.R
    tState.step = 1
  } else if (s === 1) {
    tState.c =
      tState.mode === 'interactive'
        ? randomScalar()
        : challenge(own.statement.pk, tState.R, TMSG, STRONG_FIELDS)
    tState.step = 2
  } else if (s === 2) {
    tState.s = respond(tState.k, tState.c, own.witness.x)
    tState.step = 3
  } else if (s === 3) {
    tState.step = 4
  }
}


/* ============================================================================
   WHAT IS "TRANSCRIPT" + BREAK IT YOURSELF
   ============================================================================ */
const breakState = {
  message: 'login as alice@bank — session 4f9c',
  result: null as null | {
    proof: Proof
    holds: boolean
    intent: 'honest' | 'forgery'
    note: string
    technique: boolean
    message: string
  },
}

/** Static headline comparison: the identical protocol, one field apart, both run for real. */
function headlineCompare(): HTMLElement {
  const msg = enc.encode('login as alice@bank')
  const strongF = { ...STRONG_FIELDS }
  const weakF = { ...STRONG_FIELDS, R: false }
  const strongForged = verify(target, forgeAgainstTarget(target.pk, msg, strongF).proof!, msg, strongF).equationHolds
  const weakForged = verify(target, forgeAgainstTarget(target.pk, msg, weakF).proof!, msg, weakF).equationHolds
  const col = (tone: 'good' | 'alarm', head: string, formula: string, order: string, outcome: string, forged: boolean) =>
    el('div', { class: `cmp-col ${tone}` }, [
      el('div', { class: 'cmp-head' }, [head]),
      el('div', { class: 'cmp-row' }, [el('span', { class: 'cmp-k' }, ['hash']), el('code', {}, [formula])]),
      el('div', { class: 'cmp-row' }, [el('span', { class: 'cmp-k' }, ['order']), el('span', {}, [order])]),
      el('div', { class: 'cmp-row' }, [
        el('span', { class: 'cmp-k' }, ['forgery']),
        el('span', { class: forged ? 'is-alarm' : 'is-held' }, [
          el('span', { 'aria-hidden': 'true' }, [forged ? '⚠ ' : '✓ ']),
          outcome,
        ]),
      ]),
    ])
  return el('div', { class: 'cmp' }, [
    col('good', 'Strong', 'c = H(G, pk, R, m)', 'R frozen before c', 'verifier REJECTS', strongForged),
    el('div', { class: 'cmp-delta', 'aria-hidden': 'true' }, ['− R']),
    col('alarm', 'Weak', 'c = H(G, pk, m)', 'R solved after c', 'verifier ACCEPTS', weakForged),
  ])
}

function transcriptAndBreak(): HTMLElement {
  const formulaEl = el('div', { class: 'formula', id: 'fs-formula', role: 'status', 'aria-live': 'polite' })
  const orderMount = el('div', { id: 'ordering-mount' })
  const resultMount = el('div', { id: 'break-result' })
  const guideBanner = el('div', { class: 'guide-banner', role: 'status', 'aria-live': 'polite', hidden: true })

  const FIELD_ORDER: [keyof TranscriptFields, string][] = [
    ['g', 'G'],
    ['pk', 'pk'],
    ['R', 'R'],
    ['message', 'm'],
  ]

  // Animated, token-based formula: when a field leaves the hash it visibly drops out.
  function renderFormula(prev?: TranscriptFields): void {
    formulaEl.replaceChildren(document.createTextNode('c = H('))
    const toks: HTMLElement[] = []
    for (const [k, name] of FIELD_ORDER) {
      if (fields[k]) toks.push(el('span', { class: `tok${prev && !prev[k] ? ' adding' : ''}` }, [name]))
      else if (prev && prev[k]) toks.push(el('span', { class: 'tok dropping', 'aria-hidden': 'true' }, [name]))
    }
    toks.forEach((t, i) => {
      if (i > 0) formulaEl.append(document.createTextNode(', '))
      formulaEl.append(t)
    })
    formulaEl.append(document.createTextNode(')'))
    if (prev) setTimeout(() => renderFormula(), 580)
  }
  const renderOrder = (): void => orderMount.replaceChildren(orderingStrip(fields.R))

  const toggleInputs = {} as Record<keyof TranscriptFields, HTMLInputElement>
  const toggleDefs: { key: keyof TranscriptFields; name: string; note: string }[] = [
    { key: 'g', name: 'Generator G', note: 'A fixed public constant of the group.' },
    { key: 'pk', name: 'Public key pk', note: 'The statement — the key you claim to hold.' },
    { key: 'R', name: 'Commitment R', note: 'The value the prover must lock in before the challenge.' },
    { key: 'message', name: 'Message m', note: 'What the proof is about; the context / domain.' },
  ]
  const toggles = el('div', { class: 'field-toggles', role: 'group', 'aria-label': 'Fields included in the challenge hash' })
  for (const d of toggleDefs) {
    const id = `ft-${d.key}`
    const input = el('input', { type: 'checkbox', id }) as HTMLInputElement
    input.checked = fields[d.key]
    toggleInputs[d.key] = input
    input.addEventListener('change', () => {
      const prev = { ...fields }
      fields[d.key] = input.checked
      renderFormula(prev)
      renderOrder()
      breakState.result = null
      renderBreakResult(resultMount)
      persistState()
      updatePresetActive()
    })
    toggles.append(
      el('label', { class: 'field-toggle', for: id }, [
        input,
        el('span', {}, [el('span', { class: 'ft-name' }, [d.name]), ' ', el('span', { class: 'ft-note' }, [d.note])]),
      ]),
    )
  }

  // message input
  const msgId = 'break-msg'
  const msgInput = el('input', { type: 'text', id: msgId, class: 'text-input', value: breakState.message }) as HTMLInputElement
  msgInput.addEventListener('input', () => {
    breakState.message = msgInput.value
    breakState.result = null
    renderBreakResult(resultMount)
    persistState()
  })

  // presets
  const presetRow = el('div', { class: 'presets', role: 'group', 'aria-label': 'Transcript presets' })
  const presetBtns: HTMLButtonElement[] = []
  const setFields = (next: TranscriptFields, animate = false): void => {
    const prev = { ...fields }
    Object.assign(fields, next)
    for (const [k] of FIELD_ORDER) toggleInputs[k].checked = fields[k]
    renderFormula(animate ? prev : undefined)
    renderOrder()
    breakState.result = null
    renderBreakResult(resultMount)
    persistState()
    updatePresetActive()
  }
  function updatePresetActive(): void {
    PRESETS.forEach((p, i) => {
      const match = FIELD_ORDER.every(([k]) => p.fields[k] === fields[k])
      presetBtns[i].setAttribute('aria-pressed', String(match))
      presetBtns[i].classList.toggle('active', match)
    })
  }
  PRESETS.forEach((p) => {
    const b = el('button', { type: 'button', class: `preset tone-${p.tone}`, 'aria-pressed': 'false' }, [
      el('span', { class: 'preset-label' }, [p.label]),
      el('span', { class: 'preset-hint' }, [p.hint]),
    ])
    b.addEventListener('click', () => setFields(p.fields, fields.R && !p.fields.R))
    presetBtns.push(b)
    presetRow.append(b)
  })

  const runForge = (): void => {
    const msg = enc.encode(breakState.message)
    const attempt = forgeAgainstTarget(target.pk, msg, fields)
    const res = verify(target, attempt.proof!, msg, fields)
    breakState.result = {
      proof: attempt.proof!,
      holds: res.equationHolds,
      intent: 'forgery',
      note: attempt.note,
      technique: attempt.techniqueApplies,
      message: breakState.message,
    }
    renderBreakResult(resultMount)
  }
  const forgeBtn = el('button', { type: 'button', class: 'danger' }, ["Forge Alice's proof (you don't have her key)"])
  forgeBtn.addEventListener('click', runForge)

  const honestBtn = el('button', { type: 'button' }, ['Make an honest proof (a key you own)'])
  honestBtn.addEventListener('click', () => {
    const msg = enc.encode(breakState.message)
    const proof = prove(own.statement, own.witness, msg, fields)
    const res = verify(own.statement, proof, msg, fields)
    breakState.result = {
      proof,
      holds: res.equationHolds,
      intent: 'honest',
      note: 'An honest prover who knows the private key. The equation should hold under any policy.',
      technique: false,
      message: breakState.message,
    }
    renderBreakResult(resultMount)
  })

  const copyBtn = el('button', { type: 'button', class: 'ghost' }, ['Copy link to this state'])
  copyBtn.addEventListener('click', () => {
    persistState()
    const done = (t: string): void => {
      copyBtn.textContent = t
      setTimeout(() => (copyBtn.textContent = 'Copy link to this state'), 1600)
    }
    navigator.clipboard?.writeText(location.href).then(
      () => done('Copied ✓'),
      () => done('Copy failed'),
    )
  })

  const section = el('section', { id: 'sec-break' }, [
    el('span', { class: 'section-kicker' }, ['The question the lab exists for']),
    el('h2', {}, ['What, exactly, is "the transcript"?']),
    el('p', { class: 'lead' }, [
      'Fiat-Shamir says: hash the transcript. But which values? Pick a preset — or toggle fields yourself — and try to ',
      el('strong', {}, ['impersonate Alice']),
      ': prove you hold her private key when you do not. The forger is only ever handed Alice’s public key ',
      el('code', {}, [`pk = ${hexPoint(target.pk).slice(0, 12)}…`]),
      '; her secret never exists in the code path.',
    ]),
    el('div', { class: 'card' }, [
      el('h3', {}, ['The one-field difference']),
      headlineCompare(),
    ]),
    el('div', { class: 'card' }, [
      guideBanner,
      el('h3', {}, ['Choose what the challenge hash covers']),
      presetRow,
      el('details', { class: 'custom-transcript' }, [
        el('summary', {}, ['Custom transcript (toggle individual fields)']),
        toggles,
        el('div', { style: 'margin-top:0.8rem' }, [
          el('label', { for: msgId, class: 'field-label' }, ['Message / context m']),
          msgInput,
        ]),
      ]),
      el('div', { style: 'margin-top:0.9rem' }, [formulaEl]),
      orderMount,
      el('div', { class: 'btn-row', style: 'margin-top:0.9rem' }, [forgeBtn, honestBtn, copyBtn]),
      resultMount,
      el('p', { class: 'what-isnt' }, [
        el('strong', {}, ['What a forgery here is and is not: ']),
        'a successful forgery makes the verifier believe you hold a private key you do not. It does ',
        el('strong', {}, ['not']),
        ' recover that key, does ',
        el('strong', {}, ['not']),
        ' break the discrete-log problem, and decrypts nothing. It is an authentication forgery, not key recovery.',
      ]),
    ]),
  ])

  // Register the controller the hero CTA / guided flow drives.
  breakCtrl = {
    setFields,
    forge: runForge,
    reveal: () => section.scrollIntoView({ behavior: 'smooth', block: 'start' }),
    narrate: (text, tone) => {
      guideBanner.hidden = false
      guideBanner.className = `guide-banner tone-${tone}`
      guideBanner.textContent = text
    },
    clearNarration: () => {
      guideBanner.hidden = true
    },
  }

  renderFormula()
  renderOrder()
  renderBreakResult(resultMount)
  updatePresetActive()
  return section
}

function renderBreakResult(mount: HTMLElement): void {
  mount.replaceChildren()
  const r = breakState.result
  if (!r) {
    mount.append(
      el('p', { class: 'indicator-note', style: 'margin-top:0.8rem' }, [
        'Run an attempt to see the two independent indicators.',
      ]),
    )
    return
  }
  const verdict = judge(r.intent, r.holds)
  const kids: (Node | string)[] = [
    indicatorPair(verdict, r.holds, r.intent === 'forgery' && r.holds),
    el('p', { class: 'indicator-note', style: 'margin-top:0.6rem' }, [r.note]),
  ]

  // When the forgery technique applied, show the algebra that produced it — the whole
  // point is that the forgery is arithmetic, not a simulation.
  if (r.intent === 'forgery' && r.technique) {
    const msg = enc.encode(r.message)
    const c = challenge(target.pk, r.proof.R, msg, fields)
    kids.push(
      el('div', { class: 'algebra', role: 'group', 'aria-label': 'Forgery derivation' }, [
        el('div', { class: 'algebra-title' }, ['How the forgery was built — pure algebra, no secret key']),
        algebraLine('①', 's', 'chosen at random', hexScalar(r.proof.s)),
        algebraLine('②', 'c = H(G, pk, m)', 'the hash never sees R, so c is fixed first', hexScalar(c)),
        algebraLine('③', 'R := [s]G − [c]pk', 'solved so the check is forced to pass', hexPoint(r.proof.R)),
        el('p', { class: 'algebra-foot' }, [
          'The verifier recomputes the same ',
          el('code', {}, ['c']),
          ' (it also skips ',
          el('code', {}, ['R']),
          ') and finds ',
          el('code', {}, ['[s]G = R + [c]pk']),
          '. It balances by construction — for a key whose secret the forger never had.',
        ]),
      ]),
    )
  } else {
    kids.push(
      el('div', { class: 'compare', role: 'group', 'aria-label': 'Proof values' }, [
        hexChip('R =', hexPoint(r.proof.R)),
        hexChip('s =', hexScalar(r.proof.s)),
      ]),
    )
  }

  mount.append(el('div', { style: 'margin-top:1rem' }, kids))
}

function algebraLine(n: string, expr: string, note: string, hex: string): HTMLElement {
  const short = hex.length > 26 ? `${hex.slice(0, 14)}…${hex.slice(-6)}` : hex
  return el('div', { class: 'algebra-line' }, [
    el('span', { class: 'algebra-num', 'aria-hidden': 'true' }, [n]),
    el('span', { class: 'algebra-expr' }, [expr]),
    el('span', { class: 'algebra-note' }, [note]),
    el('span', { class: 'algebra-val', title: hex, 'aria-label': `equals ${hex}` }, [short]),
  ])
}

/**
 * The two SEPARATE indicators (constraint A): the raw cryptographic result on the left,
 * the security verdict on the right. Colour tracks integrity, never the return value.
 */
function indicatorPair(
  verdict: ReturnType<typeof judge>,
  equationHolds: boolean,
  flash = false,
): HTMLElement {
  const resultIcon = equationHolds ? '✓' : '✗'
  const resultText = equationHolds ? 'Equation HOLDS' : 'Equation FAILS'
  const resultCls = equationHolds ? 'is-holds' : 'is-fails'

  const vIcon = verdict.integrity === 'alarm' ? '⚠' : verdict.integrity === 'sound' ? '✓' : '🛡'
  const vText = verdict.integrity === 'alarm' ? 'ALARM' : verdict.integrity === 'sound' ? 'SOUND' : 'HELD'
  const vCls = `is-${verdict.integrity}`
  const box = verdict.integrity === 'alarm' ? 'alarm' : verdict.integrity === 'held' ? 'held' : 'good'

  return el('div', { class: 'verdict-row' }, [
    el('div', { class: 'indicator' }, [
      el('div', { class: 'indicator-label' }, ['Cryptographic result']),
      el('div', { class: `indicator-value ${resultCls}` }, [
        el('span', { class: 'badge-icon', 'aria-hidden': 'true' }, [resultIcon]),
        el('span', {}, [resultText]),
      ]),
      el('p', { class: 'indicator-note' }, ['What the verifier’s equation [s]G = R + [c]pk returned.']),
    ]),
    el('div', { class: `indicator ${box}${flash ? ' flash' : ''}` }, [
      el('div', { class: 'indicator-label' }, ['Security verdict']),
      el('div', { class: `indicator-value ${vCls}` }, [
        el('span', { class: 'badge-icon', 'aria-hidden': 'true' }, [vIcon]),
        el('span', {}, [vText]),
      ]),
      el('p', { class: 'indicator-note' }, [verdict.label]),
    ]),
  ])
}

/**
 * The crux, visualised: the temporal order of operations, which reorders the instant you
 * drop R from the hash. With R hashed, R is frozen before c exists. Without it, R is
 * computed last — so the prover, not the hash, decides the outcome.
 */
function orderingStrip(rIncluded: boolean): HTMLElement {
  const steps = rIncluded
    ? ['commit R', 'c = H(…R…)', 'respond s']
    : ['c = H(…)', 'pick s', 'solve R = [s]G − [c]pk']
  const caption = rIncluded
    ? 'R is frozen before the challenge exists — the prover cannot change it afterward.'
    : 'R is computed last, after c and s are chosen — the prover, not the hash, controls the outcome.'
  const cls = rIncluded ? 'good' : 'alarm'
  const stepEls: (Node | string)[] = []
  steps.forEach((label, i) => {
    const last = i === steps.length - 1
    const pill = el('span', { class: `ord-pill${!rIncluded && last ? ' danger' : ''}` }, [
      el('span', { class: 'ord-num', 'aria-hidden': 'true' }, [String(i + 1)]),
      label,
    ])
    stepEls.push(pill)
    if (!last) stepEls.push(el('span', { class: 'ord-sep', 'aria-hidden': 'true' }, ['→']))
  })
  return el('div', { class: `ordering ${cls}`, role: 'group', 'aria-label': 'Order of operations' }, [
    el('div', { class: 'ordering-head' }, [
      el('span', { class: 'ordering-label' }, ['Who moves last?']),
      el('span', { class: `ordering-tag ${cls}` }, [rIncluded ? 'sound' : 'forgeable']),
    ]),
    el('div', { class: 'ordering-steps' }, stepEls),
    el('p', { class: 'ordering-caption' }, [caption]),
  ])
}

/* ============================================================================
   THE OMISSION LADDER
   ============================================================================ */
function ladderPanel(): HTMLElement {
  const msg = enc.encode('omission-ladder reference message')
  const rungs = buildLadder(target, msg)

  const list = el('div', { class: 'ladder' })
  for (const rung of rungs) {
    const sevText =
      rung.severity === 'fatal'
        ? 'Fatal'
        : rung.severity === 'unbound'
          ? 'Unbound'
          : rung.severity === 'context-loss'
            ? 'Context loss'
            : 'Sound'
    const sevIcon = rung.severity === 'fatal' ? '⚠' : rung.severity === 'sound' ? '✓' : '◐'
    const outcome = rung.fixedTargetForged
      ? 'Real verifier ACCEPTS a witness-free forgery'
      : 'Real verifier REJECTS the forgery attempt'

    const children: (Node | string)[] = [
      el('div', { class: 'rung-head' }, [
        el('span', { class: 'rung-formula' }, [
          rung.key === 'strong' ? 'strong · ' : `drop ${rung.dropped} · `,
          rung.formula,
        ]),
        el('span', { class: `sev ${rung.severity}` }, [
          el('span', { 'aria-hidden': 'true' }, [sevIcon + ' ']),
          sevText,
        ]),
      ]),
      el('div', { class: 'rung-consequence' }, [
        el('strong', { class: rung.fixedTargetForged ? 'is-alarm' : 'is-held' }, [outcome + '. ']),
        rung.consequence,
      ]),
    ]

    // Give the two non-fatal-but-interesting omissions their own live demonstration.
    if (rung.key === 'dropMessage') children.push(replayDemo(rung.key))
    if (rung.key === 'dropPk') children.push(unboundDemo(rung.key))

    list.append(el('div', { class: 'rung' }, children))
  }

  return el('section', { id: 'sec-ladder' }, [
    el('span', { class: 'section-kicker' }, ['The expert payoff']),
    el('h2', {}, ['The omission ladder — which omissions actually matter']),
    el('p', { class: 'lead' }, [
      'Drop one value from the strong transcript ',
      el('code', {}, ['H(G, pk, R, m)']),
      ' at a time. Not every omission is fatal — and knowing which is which is the difference between a scare story and understanding the bug. Every verdict below is the real verifier speaking, computed live.',
    ]),
    el('div', { class: 'card' }, [
      list,
      el('details', {}, [
        el('summary', {}, ['A note on the textbook phrase “weak Fiat-Shamir = c = H(R)”']),
        el('p', {}, [
          'Weak Fiat-Shamir is often written ',
          el('code', {}, ['c = H(R)']),
          ' — hashing only the commitment and omitting the statement. That phrasing captures the ',
          el('strong', {}, ['drop pk']),
          ' rung above: it breaks ',
          el('em', {}, ['binding']),
          ' (adaptive soundness — Bernhard–Pereira–Warinschi, 2012), but it does ',
          el('strong', {}, ['not']),
          ' let you forge against a chosen victim key, because ',
          el('code', {}, ['R']),
          ' is still hashed and the challenge stays circular.',
        ]),
        el('p', {}, [
          'The ',
          el('em', {}, ['universal']),
          ' forgery — pick ',
          el('code', {}, ['s']),
          ', solve ',
          el('code', {}, ['R = [s]G − [c]pk']),
          ' — needs the challenge to be fixed ',
          el('em', {}, ['before']),
          ' R exists, which happens only when the ',
          el('strong', {}, ['commitment R']),
          ' is left out (the ',
          el('strong', {}, ['drop R']),
          ' rung). This lab uses the drop-R construction for its headline forgery precisely so the “choose s, solve for R” attack is genuine and not a simulation. Knowing which omission does which is the whole point.',
        ]),
      ]),
    ]),
  ])
}

function replayDemo(_key: RungKey): HTMLElement {
  const out = el('div', { class: 'compare', role: 'status', 'aria-live': 'polite' })
  const btn = el('button', { type: 'button', style: 'margin-top:0.5rem' }, ['See the replay'])
  btn.addEventListener('click', () => {
    const f = evaluateRung('dropMessage', target, enc.encode('x')).fields
    const m1 = enc.encode('pay Alice 5')
    const m2 = enc.encode('pay Mallory 5000')
    const honest = prove(own.statement, own.witness, m1, f)
    const okM1 = verify(own.statement, honest, m1, f).equationHolds
    const okM2 = verify(own.statement, honest, m2, f).equationHolds
    out.replaceChildren(
      el('div', { class: 'compare-line' }, [
        el('span', { class: 'compare-key' }, ['“pay Alice 5” ']),
        el('span', { class: okM1 ? 'is-holds' : 'is-fails' }, [okM1 ? '✓ accepted' : '✗ rejected']),
      ]),
      el('div', { class: 'compare-line' }, [
        el('span', { class: 'compare-key' }, ['same proof, “pay Mallory 5000” ']),
        el('span', { class: okM2 ? 'is-alarm' : 'is-held' }, [okM2 ? '⚠ ALSO accepted — replayed' : '✓ rejected']),
      ]),
    )
  })
  return el('details', {}, [el('summary', {}, ['Demonstrate: replay across messages']), btn, out])
}

function unboundDemo(_key: RungKey): HTMLElement {
  const out = el('div', { class: 'compare', role: 'status', 'aria-live': 'polite' })
  const btn = el('button', { type: 'button', style: 'margin-top:0.5rem' }, ['See the unbound proof'])
  btn.addEventListener('click', () => {
    const f = evaluateRung('dropPk', target, enc.encode('x')).fields
    const m = enc.encode('I hold some key')
    const minted = mintUnboundStatement(m, f)
    const okMinted = verify({ pk: minted.pk }, minted.proof, m, f).equationHolds
    const attempt = forgeAgainstTarget(target.pk, m, f)
    const okTarget = verify(target, attempt.proof!, m, f).equationHolds
    out.replaceChildren(
      el('div', { class: 'compare-line' }, [
        el('span', { class: 'compare-key' }, ['freshly minted key + proof ']),
        el('span', { class: okMinted ? 'is-alarm' : 'is-held' }, [okMinted ? '⚠ accepted — not bound to any identity' : '✓ rejected']),
      ]),
      el('div', { class: 'compare-line' }, [
        el('span', { class: 'compare-key' }, ["victim's fixed key "]),
        el('span', { class: okTarget ? 'is-alarm' : 'is-held' }, [okTarget ? '⚠ forged' : '✓ still safe — cannot forge a chosen key']),
      ]),
    )
  })
  return el('details', {}, [el('summary', {}, ['Demonstrate: an unbound (key, proof) pair']), btn, out])
}

/* ============================================================================
   FROZEN HEART PANEL + RANDOM ORACLE NOTE
   ============================================================================ */
function frozenHeartPanel(): HTMLElement {
  return el('section', { id: 'sec-frozen' }, [
    el('span', { class: 'section-kicker' }, ['The 2022 disclosures']),
    el('h2', {}, ['Frozen Heart: one bug, many independent systems']),
    el('div', { class: 'card' }, [
      el('p', { class: 'lead' }, [
        'In 2022 Trail of Bits disclosed a family of vulnerabilities it named ',
        el('strong', {}, ['“Frozen Heart.”']),
        ' The same root cause — a Fiat-Shamir challenge computed over an incomplete transcript — appeared independently in implementations of ',
        el('em', {}, ['different']),
        ' proof systems:',
      ]),
      el('ul', {}, [
        el('li', {}, [
          el('strong', {}, ['Girault’s proof of knowledge']),
          ' (a Schnorr-style identification), as used in some threshold-signature libraries.',
        ]),
        el('li', {}, [el('strong', {}, ['Bulletproofs']), ' range-proof implementations.']),
        el('li', {}, [el('strong', {}, ['PlonK']), ' zk-SNARK implementations.']),
      ]),
      el('p', { class: 'lead' }, [
        'These are unrelated codebases by different teams. What united them was that each spec said “hash the transcript,” and each implementer decided for themselves which values that meant — and some left one out. The fix in every case was the same: fold every public input and every commitment into the challenge.',
      ]),
      el('p', { class: 'note' }, [
        'Scope honesty: impact varied by construction and each issue was responsibly disclosed and patched. This lab reproduces the ',
        el('em', {}, ['class']),
        ' of bug on the minimal Schnorr vehicle; it does not reproduce any specific product’s exploit, and the severity of a real deployment depends on how the proof is used.',
      ]),
      el('details', {}, [
        el('summary', {}, ['Why is Fiat-Shamir “sound” at all? (random-oracle model)']),
        el('p', {}, [
          'The Fiat-Shamir transform has a soundness proof, but only in the ',
          el('strong', {}, ['random-oracle model']),
          ' — an idealisation where the hash H is treated as a truly random function that both prover and verifier can only query. That proof assumes the challenge is a random function of the ',
          el('em', {}, ['entire']),
          ' transcript. Omit part of the transcript and you are outside the model the proof covers, which is exactly why these bugs are not caught by “but Fiat-Shamir is proven secure.” Whether SHA-512 is close enough to a random oracle is a separate assumption, not a theorem.',
        ]),
      ]),
      el('details', {}, [
        el('summary', {}, ['References']),
        el('ul', {}, [
          el('li', {}, [
            'Trail of Bits (2022), “Coordinated Disclosure of Vulnerabilities Affecting Girault, Bulletproofs, and PlonK” — the Frozen Heart series (',
            el('a', { href: 'https://blog.trailofbits.com/', rel: 'noopener' }, ['blog.trailofbits.com']),
            ').',
          ]),
          el('li', {}, [
            'Bernhard, Pereira & Warinschi (2012), “How Not to Prove Yourself: Pitfalls of the Fiat–Shamir Heuristic and Applications to Helios,” ASIACRYPT 2012 — the weak-vs-strong Fiat-Shamir distinction.',
          ]),
          el('li', {}, [
            'ristretto255: ',
            el('a', { href: 'https://www.rfc-editor.org/rfc/rfc9496', rel: 'noopener' }, ['RFC 9496']),
            ' (the group and the encoding vectors this lab tests against).',
          ]),
        ]),
      ]),
    ]),
  ])
}

/* ============================================================================
   SCOPE + RELATED DEMOS
   ============================================================================ */
function scopeAndLinks(): HTMLElement {
  const sib = (name: string, label: string) =>
    el('li', {}, [el('a', { href: `https://crypto-lab.systemslibrarian.dev/${name}/`, rel: 'noopener' }, [label])])
  return el('section', {}, [
    el('div', { class: 'card' }, [
      el('span', { class: 'section-kicker' }, ['Honest scoping']),
      el('h2', {}, ['What this demo is not']),
      el('ul', {}, [
        el('li', {}, [
          'Not production cryptography — a teaching demo. Keys and nonces live only in this page’s memory for the session.',
        ]),
        el('li', {}, [
          'Not a SNARK or STARK lab, and no Groth16/PlonK circuit build-out. The Schnorr sigma protocol is the minimal complete vehicle for weak Fiat-Shamir, and that scope is deliberate.',
        ]),
        el('li', {}, ['Not a zero-knowledge introduction — see the sibling ZK demo for that on-ramp.']),
        el('li', {}, [
          'Not a formal random-oracle-model treatment — it is named in one panel, not proved.',
        ]),
      ]),
      el('h3', {}, ['Related demos']),
      el('p', { class: 'lead' }, [
        'Every one of these Fiat-Shamirs something, and so rests on the transcript-binding assumption this lab pokes at:',
      ]),
      el('ul', { class: 'links' }, [
        sib('crypto-lab-zk-proof-lab', 'zk-proof-lab — ZK intro'),
        sib('crypto-lab-ec-point-arithmetic', 'ec-point-arithmetic — the group underneath'),
        sib('crypto-lab-bulletproofs', 'bulletproofs'),
        sib('crypto-lab-snark-arena', 'snark-arena'),
        sib('crypto-lab-stark-tower', 'stark-tower'),
        sib('crypto-lab-zk-arena', 'zk-arena'),
        sib('crypto-lab-mpcith-sign', 'mpcith-sign'),
        sib('crypto-lab-frost-threshold', 'frost-threshold — nonce commitments'),
      ]),
    ]),
  ])
}

/* ============================================================================
   AUDIT PANEL — turn the insight into review behaviour
   ============================================================================ */
function auditPanel(): HTMLElement {
  const codeBlock = (title: string, tone: 'bad' | 'good', lines: string[]) =>
    el('div', { class: `codeblock ${tone}` }, [
      el('div', { class: 'codeblock-title' }, [
        el('span', { 'aria-hidden': 'true' }, [tone === 'bad' ? '✗ ' : '✓ ']),
        title,
      ]),
      el('pre', { tabindex: '0', role: 'group', 'aria-label': title }, [el('code', {}, [lines.join('\n')])]),
    ])
  return el('section', { id: 'sec-audit' }, [
    el('span', { class: 'section-kicker' }, ['For engineers']),
    el('h2', {}, ['How to audit this in real code']),
    el('p', { class: 'lead' }, [
      'The bug never looks dramatic in a diff — it is a missing argument to a hash call. Here is the shape to grep for, and the rule that catches it.',
    ]),
    el('div', { class: 'card' }, [
      el('div', { class: 'grid-2' }, [
        codeBlock('Vulnerable — commitment omitted', 'bad', [
          '// challenge left the commitment R out',
          'c = H(G, pk, msg)',
          's = k + c*x',
          '// prover can now pick s first and',
          '// solve R = [s]G - [c]pk  → forgery',
        ]),
        codeBlock('Fixed — bind the whole transcript', 'good', [
          '// every public value AND the commitment',
          'c = H(G, pk, R, msg)',
          's = k + c*x',
          '// R is pinned before c exists;',
          '// no back-solving is possible',
        ]),
      ]),
      el('h3', {}, ['Checklist: what the Fiat-Shamir challenge must bind']),
      el('ul', { class: 'checklist' }, [
        el('li', {}, [
          el('strong', {}, ['Every prover commitment.']),
          ' Missing one is catastrophic — universal forgery. This is the Frozen Heart bug.',
        ]),
        el('li', {}, [
          el('strong', {}, ['The full statement / all public inputs']),
          ' (here, ',
          el('code', {}, ['pk']),
          '). Missing it unbinds the proof from any particular instance.',
        ]),
        el('li', {}, [
          el('strong', {}, ['The message / context, with domain separation.']),
          ' Missing it permits cross-context replay.',
        ]),
        el('li', {}, [
          el('strong', {}, ['A domain-separation tag']),
          ' so a challenge from one protocol can never be reused in another.',
        ]),
        el('li', {}, [
          el('strong', {}, ['Not every omission is equal.']),
          ' A missing commitment forges; a missing message replays; a missing statement unbinds. Triage by which value left the hash.',
        ]),
      ]),
    ]),
  ])
}

/* ============================================================================
   MOUNT
   ============================================================================ */
function renderApp(): void {
  const app = $('#app')
  app.replaceChildren(
    hero(),
    jumpNav(),
    intro(),
    transformPanel(),
    transcriptAndBreak(),
    ladderPanel(),
    auditPanel(),
    frozenHeartPanel(),
    scopeAndLinks(),
  )
}

applyStateFromHash()
renderApp()

// sanity marker for the a11y harness / manual checks that JS mounted
document.documentElement.setAttribute('data-app-ready', 'true')
