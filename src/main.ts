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

/* ============================================================================
   HERO
   ============================================================================ */
function hero(): HTMLElement {
  return el('header', { class: 'cl-hero' }, [
    el('div', { class: 'cl-hero-main' }, [
      el('h1', { class: 'cl-hero-title' }, ['Frozen Heart']),
      el('p', { class: 'cl-hero-sub' }, ['Weak Fiat-Shamir · transcript binding in NIZKs']),
      el('p', { class: 'cl-hero-desc' }, [
        'Runs a real hand-rolled Schnorr proof over ristretto255, turns it non-interactive with Fiat-Shamir, then lets you drop one value from the challenge hash and forge a proof the real verifier accepts.',
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
  const section = el('section', {}, [
    el('span', { class: 'section-kicker' }, ['The one idea']),
    el('h2', {}, ['Interactive → non-interactive: who chooses the challenge?']),
    el('p', { class: 'lead' }, [
      'Step through a real Schnorr proof of knowledge of a private key. Watch what the Fiat-Shamir transform actually substitutes — the verifier’s coin flip becomes a hash — and note the ordering that keeps it honest: the commitment ',
      el('code', {}, ['R']),
      ' is fixed before the challenge exists.',
    ]),
    el('div', { class: 'card' }, [
      el('div', { class: 'btn-row', role: 'group', 'aria-label': 'Protocol mode' }, [
        modeButton('interactive', 'Interactive (live verifier)'),
        modeButton('noninteractive', 'Non-interactive (Fiat-Shamir)'),
      ]),
      body,
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

function renderTransform(body: HTMLElement): void {
  body.replaceChildren()
  const list = el('ol', { class: 'steps' })

  // Step 1 — commit
  list.append(
    stepCard(1, 'Prover', 'Commit', [
      'Pick a secret random nonce ',
      el('code', {}, ['k']),
      ', send the commitment ',
      el('code', {}, ['R = [k]G']),
      '.',
      tState.step >= 1
        ? el('div', { class: 'compare', role: 'group', 'aria-label': 'Commitment value' }, [
            hexChip('R =', hexPoint(tState.R)),
          ])
        : document.createTextNode(''),
    ]),
  )

  // Step 2 — challenge (the substitution)
  const chalChildren: (Node | string)[] =
    tState.mode === 'interactive'
      ? [
          'The verifier sees ',
          el('code', {}, ['R']),
          ', then throws a fresh random challenge ',
          el('code', {}, ['c']),
          '. Crucially it chooses ',
          el('em', {}, ['after']),
          ' the commitment is locked in.',
        ]
      : [
          'There is no verifier to ask. Fiat-Shamir substitutes ',
          el('code', {}, ['c = H(G, pk, R, m)']),
          ' — the hash plays the verifier. Because ',
          el('code', {}, ['R']),
          ' is inside the hash, the challenge still depends on the already-committed value.',
        ]
  if (tState.step >= 2) {
    chalChildren.push(
      el('div', { class: 'subst' }, [
        el('div', { class: 'compare', role: 'group', 'aria-label': 'Challenge value' }, [
          hexChip(tState.mode === 'interactive' ? 'c (random) =' : 'c = H(…) =', hexScalar(tState.c)),
        ]),
      ]),
    )
  }
  list.append(stepCard(2, 'Verifier → Hash', 'Challenge', chalChildren))

  // Step 3 — respond
  list.append(
    stepCard(3, 'Prover', 'Respond', [
      'Answer with ',
      el('code', {}, ['s = k + c·x  (mod L)']),
      ', where ',
      el('code', {}, ['x']),
      ' is the private key.',
      tState.step >= 3
        ? el('div', { class: 'compare', role: 'group', 'aria-label': 'Response value' }, [
            hexChip('s =', hexScalar(tState.s)),
          ])
        : document.createTextNode(''),
    ]),
  )

  // Step 4 — verify
  const verifyChildren: (Node | string)[] = [
    'Check the equation ',
    el('code', {}, ['[s]G  ==  R + [c]pk']),
    '. Compute both sides and compare byte-for-byte.',
  ]
  if (tState.step >= 4) {
    const lhs = mulG(tState.s)
    // RHS = R + [c]pk, using the real verifier's algebra.
    const rhsReal = tState.R.add(own.statement.pk.multiply(tState.c === 0n ? 1n : tState.c))
    const holds = hexPoint(lhs) === hexPoint(rhsReal)
    verifyChildren.push(
      el('div', { class: 'compare', role: 'group', 'aria-label': 'Both sides of the verification equation' }, [
        hexChip('[s]G       =', hexPoint(lhs)),
        hexChip('R + [c]pk  =', hexPoint(rhsReal)),
      ]),
      indicatorPair(judge('honest', holds), holds),
    )
  }
  list.append(stepCard(4, 'Verifier', 'Verify', verifyChildren))

  body.append(list)

  // Controls
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

function stepCard(
  n: number,
  role: string,
  title: string,
  children: (Node | string)[],
): HTMLLIElement {
  return el('li', { class: 'step', 'data-done': String(tState.step >= n) }, [
    el('div', { class: 'step-role' }, [`Step ${n} · ${role}`]),
    el('div', { class: 'step-title' }, [title]),
    el('div', {}, children),
  ])
}

/* ============================================================================
   WHAT IS "TRANSCRIPT" + BREAK IT YOURSELF
   ============================================================================ */
const breakState = {
  message: 'transfer 100 coins from pk to attacker',
  result: null as null | { proof: Proof; holds: boolean; intent: 'honest' | 'forgery'; note: string },
}

function fieldFormula(): string {
  const parts: string[] = []
  if (fields.g) parts.push('G')
  if (fields.pk) parts.push('pk')
  if (fields.R) parts.push('R')
  if (fields.message) parts.push('m')
  return `c = H(${parts.join(', ') || '∅'})`
}

function transcriptAndBreak(): HTMLElement {
  const formulaEl = el('div', { class: 'formula', id: 'fs-formula', role: 'status', 'aria-live': 'polite' }, [
    fieldFormula(),
  ])
  const resultMount = el('div', { id: 'break-result' })

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
    input.addEventListener('change', () => {
      fields[d.key] = input.checked
      formulaEl.textContent = fieldFormula()
      breakState.result = null
      renderBreakResult(resultMount)
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
  const msgInput = el('input', {
    type: 'text',
    id: msgId,
    value: breakState.message,
    style: 'width:100%;padding:0.5rem 0.7rem;border-radius:8px;',
  }) as HTMLInputElement
  msgInput.style.border = '1px solid var(--border)'
  msgInput.style.background = 'var(--code-bg)'
  msgInput.style.color = 'var(--text)'
  msgInput.addEventListener('input', () => {
    breakState.message = msgInput.value
    breakState.result = null
    renderBreakResult(resultMount)
  })

  const forgeBtn = el('button', { type: 'button', class: 'danger' }, ["Forge a proof for a key you don't own"])
  forgeBtn.addEventListener('click', () => {
    const msg = enc.encode(breakState.message)
    const attempt = forgeAgainstTarget(target.pk, msg, fields)
    const res = verify(target, attempt.proof!, msg, fields)
    breakState.result = {
      proof: attempt.proof!,
      holds: res.equationHolds,
      intent: 'forgery',
      note: attempt.note,
    }
    renderBreakResult(resultMount)
  })

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
    }
    renderBreakResult(resultMount)
  })

  const section = el('section', {}, [
    el('span', { class: 'section-kicker' }, ['The question the lab exists for']),
    el('h2', {}, ['What, exactly, is "the transcript"?']),
    el('p', { class: 'lead' }, [
      'Fiat-Shamir says: hash the transcript. But which values? Toggle what the challenge hash covers and watch the formula change. Then attack a key ',
      el('strong', {}, ['whose private key you do not have']),
      ' — the forger below is only ever handed the public key ',
      el('code', {}, [`pk = ${hexPoint(target.pk).slice(0, 12)}…`]),
      '.',
    ]),
    el('div', { class: 'card' }, [
      el('h3', {}, ['Fields fed into the challenge']),
      toggles,
      el('div', { style: 'margin-top:0.8rem' }, [
        el('label', { for: msgId, style: 'font-size:0.8rem;font-weight:600;display:block;margin-bottom:0.3rem' }, [
          'Message / context m',
        ]),
        msgInput,
      ]),
      el('div', { style: 'margin-top:0.9rem' }, [formulaEl]),
      el('div', { class: 'btn-row', style: 'margin-top:0.9rem' }, [forgeBtn, honestBtn]),
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
  renderBreakResult(resultMount)
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
  mount.append(
    el('div', { style: 'margin-top:1rem' }, [
      indicatorPair(verdict, r.holds),
      el('p', { class: 'indicator-note', style: 'margin-top:0.6rem' }, [r.note]),
      el('div', { class: 'compare', role: 'group', 'aria-label': 'Forged proof values' }, [
        hexChip('R =', hexPoint(r.proof.R)),
        hexChip('s =', hexScalar(r.proof.s)),
      ]),
    ]),
  )
}

/**
 * The two SEPARATE indicators (constraint A): the raw cryptographic result on the left,
 * the security verdict on the right. Colour tracks integrity, never the return value.
 */
function indicatorPair(
  verdict: ReturnType<typeof judge>,
  equationHolds: boolean,
): HTMLElement {
  const resultIcon = equationHolds ? '✓' : '✗'
  const resultText = equationHolds ? 'Equation HOLDS' : 'Equation FAILS'
  const resultCls = equationHolds ? 'is-holds' : 'is-fails'

  const vIcon = verdict.integrity === 'alarm' ? '⚠' : verdict.integrity === 'sound' ? '✓' : '🛡'
  const vText = verdict.integrity === 'alarm' ? 'ALARM' : verdict.integrity === 'sound' ? 'SOUND' : 'HELD'
  const vCls = `is-${verdict.integrity}`
  const box = verdict.integrity === 'alarm' ? 'alarm' : 'good'

  return el('div', { class: 'verdict-row' }, [
    el('div', { class: 'indicator' }, [
      el('div', { class: 'indicator-label' }, ['Cryptographic result']),
      el('div', { class: `indicator-value ${resultCls}` }, [
        el('span', { class: 'badge-icon', 'aria-hidden': 'true' }, [resultIcon]),
        el('span', {}, [resultText]),
      ]),
      el('p', { class: 'indicator-note' }, ['What the verifier’s equation [s]G = R + [c]pk returned.']),
    ]),
    el('div', { class: `indicator ${box}` }, [
      el('div', { class: 'indicator-label' }, ['Security verdict']),
      el('div', { class: `indicator-value ${vCls}` }, [
        el('span', { class: 'badge-icon', 'aria-hidden': 'true' }, [vIcon]),
        el('span', {}, [vText]),
      ]),
      el('p', { class: 'indicator-note' }, [verdict.label]),
    ]),
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

  return el('section', {}, [
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
  return el('section', {}, [
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
   MOUNT
   ============================================================================ */
function renderApp(): void {
  const app = $('#app')
  app.replaceChildren(
    hero(),
    intro(),
    transformPanel(),
    transcriptAndBreak(),
    ladderPanel(),
    frozenHeartPanel(),
    scopeAndLinks(),
  )
}

renderApp()

// sanity marker for the a11y harness / manual checks that JS mounted
document.documentElement.setAttribute('data-app-ready', 'true')
