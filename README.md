# Frozen Heart

**Weak Fiat-Shamir · transcript binding in NIZKs**

A zero-knowledge proof forged for a statement its author cannot prove — because the
challenge hash omitted one value it should have covered. The proof system is correct; the
hash input was one field short. Built as a live, hand-rolled Schnorr proof over
ristretto255 that you can break yourself against the real verifier.

> **Not production cryptography — a teaching demo.** Everything runs in your browser; keys
> and nonces live only in memory for the session and are never persisted or transmitted.

---

## What It Is

A **Schnorr proof of knowledge** of a discrete logarithm, made non-interactive with the
**Fiat-Shamir transform**, over the **ristretto255** prime-order group (RFC 9496). The
prover convinces a verifier it knows the secret key `x` behind a public key `pk = [x]G`,
without revealing `x`.

Fiat-Shamir replaces the verifier's random challenge with a hash of the transcript. It is
sound **only if that hash covers the whole transcript** — every public input and, crucially,
the prover's commitment `R`. Leave `R` out and the prover, not the hash, effectively
chooses the challenge, which enables a genuine algebraic forgery.

- **The primitives are real.** Point arithmetic and canonical encoding come from the
  audited [`@noble/curves`](https://github.com/paulmillr/noble-curves) library; the Schnorr
  prover, verifier, Fiat-Shamir challenge, and the forgeries are hand-rolled here so the
  internals are inspectable (`src/schnorr/`).
- **The forgery is real.** It is a byte-exact algebraic construction — pick the response
  `s`, then solve `R = [s]G − [c]pk` — run against the same verifier an honest proof faces.
  No simulation, no warning banner standing in for a broken check.
- **Security model.** A forged proof is an **authentication forgery**: the verifier is made
  to believe you hold a key you do not. It does **not** recover the secret key, does **not**
  break the discrete-log problem, and decrypts nothing.

## Exhibits

1. **The transform, stepped** — a real Schnorr proof walked through Commit → Challenge →
   Respond → Verify, with a toggle between the interactive protocol (a live verifier throws
   a random challenge) and the non-interactive Fiat-Shamir version (a hash plays the
   verifier). Shows the exact substitution and why the ordering — commit `R` *before* the
   challenge — is what keeps it honest.
2. **What is "the transcript"?** — toggle which of `{G, pk, R, m}` the challenge hash
   covers; the formula `c = H(...)` updates live.
3. **Break it yourself** — forge a proof for a target public key **whose secret you do not
   have** (the forge code is only ever handed the public key). Two **independent**
   indicators are rendered side by side: the raw *cryptographic result* (did the equation
   balance?) and the *security verdict* (SOUND / HELD / ALARM). Under weak Fiat-Shamir you
   see "Equation HOLDS ✓" next to "ALARM ⚠" — a forged proof that verifies is never green.
4. **The omission ladder** — drop each field in turn and see the verdict the *real verifier*
   returns: only dropping the commitment `R` is fatal; dropping the message enables replay;
   dropping the public key leaves proofs unbound to any identity; dropping the generator is
   harmless in one fixed group. Each verdict is computed live, not asserted.
5. **Frozen Heart (2022)** — the Trail of Bits disclosures that hit independent
   implementations of Girault's proof of knowledge, Bulletproofs, and PlonK with the *same*
   root cause, plus a one-panel note on the random-oracle model.

## When to Use It

- **Use it** to build intuition for why "hash the transcript" must mean *the entire*
  transcript, and to see the difference between a fatal omission and a merely sloppy one.
- **Use it** to explain the Frozen Heart bug class to engineers reviewing a Fiat-Shamir
  implementation.
- **Do NOT use it** as a cryptographic library. This is a teaching build: it favours
  transparency over constant-time discipline and side-channel resistance, and it is not
  audited for production. For real Schnorr signatures use a vetted library and a specified
  scheme (e.g. Ed25519 / BIP-340).

## Live Demo

**https://crypto-lab.systemslibrarian.dev/crypto-lab-frozen-heart/**

Step the transform, toggle the transcript fields, and forge a proof the real verifier
accepts — then watch the security verdict alarm even though the equation balances.

## What Can Go Wrong

The lab *is* the "what can go wrong," reproduced honestly:

- **Drop the commitment `R` from the hash → universal forgery.** The challenge is fixed
  before `R` exists, so a forger picks `s` and solves `R = [s]G − [c]pk`, producing a proof
  that verifies for any target key. This is the Frozen Heart pattern.
- **Drop the message `m` → replay.** The proof of knowledge is still sound, but nothing binds
  it to a context; an honest proof replays verbatim under a different message.
- **Drop the public key `pk` → unbound statements.** No fixed-target forgery, but a proof
  is not tied to any particular key: a witness-free `(key, proof)` pair can be minted, so a
  verifying proof says nothing about a pre-existing identity.
- **Precision matters.** A forgery here is authentication-only. Claiming it recovers the
  secret key or breaks discrete log would be false — and the lab is careful never to.

## Real-World Usage

The **Frozen Heart** vulnerabilities (Trail of Bits, 2022) were exactly this bug, found
independently across unrelated codebases: Girault's Schnorr-style proof of knowledge (in
threshold-signature libraries), Bulletproofs range proofs, and PlonK zk-SNARKs. Each spec
said "hash the transcript"; each implementer decided for themselves what that included, and
some left a value out. The fix in every case was to fold every public input and every
commitment into the Fiat-Shamir challenge. Impact varied by construction, and every issue
was responsibly disclosed and patched — this lab reproduces the *class* of bug on the
minimal Schnorr vehicle, not any specific product's exploit.

## How to Run Locally

```bash
npm install
npm run dev        # http://localhost:5173/crypto-lab-frozen-heart/
npm test           # unit tests: KATs, round-trips, forgeries, the omission ladder
npm run build      # type-check + production build to dist/
npm run test:a11y  # axe-core WCAG 2.1 A/AA gate, both themes (needs a built dist/)
```

## Related Demos

Every one of these Fiat-Shamirs something, and so rests on the transcript-binding
assumption this lab pokes at:

- [zk-proof-lab](https://crypto-lab.systemslibrarian.dev/crypto-lab-zk-proof-lab/) — a
  zero-knowledge on-ramp
- [ec-point-arithmetic](https://crypto-lab.systemslibrarian.dev/crypto-lab-ec-point-arithmetic/)
  — the group underneath
- [bulletproofs](https://crypto-lab.systemslibrarian.dev/crypto-lab-bulletproofs/)
- [snark-arena](https://crypto-lab.systemslibrarian.dev/crypto-lab-snark-arena/)
- [stark-tower](https://crypto-lab.systemslibrarian.dev/crypto-lab-stark-tower/)
- [zk-arena](https://crypto-lab.systemslibrarian.dev/crypto-lab-zk-arena/)
- [mpcith-sign](https://crypto-lab.systemslibrarian.dev/crypto-lab-mpcith-sign/)
- [frost-threshold](https://crypto-lab.systemslibrarian.dev/crypto-lab-frost-threshold/) —
  nonce commitments

## Build & Verify

- **49 unit tests** (Vitest), all passing, including **18 known-answer tests**:
  - **16 RFC 9496 ristretto255 vectors** — the canonical encodings of `[0]B`…`[15]B`,
    verifying the group layer is the real ristretto255 bit-for-bit
    (`src/schnorr/group.test.ts`).
  - **2 NIST SHA-512 vectors** — `SHA-512("")` and `SHA-512("abc")`.
- **Correctness** — honest proofs verify (100 randomized round-trips); the verifier rejects
  every tampered response, commitment, message, and wrong key, and rejects out-of-range
  responses fail-closed (`src/schnorr/schnorr.test.ts`).
- **Attack tests** — the weak-Fiat-Shamir forgery is *accepted* by the real verifier across
  50 random targets; the strong transform *rejects* all 50; the omission ladder confirms
  exactly one rung (drop `R`) yields a verifying fixed-target forgery
  (`src/schnorr/forge.test.ts`).
- **Accessibility** — `@axe-core/playwright` scans the production build for zero WCAG 2.1
  A/AA violations in **both** themes; the GitHub Pages deploy is blocked on any failure.

Run everything: `npm test && npm run build && npm run test:a11y`.

## Performance

All operations are single ristretto255 scalar multiplications and one SHA-512 — sub-
millisecond each; the UI recomputes proofs and the full omission ladder synchronously on
every interaction with no perceptible delay.

---

*One of 120+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
