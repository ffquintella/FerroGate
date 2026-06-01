# Formal verification

Machine-checked models of the two protocols whose compromise would be
catastrophic: the four-phase attestation handshake and the hybrid
post-quantum key exchange that carries it. Both are checked by the
`formal-verification` CI job (`.github/workflows/ci.yml`) and reproducible
locally with `make formal`.

| Model | Tool | File | What it proves |
|-------|------|------|----------------|
| Four-phase attestation | [Tamarin](https://tamarin-prover.github.io/) | [`tamarin/attestation.spthy`](tamarin/attestation.spthy) | An SVID is only ever issued to the TPM that actually holds the named EK; quotes cannot be replayed; the residency secret and host key stay secret. |
| Hybrid AKE | [CryptoVerif](https://cryptoverif.inria.fr/) | [`cryptoverif/hybrid_ake.cv`](cryptoverif/hybrid_ake.cv) | The session key stays indistinguishable from random even if X25519 is fully broken, as long as ML-KEM-768 is IND-CCA2 (harvest-now-decrypt-later resistance). |

## Why these two

They map directly onto the threat model (`docs/threat-model.md`):

- **Attestation (Tamarin, symbolic / Dolev-Yao).** Goal G1 (hardware-rooted
  identity) and adversary A5 (malicious peer replaying another node's quote).
  The interesting questions are *authentication and freshness* — exactly what a
  symbolic trace prover is built to answer.
- **Hybrid AKE (CryptoVerif, computational).** Goal G3 (post-quantum + forward
  secrecy) and adversary A4 (a CRQC breaking ECC retroactively). The interesting
  question is *indistinguishability under a partial break* — a probabilistic,
  reduction-style argument, which is CryptoVerif's domain.

## Running locally

```sh
make formal              # runs both provers within the CI budget
make formal-tamarin      # just the attestation proof
make formal-cryptoverif  # just the AKE proof
```

### Installing the provers

Neither tool ships in the Rust toolchain; the CI job installs them, and for
local runs:

- **Tamarin** — `brew install tamarin-prover` (macOS) or the static release
  from the [releases page](https://github.com/tamarin-prover/tamarin-prover/releases).
  Needs `maude` on `PATH`.
- **CryptoVerif** — `opam install cryptoverif`, or build from the
  [distribution](https://cryptoverif.inria.fr/). The `cryptoverif` binary and
  its `cryptoverif.cvl` default library must be reachable.

`make formal` degrades gracefully: if a prover is missing it prints an install
hint and skips that model rather than failing, so a contributor without the
tools installed is not blocked. CI installs both, so the gate is real there.

## Budget

Both proofs are expected to complete well inside the CI time budget
(`FERROGATE_FORMAL_TIMEOUT`, default 600 s each). The Tamarin model is fully
automatic (no interactive oracle); the CryptoVerif model uses the default
proof strategy. If a future protocol change makes a proof exceed the budget,
the CI job fails loudly rather than silently truncating — the timeout is the
signal that the change needs a re-examined proof, not a bumped limit.

## What the models do *not* cover

These are scoped, honest abstractions — see the header comment in each file for
the precise gap to the implementation. In short:

- The composite signature's AND-combiner is abstracted to a single EUF-CMA
  signature (sound under-approximation: the combiner is at least as strong as
  its strongest half).
- PCR/RIM policy admissibility is a public predicate, orthogonal to the
  authentication goal.
- The TLS record layer, HKDF internals, and certificate-chain parsing are
  trusted; the models reason about the protocol structure above them.
