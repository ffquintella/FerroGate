# F12 — MIA Process Hardening

## Summary

The MIA is a static-PIE Rust binary that applies a defence-in-depth profile
at startup before any TPM or network I/O: no-new-privs, dumpable-off,
mlockall, seccomp-bpf allowlist, drop to a dedicated UID with minimal
capabilities, and a kernel-cmdline requirement for enforced IMA.

## Scope

In:

- `prctl(PR_SET_DUMPABLE, 0)`, `prctl(PR_SET_NO_NEW_PRIVS, 1)`.
- `mlockall(MCL_CURRENT | MCL_FUTURE)`.
- seccomp-bpf allowlist (~35 syscalls); explicit allow-list, not deny-list.
- Drop to `_ferrogate` UID with `CAP_IPC_LOCK` only.
- IMA-enforcement check: refuse to start if not active.
- Static-PIE build with reproducible-build flags.
- `unsafe` forbidden in MIA crates (CI gate).

Out:

- LSM modules (SELinux/AppArmor policy is operator-supplied, not built in).
- Anti-debug measures (overlap with kernel ptrace policy).

## Components touched

- `crates/mia`.
- Build configuration (`Cargo.toml`, `rust-toolchain.toml`, CI).

## Dependencies

- None.

## Design notes

See [../mia.md](../mia.md) §"Hardening profile".

## Acceptance criteria

- [ ] `mia` binary refuses to start when IMA is not enforced.
- [ ] seccomp violation in a fuzzed handler kills the process; verified by
      a unit test that triggers a forbidden syscall.
- [ ] Reproducible build: two independent builds yield byte-identical binary
      and matching `bin_sha384`.
- [ ] `mlockall` succeeds; if it fails, MIA exits non-zero.
- [ ] Capabilities at runtime are exactly `{CAP_IPC_LOCK}`.
- [ ] `cargo clippy -- -D warnings` is clean and no `unsafe` blocks exist
      under `crates/mia`.

## Risks

- **Syscall set churn.** A glibc / kernel update may need a new syscall.
  Mitigation: log-only "audit" mode in development to discover drift before
  rollout.
- **Reproducibility regressions.** Mitigation: lockfile committed, vendored
  build container.
