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

- [x] `mia` binary refuses to start when IMA is not enforced.
      (`mia::hardening::harden` fails closed unless `/proc/cmdline` carries
      `ima_appraise=enforce`; the parser `ima_cmdline_enforced` is unit-tested.
      `FERROGATE_REQUIRE_IMA=0` is a documented dev-only override.)
- [x] seccomp violation in a fuzzed handler kills the process; verified by
      a unit test that triggers a forbidden syscall.
      (`ferro_harden::linux::tests::seccomp_enforce_kills_forbidden_syscall`
      installs the enforcing allow-list in a forked child, calls a syscall not
      on the list, and asserts the child died from `SIGSYS`. Runs unprivileged.)
- [x] Reproducible build: two independent builds yield byte-identical binary
      and matching `bin_sha384`. (`scripts/reproducible-build.sh` + the
      `reproducible-build` CI job build `mia` twice with path remapping,
      `--build-id=none`, and pinned `SOURCE_DATE_EPOCH`/locale/TZ, then compare
      SHA-384.)
- [x] `mlockall` succeeds; if it fails, MIA exits non-zero.
      (`ferro_harden::apply` runs `mlockall(MCL_CURRENT|MCL_FUTURE)` first and
      returns a fatal `HardenError::Mlock`; `harden()` propagates it so `main`
      exits non-zero.)
- [x] Capabilities at runtime are exactly `{CAP_IPC_LOCK}`.
      (`restrict_caps_to_ipc_lock` drops the bounding set, sets
      effective/permitted to the single cap, and clears inheritable/ambient;
      `harden()` reads back `effective_capabilities()` and aborts if it is not
      exactly `["CAP_IPC_LOCK"]`.)
- [x] `cargo clippy -- -D warnings` is clean and no `unsafe` blocks exist
      under `crates/mia`. (`#![forbid(unsafe_code)]` on every MIA module; all
      FFI lives in `ferro-harden` / `ferro-winauth`. The `no-unsafe-in-mia` CI
      job greps for unsafe constructs as a belt-and-suspenders gate.)

## Status

**Done.** All hardening syscalls (prctl `PR_SET_NO_NEW_PRIVS` /
`PR_SET_DUMPABLE` / `PR_SET_KEEPCAPS`, `mlockall`, `setgroups`/`setgid`/`setuid`,
capability restriction, seccomp-bpf via `seccompiler`) live in the new
`ferro-harden` crate — the Linux analogue of `ferro-winauth` — so `mia` stays
`#![forbid(unsafe_code)]`. `main` applies the profile on the startup thread
before the tokio runtime spawns workers (so the filter is inherited and
`MCL_FUTURE` covers their allocations) and before any TPM/network I/O. Env
toggles (`FERROGATE_SECCOMP=enforce|audit|off`, `FERROGATE_SKIP_HARDENING`,
`FERROGATE_REQUIRE_IMA`, `FERROGATE_RUN_AS_UID/GID`) cover staged rollout and
the dev "audit" mode. The Linux paths are verified by `cargo test -p
ferro-harden` (including the live `SIGSYS` self-test) run in CI / the
`rust:1.88-bookworm` container. A static-PIE musl build that statically links
TSS2 is left as deployment packaging; the reproducibility gate runs on the
default glibc build, which is PIE by default.

## Risks

- **Syscall set churn.** A glibc / kernel update may need a new syscall.
  Mitigation: log-only "audit" mode in development to discover drift before
  rollout.
- **Reproducibility regressions.** Mitigation: lockfile committed, vendored
  build container.
