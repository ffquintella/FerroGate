# AI Agent Instructions — FerroGate

This project was scaffolded by `ironroot`. AI assistants working on it
should follow the conventions below in addition to the upstream
[IronRoot AGENTS.md](https://github.com/ffquintella/IronRoot/blob/main/ai/AGENTS.md).

## Project shape

- Kind     : CLI tool
- Database : MySQL

## House rules

1. **Prefer composition over inheritance** — use traits and generics; avoid
   deep type hierarchies.
2. **Keep `main.rs` thin** — wire dependencies and delegate to library code.
3. **One concern per module.** Domain logic and I/O do not mix.
4. **No silent breaking changes.** Bump versions, mark deprecations.
5. **Document every public item** with `///` doc comments.
6. **Tests are non-optional.** Every new feature ships with at least one test.
7. **`unsafe` is forbidden** unless justified inline with a `// SAFETY:` note.

## Skills

AI assistants that support skills (e.g. Claude Code) must use the
following ones on this repository:

- **`agent-router`** — invoke it *before starting* any request to
  implement, fix, refactor, test, review, investigate, document or plan
  something, even when the task looks small. It decides whether the work
  stays inline or is delegated, and to which agent, model and effort
  level. Follow its decision; when it delegates, give the chosen agent a
  self-contained prompt and verify its result before reporting back.
- **`fgv-desenvolvimento-seguro`** (secure programming) — apply it
  whenever code or design is written or reviewed, and always when the
  change touches authentication, authorization, secrets, key material,
  cryptography, attestation, logging/auditing, personal data (LGPD),
  integrations, dependency updates or a security incident. Given what
  FerroGate does (TEE sealing, attestation, SVID issuance, ceremonies),
  assume most changes fall in scope. Security findings from the skill
  are blocking: fix them or record the justification in the PR.

The two compose: `agent-router` picks who does the work; the delegated
agent (or the coordinator, if inline) applies `fgv-desenvolvimento-seguro`
while doing it. Security-sensitive reviews should be routed to the
stronger model tier.

## Workflow

- `make fmt`   — format the workspace.
- `make lint`  — run clippy with `-D warnings`.
- `make test`  — run the full test suite.
- Update this file whenever a new convention is agreed.
