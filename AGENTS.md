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

## Workflow

- `make fmt`   — format the workspace.
- `make lint`  — run clippy with `-D warnings`.
- `make test`  — run the full test suite.
- Update this file whenever a new convention is agreed.
