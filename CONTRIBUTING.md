# Contributing to the MirrorStack CLI

Thanks for helping improve `mirrorstack`. Before you start on an issue, comment
on it with what you plan to change so a maintainer can confirm the approach.
Look for issues labeled
[`good first issue`](https://github.com/mirrorstack-ai/mirrorstack-cli/issues?q=is%3Aopen+label%3A%22good+first+issue%22)
to get started.

## Prerequisites

- A stable Rust toolchain that supports edition 2024 (Rust 1.85 or newer)

## Build and test

Run the same checks as CI:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features
cargo test --all-features
cargo build --release --locked
```

## Pointing the CLI at an API

See [Local development](README.md#local-development). Copy `.env.example` to
`.env` to choose which API the CLI talks to; process environment variables
override `.env`.

## Pull requests

- Branch names: `feat/<issue>-<slug>` or `fix/<issue>-<slug>`.
- Commit prefixes: `feat:`, `fix:`, `docs:`, `refactor:`.
- Reference the issue with `Closes #<issue>`.
- Add or update tests for behavior changes.

## License

By contributing, you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE).
