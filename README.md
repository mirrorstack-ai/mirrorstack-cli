# MirrorStack CLI

Official command-line tool for the MirrorStack platform.

## Install

```bash
cargo install --git https://github.com/mirrorstack-ai/mirrorstack-cli
```

Pre-built releases (brew, scoop, deb) coming with the next milestone.

## Commands

```bash
mirrorstack login              # Opens the browser and completes automatically on macOS/Linux
mirrorstack login --no-browser # Sign in on SSH/headless (paste the code shown on the page)
mirrorstack logout             # Revoke the current session and wipe local credentials
mirrorstack whoami             # Print the currently signed-in user
mirrorstack app module init    # Register a new module on the platform
mirrorstack app module rename  # Safely rename a module slug without changing its ID
mirrorstack module deploy      # Cross-compile Linux/arm64, package a bootstrap zip, and upload it
mirrorstack app web deploy     # Deploy a static build directory to app hosting
mirrorstack module capabilities         # Which host slots exist, who fills them, what is broken
mirrorstack module capabilities --json  # …the same index, machine-readable
mirrorstack module capabilities --app @me/my-app  # …resolved against the app's installed versions
mirrorstack module move --app my-app --module media             # Pick a published version to move that install onto
mirrorstack module move --app my-app --module media --to 0.2.0  # …or name it outright
mirrorstack --help             # Show help
mirrorstack --version          # Show CLI version
```

## Deploy tokens

Create a token in the app's deployment settings on the platform. Its value is
shown exactly once and does not expire.

```bash
export MIRRORSTACK_TOKEN=...
mirrorstack apps web deploy --app <slug> --dir out
```

Revoke the token when it is no longer needed.

## Local development

Build:

```bash
cargo build
cargo test
```

Run against local services. Easiest is a `.env` file in the project
root — copy `.env.example` and edit:

```bash
cp .env.example .env
cargo run -- login
```

Or set the env vars per-invocation (these always win over `.env`):

```bash
MIRRORSTACK_API_URL=http://localhost:8081 \
MIRRORSTACK_WEB_URL=http://localhost:3000 \
cargo run -- login
```
