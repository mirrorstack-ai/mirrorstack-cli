# MirrorStack CLI

Scaffold, develop, and deploy MirrorStack modules.

## Install

```bash
cargo install --git https://github.com/mirrorstack-ai/mirrorstack-cli
```

Pre-built releases (brew, scoop, deb) coming with the next milestone.

## Commands

```bash
mirrorstack login                       # Sign in via OAuth (PKCE)
mirrorstack app module init <name>      # Scaffold a new module
mirrorstack --help                      # Show help
mirrorstack --version                   # Show CLI version
```

## Quick start

```bash
mirrorstack login
mirrorstack app module init my-module
cd my-module
# Edit api/, web/, sql/ as needed
```

## Local development

Build:

```bash
cargo build
cargo test
```

Run against local services:

```bash
MIRRORSTACK_API_URL=http://localhost:8081 \
MIRRORSTACK_WEB_URL=http://localhost:3000 \
cargo run -- login
```
