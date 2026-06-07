# Platform → Module Auth: Per-Tunnel Service Token

## Problem

Platform calls modules via tunnel (lifecycle install, RPC). Today uses `MS_INTERNAL_SECRET` shared symmetric key. Breaks because CLI generates a random one for compose while the platform has a different one.

## Design

Use the **`stk_*` service token** already minted by dispatch during tunnel registration. Platform-minted, per-tunnel, delivered through the authenticated WSS channel.

### Flow

```
mirrorstack dev --tunnel
  → CLI registers tunnel via WSS (authenticated by user OAuth)
  → dispatch mints stk_* token, stores in session, returns in register_ack
  → CLI receives stk_*, passes as MS_PLATFORM_TOKEN to compose env
  → module SDK reads MS_PLATFORM_TOKEN from env

Platform → Module request
  → lifecycle client looks up stk_* from tunnel session (Redis)
  → sends as X-MS-Platform-Token header
  → SDK validates via constant-time compare against MS_PLATFORM_TOKEN env
```

### Changes

**api-platform** (3 files):
1. `internal/dispatch/ws/sessions.go` — add `ServiceToken` to Session struct
2. `internal/dispatch/ws/handlers.go` — store service token in session during handleRegister
3. `internal/applications/service/module_lifecycle.go` — read service token from session, send as `X-MS-Platform-Token`

**app-module-sdk** (1 file):
1. `auth/middleware.go` — `InternalAuth` checks `X-MS-Platform-Token` against `MS_PLATFORM_TOKEN` env. Fallback to `MS_INTERNAL_SECRET` for backward compat.

**mirrorstack-cli** (2 files):
1. `src/commands/dev/tunnel.rs` — expose `service_token` from `RegisterAck` on `TunnelHandle`
2. `src/commands/dev/mod.rs` — pass `MS_PLATFORM_TOKEN` from tunnel handles to compose env. Remove `MS_INTERNAL_SECRET` generation.

### Build Order

1. api-platform: store + expose service token
2. app-module-sdk: validate `X-MS-Platform-Token`
3. mirrorstack-cli: pass token through to compose
