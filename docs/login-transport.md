# Login Transport

MirrorStack CLI uses the custom `mirrorstack://callback` URL scheme by default
where the host operating system supports it. The registered handler invokes the
same CLI binary, which relays the callback to the waiting `mirrorstack login`
process. Out-of-band (OOB) code entry remains available as a fallback.

## Operating-system support

| Operating system | Handler |
| --- | --- |
| macOS | A generated `~/Applications/MirrorStackURL.app` AppleScript applet |
| Linux | A best-effort `~/.local/share/applications/mirrorstack-url.desktop` registration |
| Windows | OOB-only |

The macOS handler bundle is generated locally, so it does not require an Apple
Developer Program fee. It is ad-hoc signed with `codesign -s -`; because the
locally generated bundle is not quarantined, notarization is not required.

## Callback relay

Each login attempt listens on a state-keyed Unix domain socket at
`<config>/mirrorstack/cli/oauth/<state-prefix>.sock` (the filename is a
fixed-length prefix of the login state so the absolute path stays within the
platform `AF_UNIX` limit). The OAuth directory has mode `0700`, and each socket
has mode `0600`. The socket is per-attempt, single-use, and removed after
success or any terminal failure. The browser callback deadline is 180 seconds.

The URL handler invokes `mirrorstack __oauth-deliver <url>` to send the complete
callback URL to that socket. `__oauth-deliver` is an internal, hidden subcommand
and is not intended for direct use.

## OOB fallback

Login falls back to pasting the code shown in the browser when the operating
system is unsupported, handler registration fails, the callback times out, or
the callback state does not match the login attempt. Passing `--no-browser`
forces OOB mode for SSH and other headless environments.
