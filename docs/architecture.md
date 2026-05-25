# OnionBird Architecture

## Hybrid: MailExtension + Experiments API

The privileged operations that OnionBird needs (writing `Services.prefs`,
manipulating `nsIMsgIdentity` and `nsISmtpServer`) are NOT available to
pure WebExtension code. Thunderbird MailExtensions are sandboxed and
restricted to a declarative API surface that excludes most of the
fingerprint-defense vectors.

The way around this is the **Experiments API** — a Thunderbird-specific
extension mechanism that lets an addon ship its own privileged
ES module which runs in the parent process and exposes a custom
WebExtension namespace.

```
┌────────────────────────────────────────────────────────────┐
│ MailExtension sandbox (child process)                      │
│                                                            │
│   background.js                                            │
│     ├── browser.runtime.onMessage  (options page IPC)      │
│     ├── browser.compose.onBeforeSend  (header hooks)       │
│     └── browser.onionbird.*    ◄── custom namespace ──┐     │
│                                                      │     │
└──────────────────────────────────────────────────────┼─────┘
                                                       │
                                                       │ JSON-RPC
                                                       ▼
┌────────────────────────────────────────────────────────────┐
│ Parent process — Experiments API implementation            │
│                                                            │
│   experiments/onionbird/implementation.js                   │
│     ├── ExtensionAPI subclass                              │
│     ├── Services.prefs.set*/get*                           │
│     ├── MailServices.smtp.servers iteration                │
│     ├── MailServices.accounts.allIdentities iteration      │
│     └── (future) nsIMsgCompose hooks                       │
│                                                            │
└────────────────────────────────────────────────────────────┘
```

### Why the split

- **Background script** owns user-visible logic, options-page IPC, and
  things expressible in standard WebExtension APIs.
- **Experiments script** owns the operations that require XPCOM /
  `Services.*` access.

If MailExtensions ever expose enough surface to do everything we need,
the experiments layer shrinks. Until then, it's load-bearing.

## Why MV2 first

Thunderbird 140 ESR accepts MV2 *and* MV3 manifests, but the Experiments
API schema differs between them and MV2 documentation is more stable.
The plan migrates to MV3 in Phase 7 once the feature set has settled.

## Test architecture

```
┌──────────┐       ┌──────────┐      ┌──────────┐
│ runner   │──────►│ thunder- │      │ smtp-    │
│ pytest   │ M'ette│ bird     │      │ trap     │
│ helpers  │       │ Xvfb+TB  │      │ aiosmtpd │
└──┬───────┘       └────┬─────┘      └────▲─────┘
   │ HTTP                │ SOCKS5          │ via .onion
   │                     ▼                 │
   │              ┌──────────┐     ┌───────┴──┐
   ├─────────────►│ dns-trap │     │ tor      │
   │      HTTP    │ dnslib   │     │ + Hidden │
   │              └──────────┘     │ Service  │
   │                               └──────────┘
   │
   └── all in podman compose network t0net ──┘
```

**Key property**: the SMTP capture server is reachable ONLY via the
Tor onion service. If a TB-issued SMTP connection arrives at smtp-trap,
we know with certainty it went through Tor. This is the load-bearing
"SOCKS routing actually works" assertion.

**DNS leak detection**: dns-trap is the configured DNS server in some
test scenarios. With `socks_remote_dns=true`, `.onion` hostnames are
never queried via DNS (they're resolved by Tor itself). If dns-trap
sees a query for the onion address, we have a leak.

## Companion `user.js`

The addon loads asynchronously *after* Thunderbird starts. Between
launch and addon load, TB may issue DNS probes (autoconfig, update
checks). The companion `user.js` lives in the profile directory and
is applied at profile-load time, before any network activity. It
covers the "safe regardless of network config" subset of hardening
prefs; the addon enforces the Tor-specific prefs at runtime.

Both are best-effort against a determined adversary. The threat model
explicitly excludes pre-load races as a fully-solvable problem within
the addon model.
