# Havoc Improvement Index

This directory contains all improvement proposals, feature specifications, and enhancement plans for the Havoc C2 framework. Each document describes a concrete, self-contained change: its motivation, design, affected files, and verification steps. Items progress from `Pending` through `In Progress` to `Applied`; once applied, the entry is moved to `CHANGES.md` and its status here is updated to `Applied`.

## Master Index

| ID | Title | Area | Priority | Status | Doc |
|----|-------|------|----------|--------|-----|
| HVC-013 | Raw TCP Transport | Transport | High | Pending | [01-transport-tcp.md](01-transport-tcp.md) |
| HVC-028 | DNS-over-HTTPS Transport | Transport | Medium | Pending | [02-transport-doh.md](02-transport-doh.md) |
| HVC-029 | Wire Encoding Module Refactor | Architecture | High | Pending | [03-traffic-encoding-module.md](03-traffic-encoding-module.md) |
| HVC-030 | Sleep Obfuscation Enhancements | Evasion | High | Pending | [04-sleep-obfuscation.md](04-sleep-obfuscation.md) |
| HVC-031 | Evasion Enhancements (ETW, Module Hide, Anti-Debug) | Evasion | High | Pending | [05-evasion-enhancements.md](05-evasion-enhancements.md) |
| HVC-032 | New Agent Commands (Lateral, Persist, Creds) | Commands | High | Pending | [06-new-commands.md](06-new-commands.md) |
| HVC-033 | Cryptographic Improvements (KDF, FS, Replay) | Crypto | Medium | Pending | [07-crypto-improvements.md](07-crypto-improvements.md) |
| HVC-034 | Listener Enhancements (jitter, mTLS, fake bodies) | Listener | Medium | Pending | [08-listener-enhancements.md](08-listener-enhancements.md) |
| HVC-035 | Teamserver Operator UX (RBAC, audit log, tags) | Teamserver | Medium | Pending | [09-teamserver-ux.md](09-teamserver-ux.md) |
| HVC-036 | Injection Engine Improvements | Injection | Low | Pending | [10-injection-improvements.md](10-injection-improvements.md) |

## Template

All improvement docs in this directory follow this standard template:

```
## Status
Pending / In Progress / Applied

## Problem
What gap this fills (1-3 sentences).

## Scope
Files to be modified (Demon side, Teamserver side, Client side, Tests).

## Design
Concrete implementation approach: function signatures, data structures, wire format.

## File Map
| File | Change |
|------|--------|
| ...  | ...    |

## Tests
How to verify the change works.

## Notes
Trade-offs, risks, open questions.
```

## Convention

- Improvement docs go in `improvement-docs/` at repo root — this is the only correct location for specs, proposals, and designs.
- HVC numbers are assigned sequentially from `CHANGES.md` (currently at HVC-027; new items start at HVC-028).
- Each file is named `NN-kebab-title.md` where `NN` is a two-digit sequence number within this directory (not the HVC number).
- Status values: `Pending` / `In Progress` / `Applied`.
- When an improvement is implemented, move its entry to `CHANGES.md` and update Status here to `Applied`.
- Do not place improvement specs in root-level markdown files or in memory files.
