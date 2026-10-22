# Phase 1 threat model

Assets: exact original bytes; consent scope; private identifiers; timestamps/provenance; accurate uncertainty; operator machine. Trust boundary: all imported bytes and tool output are untrusted. Case operator/host/kernel/interpreter are trusted; no claim to resist root or a malicious same-UID process. No network/device boundary is opened by this release.

| Threat | Control | Residual risk |
|---|---|---|
| Archive traversal/bombs/symlinks | No extraction; archive signatures unsupported; all source path components checked, O_NOFOLLOW final open, regular file requirement | Hostile local directory swaps not fully hardened; no archive support |
| Memory/CPU exhaustion | 8MiB/file,64KiB/line,5000lines,32artifacts,20000events,64MiB state; per-domain IOC grouping avoids Cartesian expansion | Whole-state copies and JSON parser/runtime cost; no OS sandbox or global CPU quota |
| Forged provenance/findings | Original hashes, reparse/compare, rule recomputation, source references/time interval checks, local audit hash chain | Same user can rewrite/recompute everything; no external anchor or authenticated collector |
| Injection in app/log/domain strings | No shell/eval/network/AI; report allowlist omits raw attributes; errors are fixed codes | No AI mode tested because none exists; metadata still sensitive |
| Exposure through reports/CI | No labels/filenames/domains/payload in exports; synthetic fixtures only; no upload-artifact; hygiene scanner | Timestamps/hashes are linkable; scanner is heuristic, not complete DLP |
| False spyware assertion | Regularity is a lead; alternative hypotheses, context, missing scope and no clean verdict | No ground truth malware corpus; thresholds uncalibrated |
| Concurrent writers / interruption | Nonblocking advisory case lock; same-directory atomic metadata replace; fsync; read-only originals | Crash may leave unreferenced original/temp file; no complete recovery tooling; locks cooperative |
| Dependency compromise | Zero third-party runtime deps; exact dev pins; SHA-pinned GitHub actions; no upstream binaries | Python/native stdlib and dev package supply chain remain; lock lacks package hashes |

Future external tools need OS isolation and allowlisted operations, process group termination, bounded output and schema checks. No claim that merely using Rust or a subprocess would solve these threats. Future native parsers must preserve raw data before any transformation.
