# Security

Use SCRYVEIL only with your own exports or explicit authorization. It does not certify devices as spyware-free and is not a replacement for expert incident response.

Do not attach private phone evidence, pair records, credentials, backups or raw reports to public issues/PRs. Report a vulnerability using GitHub's private vulnerability reporting feature **if available**. If unavailable, open a content-free request for a private contact method; never publish sensitive exploit/evidence details while arranging contact. No private channel is presumed configured.

Initial controls: offline stdlib-only runtime, bounded NDJSON, exact byte hashes, no archive extraction, symlink/FIFO rejection, case ID validation, private POSIX modes, atomic state replacement, advisory case locks, redacted allowlist reports and lineage revalidation. No arbitrary subprocess, dynamic plugin, network client or model tool exists.

Limits: same-user/root attackers can rewrite files and recompute hashes; the audit chain has no external anchor. Advisory locks are cooperative; parent-directory race hardening and hostile local-user sandboxing are not claimed. No encryption at rest is implemented. CPython/native standard library remains part of the trust base. See threat-model and known-limitations.
