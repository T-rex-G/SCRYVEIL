# Security

Use SCRYVEIL only with your own exports or explicit authorization. It does not certify devices as spyware-free and is not a replacement for expert incident response.

Do not attach private phone evidence, pair records, credentials, backups or raw reports to public issues/PRs. Report a vulnerability using GitHub's private vulnerability reporting feature **if available**. If unavailable, open a content-free request for a private contact method; never publish sensitive exploit/evidence details while arranging contact. No private channel is presumed configured.

Controls: bounded NDJSON/explicit IPS, exact byte hashes, no archive extraction, symlink/FIFO rejection, case ID validation, private POSIX modes, atomic state replacement, advisory locks, report minimization and lineage revalidation. Optional investigation uses fixed internal subprocesses, a Linux default-deny syscall policy, one-case snapshots and allowlisted read-only tools. Provider requests require explicit configuration; remote evidence requires exact disclosure consent. There is no arbitrary shell, device library or dynamic plugin access. See [ADR-002](docs/architecture/ADR-002-read-only-ai-investigation.md).

Limits: same-user/root attackers can rewrite files and recompute hashes; the audit chain has no external anchor. Advisory locks are cooperative; parent-directory race hardening and hostile local-user isolation are not claimed. No encryption at rest is implemented. The owner supervisor, CPython/native libraries, libseccomp and kernel remain trusted. Prompt injection can still mislead permitted analysis; valid references do not prove hypothesis truth. Actual models and real exports remain unqualified. See [threat model](docs/threat-model.md) and [limits](docs/validation/known-limitations.md).
