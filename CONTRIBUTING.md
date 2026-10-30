# Contributing

Keep changes in a reviewable branch/PR. No automatic merges or settings changes. Use only independently generated fixtures under fixtures/synthetic with reserved .invalid endpoints and fictional identifiers. Do not submit real exports even if you believe they are anonymized.

Read ADR-001 and the source/license matrix before adding dependencies or languages. No code/binary vendoring without exact source/license/notice review. Device adapters require explicit capability, consent, version, timeout/output budget and side-effect contracts.

Run the documented lint, type, security, test, packaging and hygiene commands. Tests must cover unknowns, malformed inputs, false positives and lineage. Every claim needs source evidence. Keep benchmark spikes outside the production wheel.
