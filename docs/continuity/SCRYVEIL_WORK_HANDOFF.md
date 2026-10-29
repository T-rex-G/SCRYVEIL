# SCRYVEIL engineering handoff

Branch `feat/forensic-core-genesis`; PR #1 open; never merge automatically.
Last verified published implementation: `b205cadfc73509fee7e755631269a9d74c763f3c`; core CI 40905285285 passed. Current offline-report changes have passed local qualification; final commit/CI reference follows after publication.

## Delivered offline capability

`python scripts/collection_demo.py --offline-only --output /tmp/scryveil-example`

Creates the fictional collection, imports through the ordinary CLI, reconstructs 6,260 events, measures three signature groups of 80 incident declarations, and exports `diagnostics.md`, full JSON, inventory and paged queries. No AI (including mock) is invoked. Reports now show timeline coverage, authorized signature symbols, resource accounting windows, original hashes, byte ranges and JSON pointers. 24 explicit nonfatal declarations and 20 no-action resource reports contradict an all-fatal interpretation. Earlier Jetsam records do not establish pressure at later crash times.

All 266 original member bytes and normalized crash timestamps/exception fields/flags were checked independently against Python's ZIP reader and raw JSON. Original bytes and case state remain unchanged. 534 local tests, static/type/security/hygiene checks, historical compatibility, five source/installed-wheel demos and the installed-wheel offline delivery pass. The latter completed in 3.727 seconds on this shared host; this is not a general scalability guarantee.

## Actual-model blocker

Evidence-free Gemini 3.8 Flash check 40905285383 at b205cad failed on request one: `provider_timeout_headers` after 60.03819 seconds, 2,096 context bytes, no reply, no tools, no evidence, no retries. Exact compact record: `docs/validation/provider-protocol-result.json`; executed plan is in that commit. No forensic benchmark followed. Earlier semantic failures remain unresolved; no actual model is qualified. No billing changes were made. Availability at this endpoint/model must be established before further reasoning tests; do not repeat the unchanged failing check.

## Boundaries and next action

A is demonstrated on fictional inputs. B remains blocked by transport/provider response availability; its root cause is not established. Genuine Apple-export accuracy needs separately authorized independent samples. No private owner diagnostics/devices are authorized. Broader acquisition and authenticated custody remain unqualified. Eleven read-only tools, syscall isolation, consent, source integrity and historical contracts are preserved.

Next: run a minimal protocol check only when an authorized endpoint/model has a concrete availability change; then evaluate the fixed case against source facts, competing explanations, contradictions and causal restraint. Preserve the offline delivery independently. Stored approval plans are historical evidence; re-preview the exact current code before any new authorized transmission. Do not expand research or compatibility layers without an observed blocker.
