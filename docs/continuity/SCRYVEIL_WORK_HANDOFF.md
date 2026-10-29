# SCRYVEIL engineering handoff

Branch: `feat/forensic-core-genesis`; PR #1 open, never merge automatically.
Verified implementation SHA: `af69350619b48dad94baf4f70f058475175a6f1c`.
This documentation checkpoint records that exact implementation; earlier handoffs remain in Git history.

## Completed and verified

- Evidence integrity, eleven allowlisted tools, isolated worker and exact claim grounding preserved.
- Required coverage review, persistent review progress and corrective feedback implemented.
- Shared reasoning procedure remains experimentally unqualified; it cannot enforce causal truth.
- Chat low/medium/high reasoning control and incomplete/refused response rejection implemented.
- Fixed-vocabulary broker timeout phases, sanitized HTTP errors and remote benchmark fail-fast behavior implemented.
- Explicit `retry_http_503_once` permits one five-second delayed retry only for exact 503, inside existing budgets; cancellation and report auditing tested. Default no retries.
- Embedded provider report schema corrected; stored cases/report contracts remain compatible.
- 519 local tests pass. Core CI 40902935469 passes static, typing, security, hygiene, historical compatibility, source demos, build and installed-wheel demos.

## Actual-model evidence and blockers

- Historical Gemini recurrence/mixed-format completions had valid field facts but unsupported causal inferences/incomplete contradiction mapping. Do not call these qualified reasoning.
- Run 40851648597 (explicit low effort) timed out on request four. No final; remaining selected cases skipped.
- Run 40902135551 produced a plan, then HTTP 503. It did not reach a timeout, so earlier timeout causes remain unknown.
- Run 40902935225 returned 503 twice, with exactly one five-second delayed retry. No model response; no further calls. Recovery limit demonstrated, semantic quality not exercised.
- These report schemas/digests, disclosure plans and bound source hashes were independently verified. See docs/validation/provider-qualification.md and the original JSON records.
- Full seven-scenario qualification remains open. Current focused workflow selects recurrence, injection and missing evidence; omitted cases never count as passing.
- No current evidence supports increasing budgets or repeating the identical failing experiment. Establish reliable authorized model availability/protocol before another reasoning comparison.

## Next priority

Resolve provider availability with a bounded, evidence-free protocol check for a supported model/endpoint, then run the focused fictional investigation and manually evaluate competing explanations, causal restraint, contradiction mapping and actual attack exposure. If a different provider is used, keep credentials separate and bind its endpoint/model to explicit disclosure. Do not weaken criteria or treat operational CI success as reasoning success.

## Reproduction and authorization

Run checks in AGENTS.md, including `.venv/bin/python -m pytest -q`, Ruff, mypy, Bandit, hygiene, both historical compatibility scripts, all five source demos, build and installed-wheel demos. `scripts/provider_qualification.py --provider-config PRIVATE_CONFIG --scenario recurrence --scenario injection --scenario missing_evidence --preview` prepares offline disclosure. Execution requires its exact digest. Configuration alone never triggers inference.

Owner authorized fictional model testing and reviewable development. No authorization for private owner diagnostic processing/device access, paid billing activation or automatic merge. Genuine Apple exports, independent authenticated custody, broad backup/sysdiagnose/PCAP/live acquisition remain open. No private evidence or credentials enter repository or model inputs.

## In-progress continuation after b8777bde571c966d4c037ed100834f218c44fde3

Implemented an evidence-free, two-turn provider protocol check, with no tool execution, explicit digest approval, capped budgets, sanitized errors and fail-fast behavior. 533 local tests, static/type/security/hygiene gates, historical compatibility, five source demos and package build pass. Native and Chat paths pass fictional HTTP tests; live protocol and reasoning results are pending.

Selected Gemini 3.8 Flash for the next bounded check using the existing Google secret and endpoint. Current official compatibility documentation uses this model and standard pricing lists a free tier; account eligibility and billing are not verified by these public documents. Google now limits 2.5 access to prior users, consistent with (but not proof of the cause of) the earlier 404. No billing changes. If protocol succeeds, run the focused fictional benchmark; otherwise preserve the precise failure and do not replay the same experiment.
