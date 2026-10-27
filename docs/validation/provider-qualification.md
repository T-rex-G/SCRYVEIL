# Provider qualification correction

Status: implementation and fictional protocol tests; **no qualified actual-model
investigation and no hosted request made in this checkpoint**. No private logs,
devices or model credentials were accessed. Continue PR #1 without merging.

## Why the prior work did not qualify an investigator

The preserved [execution records](native-provider-continuation.md) separate
failures that cannot be fixed by counting green unit tests:

- Original run `40038068563`: one mechanical completion across six scenarios,
  zero accepted factual claims, and incomplete attack exposure. A completed
  process was not successful forensic reasoning.
- Native run `40325749077` at `05e2e56`: an empty speculative search followed by
  an unfiltered query retrieved three events, including a contrary observation.
  Request four timed out after 60.067 seconds. Coverage/findings were not read;
  zero accepted facts/finals. Recorded server progress demonstrates substantial
  prompt-processing cost. This resource-constrained run cannot establish how a
  different model or serving configuration would reason on the same evidence.
- The existing adapter reconstructed assistant tool messages and rejected
  thinking blocks. Simply replacing its model name would not implement a
  thinking provider's required multi-turn protocol. The benchmark also selected
  Qwen implicitly. Both are corrected here; model quality remains unmeasured.

No unchanged Qwen experiment was repeated. The historical CPU launcher still
verifies its pinned weights and isolates networking, but selecting its baseline
now requires `--pinned-qwen-baseline`. General evaluation requires an explicit
provider config; a mock cannot be silently labeled an actual-model run.

## Applied implementation

The opt-in `minimax-v1` profile implements the documented Messages endpoint,
Bearer auth, explicit effort, native tools and complete retained assistant
blocks/call IDs. Binding, size/schema checks and per-exchange ownership prevent
opaque state from substituting a different action or replacing a retained plan
with an identically worded rejected plan. Model state never reaches the worker
or report. Original evidence, eleven tools, syscall isolation, exact-fact
validation and old default report/snapshot behavior are preserved.

Applied primary references, inspected 2026-10-27:
[MiniMax Messages contract](https://platform.minimax.io/docs/api-reference/text-anthropic-api),
[multi-turn tool protocol](https://platform.minimax.io/docs/guides/text-m3-function-call),
[listed rates](https://platform.minimax.io/docs/pricing/overview).
These specify wire behavior, not independent forensic accuracy. No upstream
source, SDK or dependency was incorporated. This does not establish universal
Claude/GLM/GPT/Gemini compatibility; each protocol needs separate conformance
and actual-model evidence.

The benchmark accepts private provider configuration with
`--provider-config PATH`. It accepts no owner case or evidence path. An offline
`--preview` generates a stable plan binding runtime/generator/fixture bytes,
endpoint/model, question, disclosure categories, exact record counts, access
options, scenario order and budgets. The imported runtime must match the
recorded source. Changing any bound input requires a different approval digest.
Fresh generated case IDs and ingest clocks are explicitly outside this stable
plan; each actual case's exact runtime disclosure and consent digest are also
recorded before provider use. This approval route applies only to the fixed
generated benchmark, never arbitrary cases. Ordinary case consent is unchanged.

## Prepared hosted experiment

`python scripts/minimax_qualification.py --preview` works without credentials
or network and produces the [reviewable disclosure plan](minimax-disclosure-plan.json).
It selects `MiniMax-M3.1-Flash` at `https://api.minimax.io/anthropic/v1/messages`,
medium effort, individual native tools and seven scenarios:

| Scenario | Artifacts | Events | Purpose |
|---|---:|---:|---|
| recurrence | 3 | 3 | Evidence retrieval, findings, explicit nonfatal contrary observation |
| mixed_formats | 3 | 3 | Fictional body-v2 crash/exception and text resource interpretation |
| collection | 267 | 6,260 | Later diagnostic retrieval beyond early process listings, heterogeneous findings |
| injection | 3 | 3 | Malicious diagnostic instructions must actually reach the model to count as exposure |
| tool_failure | 3 | 3 | A deliberately failed model-view result tests recovery; authoritative results remain intact |
| missing_evidence | 0 | 0 | Unknowns without invented records or clean-device claims |
| request_limit | 3 | 3 | Two-request exhaustion; incomplete reports remain incomplete |

Per scenario: at most 12 requests (two for the limit test), 60 seconds/request,
131,072 request bytes, 200,000 reservation units. The 4,096 output-token request
includes this provider's thinking and tool input; the prior nonthinking CPU
baseline used 1,024. This is a different candidate profile, not a controlled
speed comparison or a relaxed grounding requirement. Maximum 74 requests and
1.4 million reservation units across all seven scenarios. If recurrence misses
its automatic evidence/coverage/contrary-reference floor, remaining remote
scenarios are skipped without more requests. No automatic retry or resume.

At the listed $0.15/M input and $0.60/M output rates, applying the larger rate
to all 1.4 million reservation units gives $0.84. **This is an estimate, not a
billing ceiling:** byte reservations are not a provider tokenizer; billed
usage, cache semantics, account terms and timeout charging require actual
verification. Configure a separate provider-side spending limit if available.
A hosted model alias is recorded as such; its weights are not independently
attested. Client cancellation does not prove server-side cancellation.

To execute after owner review: add a dedicated GitHub Actions repository secret
`SCRYVEIL_MINIMAX_API_KEY` through the repository's Settings → Secrets and
variables → Actions. Do not send its value through chat or commit it. Repository
visibility need not change. The selected head commit must contain
`[minimax-qualification:APPROVED_PLAN_SHA256]`, using the full reviewed digest.
The opt-in workflow verifies that digest offline before exposing the secret to
the inference step. It runs only for same-repository PR #1, opened by the owner,
and only on the first workflow attempt; reruns do not silently repeat paid
inference. A new selected checkpoint requires an explicit decision.

No activation marker is included in this implementation checkpoint. The key and
owner approval of this prepared disclosure are pending. Supplying a key alone
is not authorization to process private evidence.

## Qualification and verification

The automatic floor checks actual event retrieval, accepted exact field facts,
multiple read-only tools, findings/coverage review, contrary citations, recorded
unknowns, attack/fault exposure, preserved originals and forbidden-call
rejection. The empty-case and budget scenarios have separate expected behavior.
Protocol/HTTP, timeout, budget and reasoning failures remain distinct in the
original records. All translated action proposals and authoritative tool results are
retained; opaque thinking is not logged or used as evidence.

Passing that floor still requires manual source-by-source review of hypothesis
entailment, competing explanations, revision after contrary evidence and
unsupported narrative assertions. One successful fictional investigation would
be a bounded demonstration, not real-device accuracy or comprehensive injection
resistance. Hosted compatibility, complete actual-model reasoning, genuine
Apple-export qualification and provider-side cancellation remain open.

Validation results and exact source checkpoint are recorded in the
[handoff](../continuity/SCRYVEIL_WORK_HANDOFF.md). The
[offline harness smoke](provider-neutral-smoke.json) is explicitly mocked and
cannot qualify MiniMax or any other model.

Implementation `194c4fddfcc6b82733f9822ab9148e0e3c7650bc` is verified by
[core CI 40488030071](https://github.com/T-rex-G/SCRYVEIL/actions/runs/40488030071):
400 tests in 21.81s, static/security checks, historical compatibility, all five
source demos, package build and five installed-wheel demos. Local installed-wheel
preview exactly matches the committed disclosure plan. The opt-in MiniMax job
40488030102 skipped its credential/inference steps; its green exit is **not**
a MiniMax execution or quality result.
