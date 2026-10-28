# Provider qualification correction

Status: **no qualified actual-model investigation**. One owner-authorized hosted attempt reached HTTP 403 before any model action. Private diagnostics and devices remain out of scope; PR #1 stays unmerged.

## Recovered gateway attempt and access diagnostics

At `6058a0d9df07c753e87392c9c4689f7c59039bc7`, [run 40580100780](https://github.com/T-rex-G/SCRYVEIL/actions/runs/40580100780), job `122456873922`, matched approved digest `6cf6fefb6b35ba4beeb87f2adf790e9d1886808030d9ba559a3583670a33f008` before secret access. The first recurrence request returned `provider_http_403` after 0.9787s. No accepted plan, query, factual claim, final report or adversarial exposure occurred. All other six scenarios were skipped; originals/state were unchanged. No provider usage returned and cost is unknown.

[Machine-readable original](apmix-access-40580100780.json) and [executed disclosure](apmix-disclosure-6058a0d.json) are independently hash-checkable. Offline reconciliation verified the report/plan digests and all 36 historical bound files; no inference replay. Core CI 40580100705 passed independently. The original transport discarded the error body; neither account entitlement nor a specific rejection reason can be inferred from status 403 alone.

The continuation adds a closed set of bounded, provider-reported error categories and an explicit **one-GET catalog check**, with no evidence or inference. It preserves auth secrecy, TLS/public-DNS restrictions, syscall isolation, same-origin authorization, strict size limits and no retries/redirects. Catalog entries cannot install tools, select a model or trigger inference. Unknown error content never reaches the operator or agent.

Applied reference: [gateway API error/catalog documentation](https://apmix.ai/docs), inspected 2026-10-28. Only documented stable error identifiers inform the closed classification; no source/SDK/dependency was incorporated. Catalog declarations are unverified provider data, not proof of free access or model capability. [Catalog plan](provider-access-plan.json). Current inference disclosure is preparation only; no unchanged paid retry is selected. Local validation: 498 tests in 21.07s; static/security checks, three historical compatibility baselines, five source demos, build and five installed-wheel demos pass. Catalog security tests cover same-origin enforcement before credential access, one GET with no body, exact auth binding, redirects, malformed/oversized lists and malicious/credential-bearing error responses.

The live catalog-only check [40743613991](https://github.com/T-rex-G/SCRYVEIL/actions/runs/40743613991), job `123011450525`, at `e8f1ebd5ba5c36efa7d0828a11662c8fdea50138` received zero entries, no indicated pagination, and no exact matches for either MiniMax alias or the explicitly checked historical free-Claude ID. [Exact result and plan](apmix-catalog-40743613991.json); all 25 bound historical files/digest were independently recomputed. No evidence or inference request was sent. It does not verify billing, establish why the earlier POST failed, or justify automatically trying an unlisted model.

[Core CI 40743614263](https://github.com/T-rex-G/SCRYVEIL/actions/runs/40743614263) passed 498 tests in 25.11s and every required static/security, compatibility, source-demo and packaging check. Hosted workflow 40743613945 explicitly skipped inference. Actual-model qualification remains blocked on access; no completion, reasoning or injection-resilience claim is made.

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

The opt-in `minimax-v1` profile implements the documented Messages protocol,
explicit effort, native tools and complete retained assistant
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

## Hosted experiment configuration and reproduction

The owner clarified that their credential is for **apmix.ai**, not direct
MiniMax. The former [direct-service disclosure](minimax-disclosure-plan.json)
is a historical preparation, not approval for a new destination. Its workflow
has been replaced by a provider-neutral opt-in workflow. The direct launcher
remains for reproducibility, but its old marker no longer selects inference.

Current [nonsecret configuration](../../configs/qualification-provider.json)
uses `base_url: https://api.apmix.ai`, Messages, `auth_scheme: x-api-key`, model
alias `minimax/minimax-m3.1-flash`, medium effort and the existing MiniMax protocol
profile. These settings are candidates, not a qualified gateway/model pairing.
[The gateway's own API example](https://apmix.ai/models/minimax-m3.1-flash)
documents the URL/header/model. Its translation of thinking/tool state and
`output_config.effort` still needs actual execution. That preparation made no model-list request or credential access; the subsequent attempt is recorded above. No dependency or upstream source was incorporated.

Create an owner-private copy of that config and preview it offline:

```sh
install -m 600 configs/qualification-provider.json /tmp/scryveil-provider.json
python scripts/provider_qualification.py --provider-config /tmp/scryveil-provider.json --preview
```

The [current disclosure plan](provider-disclosure-plan.json) resolves the request
to `https://api.apmix.ai/v1/messages`. URL, path, model, auth and protocol are
owner-selectable; normalization never changes destinations after approval.
Only the existing supported wire contracts are implemented. An arbitrary base
URL does not prove an arbitrary model/API is compatible. Seven scenarios:

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

Apmix uses weighted subscription tokens, so the earlier direct-MiniMax USD
estimate does **not** apply. Rates are deliberately unset and SCRYVEIL reports
unknown USD cost. Token usage is retained when available, without pretending to
measure the gateway's billing weights. Set an account/key allowance separately.
[Gateway privacy terms](https://apmix.ai/privacy) say content may be forwarded
to a model vendor or intermediary; neither upstream identity nor retention is
independently verified here. The disclosed destination is the gateway. Client
cancellation cannot prove provider-side cancellation.
To execute after owner review: add a dedicated GitHub Actions repository secret
`SCRYVEIL_PROVIDER_API_KEY` through the repository's Settings → Secrets and
variables → Actions. Do not send its value through chat or commit it. Repository
visibility need not change. The selected head commit must contain
`[provider-qualification:APPROVED_PLAN_SHA256]`, using the full reviewed digest.
The [opt-in workflow](../../.github/workflows/provider-qualification.yml) copies the
reviewed config with private permissions, then verifies that digest offline before exposing the secret to
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
source demos, package build and five installed-wheel demos. That implementation's installed-wheel
preview matched its historical direct-service plan. The opt-in MiniMax job
40488030102 skipped its credential/inference steps; its green exit is **not**
a MiniMax execution or quality result.

The custom-gateway continuation removes vendor path coupling, adds canonical
base-URL resolution and explicit auth selection, and keeps both old default
providers byte-compatible. Loopback peers test full eight-step native
investigations on direct/root/prefixed routes, custom JSON routes, TLS, mixed
DNS rejection, credential isolation and changed-destination consent. These are
protocol/security measurements, not hosted inference. Current test/CI results
and the exact checkpoint are in the handoff.

Custom-gateway implementation `1ad9d0ca0937c8bbf38e755d9772c8da19b1c55a`
is independently checked by [core CI 40530288063](https://github.com/T-rex-G/SCRYVEIL/actions/runs/40530288063):
453 tests in 21.45s and all required static/security, compatibility, demo and
package checks. The opt-in gateway workflow 40530288157 skipped inference.
Its current plan digest is
`6cf6fefb6b35ba4beeb87f2adf790e9d1886808030d9ba559a3583670a33f008`.
The installed-wheel offline preview matches it exactly. No hosted reasoning
result is available; credential setup and reviewed experiment activation remain
the immediate next step.
