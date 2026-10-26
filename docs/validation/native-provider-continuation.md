# Native provider continuation

## Instrumented JSON-action baseline

[Run 40137879901](https://github.com/T-rex-G/SCRYVEIL/actions/runs/40137879901), source `f5676df2528e3b64c42f820dbffeb0a4a9087db6`, selected only the generated recurrence scenario. [Original result](model-experiments/qwen-run-40137879901.json), [timing record](model-experiments/qwen-run-40137879901-timing.json), and [resources](model-experiments/qwen-run-40137879901-resources.json) are retained without reinterpretation.

The first 6,331-byte context timed out after 60.028s. Zero replies, event queries, findings reviewed, factual claims or completed investigations. Originals/state remained unchanged. Workflow success means the measurement process completed, not forensic reasoning success.

The server/evaluation children used 123.333 user CPU seconds over 65.664s wall, with largest-child peak RSS 6,664,092 KiB. Server shutdown exited normally in 0.164s without a forced kill. No numeric server events were collected. Raw server log content was not retained in the published record; therefore missing telemetry cannot establish absence of server activity, the prompt/generation split, cancellation cause, or the latency bottleneck. No usage/cost or narrative-accuracy score is inferred from the timeout.

## Corrective implementation and experiment

Prior invalid action/envelope failures justify testing a native client-tool protocol independently of JSON prose actions. `messages-tools` adds a bounded `/v1/messages` adapter, native call/result exchanges, phase-scoped definitions, sanitized protocol errors and complete request-size accounting. The same worker still authorizes eleven read-only tools and validates exact facts. Unknown tools/arguments and invented references gain no permissions. No framework or provider SDK is added.

Source inspection found that the pinned local server reports cached input tokens separately; the adapter includes those in conservative input totals. History compaction retains matched call/result pairs. Only the plan is advertised initially, then authorized query/final operations. This reduces initial request context and prevents advertising operations that the worker cannot yet accept; it does not lower completion requirements.

Synthetic HTTP peers exercise the real broker and isolated worker, complete an eight-request cited report, expose contrary observations, validate native accounting, and reject prohibited calls, cross-path arguments, changed remote consent, unsupported output blocks, parallel calls, truncated responses and bad usage. These tests qualify protocol mechanics only. Text alongside a native call is discarded and not scored as factual accuracy. Hosted providers and reasoning quality remain unqualified.

The next selected actual-model comparison uses the same pinned Qwen3 4B weights, recurrence inputs, 60-second request timeout, 12-request ceiling and 200,000-unit reservation budget. Native framing, phase-scoped definitions, explicit Jinja and prompt/generation progress telemetry differ, so it is not a strict single-variable comparison. It does not repeat the six-scenario suite. Do not raise budgets or relax grounding to call it successful. A useful result must retrieve evidence, review findings, cite valid facts and address contrary/missing evidence; semantic revision still requires independent review.

New telemetry records only fixed numeric patterns, log byte counts/digest, task/slot progress and shutdown state. Raw-log retention is capped at 8 MiB locally and never automatically uploaded. Task IDs are not authenticated request bindings. The next run must be reconciled before any success claim or further experiment.

Local follow-up verification: 356 tests in 10.68s, static checks, historical executable compatibility, five demos, package build and installed-wheel demos passed. Initial native recurrence request body is 2,152 bytes including the plan schema; old JSON context was 6,331 bytes (different framing/budget bases). Actual native execution remains pending at this implementation checkpoint.

## Reconciled native execution and bounded correction

[Run 40181063497](https://github.com/T-rex-G/SCRYVEIL/actions/runs/40181063497), source `4040436af2a893bc9853bcb384024f018042b76a`: [original result](model-experiments/qwen-run-40181063497.json), [timing](model-experiments/qwen-run-40181063497-timing.json), [resources](model-experiments/qwen-run-40181063497-resources.json). A real native call returned an accepted eight-step plan after 35.117s. Its reported usage was 497 input/95 output tokens; server timings measured 18.090s prompt evaluation and 16.932s generation. The 8,813-byte second request timed out after 60.061s. **Zero queries, accepted facts or completed investigations.** A valid plan proves only partial native protocol interoperability.

The server required SIGKILL after the five-second shutdown grace. The supervisor/worker still preserved original evidence and returned a partial report. This is not proof of timely server-side request cancellation. There was no prompt/generation breakdown for the second request. CPU-intensive prompt processing is a plausible bottleneck, inferred from the measured first request; its second-request share remains unmeasured.

The next correction removes repeated string-length hints only from the native model-facing schemas; the worker still checks full schemas/byte limits, and numeric/page/array limits remain advertised. Native context `scryveil.context.native/1` keeps system policy constant and places bounded changing protocol state after the latest result, avoiding unnecessary cache-prefix invalidation. Replaying the exact prior plan reduces the second request from 8,813 to 7,393 bytes. This is a byte measurement, not a latency or reasoning result.

The selected server uses logical/physical batches of 128 tokens, preserving two CPU threads, weights and all investigation budgets. Smaller decode batches are intended to improve progress observation and cancellation responsiveness; throughput and actual effectiveness must be measured. The native HTTP → isolated-worker injection regression rejects shell and cross-path proposals after exposing the attack string. Collection inventory separately preserves unqualified-v73 observations and unsupported types.

The next workflow runs recurrence first. Only if it completes with grounded facts, queried coverage and cited contrary evidence does it attempt the 266-member/6,260-event generated collection. Otherwise the collection is explicitly skipped with a reason. This floor is not a semantic-quality score. Mock harness checks complete both scenarios (three/five accepted field facts), solely proving mechanics. Local full regression passed 360 tests in 11.26s; static/compatibility checks, five demos, package builds and installed-wheel demos pass. No further actual-model success is presumed.

## Preparation failure, not a reasoning result

At `38e7b3320d4403b88b8f47ef3710b9dd721b7bcb`, [core CI 40182871754](https://github.com/T-rex-G/SCRYVEIL/actions/runs/40182871754) passed 360 tests in 14.07s and all required checks. [Model workflow 40182871736](https://github.com/T-rex-G/SCRYVEIL/actions/runs/40182871736), job 121137454993, built the pinned server but failed downloading weights: curl exit 28 after 299,861ms, 503,858,822 of 2,497,280,256 bytes received. The inference step was skipped; neither selected scenario executed. This is an infrastructure failure, with no new model-quality measurements.

The follow-up preserves the experiment code and inference limits, separately allows up to 1,800s for the pinned public download, rejects stalls/oversized files, and verifies exact size/SHA-256 before inference. A pinned cache action stores only the verified public weights; restored bytes are always verified again. No case, report, server log, credential or binary build is cached. Cache availability is optional and cannot substitute for the hash check. The job ceiling accommodates preparation; model requests remain bounded at 60s and twelve per case. This retry is justified because no inference ran.

## Compact-native result: prompt evaluation exceeds the request bound

[Run 40204579155](https://github.com/T-rex-G/SCRYVEIL/actions/runs/40204579155), source `39bf69c3aa1e11760670e886e03a6818dc205681`, completed preparation, verified the weight hash and saved the public-weight cache. A future cache restore remains untested in CI. [Original report/actions](model-experiments/qwen-run-40204579155.json), [numeric server timing](model-experiments/qwen-run-40204579155-timing.json) and [resources](model-experiments/qwen-run-40204579155-resources.json) are retained unchanged.

The initial 2,121-byte native request returned an accepted plan in 31.769s (481 input/101 output tokens). Server timings: 19.657s prompt evaluation, 11.999s generation. The second request was 7,406 bytes; it timed out in 60.063s. The single server slot was still reporting prompt progress at 57.75s, with 1,280 newly processed tokens and displayed progress 0.79. No generation phase or evidence-query reply was recorded. This directly supports a prompt-processing bottleneck in this two-thread CPU profile; it does not establish a model reasoning failure on evidence it never received. Shared-host conditions and changed plan text preclude a controlled speedup claim.

**Zero evidence queries, accepted facts, contrary citations or completed investigations.** The large collection was explicitly skipped because the recurrence floor failed. Original evidence/state remained unchanged. Server shutdown completed normally in 4.224s without SIGKILL; request cancellation attribution remains unmeasured. Largest-child peak RSS was 6,600,992 KiB, wall 98.981s and user CPU 194.345s. Workflow success means measurements were recorded, not that forensic quality passed.

Do not repeat this unchanged full investigation or raise budgets to conceal the bottleneck. The next model qualification needs a demonstrated serving-throughput improvement or a separately tested reduction in native request cost that retains tool semantics, retrieval and grounding. Genuine Apple-export, hosted-provider, actual-model injection and hypothesis-revision qualification remain open.

## Measured request-cost correction

The next adapter revision defers the final-report schema until two distinct successful query tools are present in retained history. It keeps all eleven read-only tools after the plan; the worker still checks actual event retrieval, findings and exact claims before accepting a final report. Rejected or repeated calls do not satisfy this advertising floor. If context compaction removes the distinct query views, the model can re-query them. No detector, evidence field, inference budget or permission changes.

Shorter descriptions preserve tool distinctions, literal-filter semantics and source/custody limitations. Removing an empty JSON Schema `required` list changes no validation meaning. Replaying context SHA-256 `f16e4450c93d4f89e2c315b3d6eae4633c2c4b920e2355bec56c964e3450698a` from run 40204579155 produces **5,899 native request bytes versus 7,406** previously (20.3% less), with all eleven query schemas. This is a request-cost measurement; throughput, model selection and forensic quality require the next execution record. The real HTTP mock now also checks that every proposed valid call was advertised and its input conforms to that schema. Local 361-test, static, historical compatibility, five-demo, build and installed-wheel checks pass.

## Reconciled retrieval progress; final investigation still fails

[Run 40229335744](https://github.com/T-rex-G/SCRYVEIL/actions/runs/40229335744), source `fecbb7a9ae41be5e8d74a4d9ebb4cf802dd0bf69`, restored the pinned public-weight cache successfully and reverified its size/hash. The weights, server revision, two CPU threads, sampling settings, 60s request bound and twelve-request ceiling were unchanged. [Original result/actions](model-experiments/qwen-run-40229335744.json), [timing](model-experiments/qwen-run-40229335744-timing.json) and [resources](model-experiments/qwen-run-40229335744-resources.json) are extracted from the original execution log. Core [CI 40229335698](https://github.com/T-rex-G/SCRYVEIL/actions/runs/40229335698) independently passed 361 tests and all required checks.

| Request | Actual response or outcome | Request bytes | Elapsed seconds |
|---|---|---:|---:|
| 1 | Accepted eight-step plan | 2,121 | 30.602 |
| 2 | `coverage.inspect`: missing families and uncertainty | 5,899 | 59.390 |
| 3 | `timeline.query`, literal `search service failure`: zero matches | 6,612 | 14.888 |
| 4 | `diagnostics.search`, same literal phrase: zero matches | 8,420 | 47.266 |
| 5 | Unfiltered `timeline.query`, limit 5: all three events | 8,834 | 15.658 |
| 6 | Timeout after the event results entered context | 11,719 | 60.063 |

All four query calls were valid and read-only; three distinct query tools were used. The model eventually removed the speculative filter after two empty queries, despite earlier guidance to start unfiltered. The returned events include two `EXC_BAD_ACCESS` observations and one explicitly nonfatal `EXC_RESOURCE` observation. These are retrieved source values, **not accepted model conclusions**. No findings query or structured factual assertion, hypothesis, contrary citation or final report followed. Accepted facts and completed investigations remain zero; factual precision is unmeasured because no facts were proposed. The collection scenario was explicitly skipped. Injection and tool-failure recovery were not exercised in this run; zero forbidden calls cannot qualify those properties. Text accompanying native calls is discarded and unscored, so it cannot establish narrative accuracy or absence of unsupported assertions.

The exact previously failing second context now returned a coverage query, narrowly inside its deadline. Its server prompt evaluation took 56.855s and generation 2.429s. The sixth request again remained in prompt evaluation: last progress at 56.65s, 1,024 newly processed tokens, displayed progress 0.97, before the adapter timeout. No completed sixth-request prompt/generation timing exists. Task IDs are not authenticated request bindings. These records demonstrate prompt cost and retrieval progress, not a controlled throughput speedup or useful final reasoning.

Originals and state remained unchanged. Reported usage for the five replies was 8,249 input/183 output tokens; sixth-request usage and total cost are unknown. The reservation was 49,749/200,000 units, so neither total-budget nor twelve-request exhaustion caused this stop. Evaluation wall time was 227.940s; server/evaluation children used 464.658 user CPU seconds over 234.271s wall, largest-child RSS 6,606,572 KiB. Server shutdown exited normally in 3.722s without a forced kill; this still does not prove request-specific cancellation.

Offline verification reproduced all five action/result hashes through the isolated worker, all six model-context hashes/request sizes, all three event values/source references and the recomputed metrics. The report hash and all 22 runtime source hashes match. This replay uses only the three committed fictional fixtures and performs no inference. It establishes record consistency, not an independent parser-accuracy or model-quality qualification.

The next experiment must first demonstrate a serving-throughput or request-cost improvement for the exact sixth request, while retaining relevant diagnostic detail, contrary observations, source identity and worker grounding. Replaying the same full investigation or merely raising budgets is not justified. Literal-search selection and delayed review of deterministic findings are separate observed investigation weaknesses; the existing feedback did not prevent two empty queries. A complete evidence-grounded actual-model investigation and genuine Apple-export qualification remain open.

## Lossless event factoring and measured serving profile

The native model view now factors exactly identical fields shared by every event
in a page into `data.shared_event_fields`. Each event keeps its own ID and every
differing field; merge the shared object into each row to reconstruct the exact
previous view. Missing fields differ from null, and boolean/numeric JSON values
are compared by canonical bytes. An identical envelope ID list may be omitted
because those IDs remain in the rows; differing lists remain intact. Small pages
that do not save at least 128 bytes retain their existing representation. Original
tool results, claim validation, reports, disclosure boundaries and all eleven
queries remain unchanged. Evidence strings remain untrusted even when shared.

`python scripts/replay_native_request.py` reproduces all six contexts from the
preserved fictional run, checks action/result hashes and requires exact
reconstruction of every transformed result. [Measurements](native-wire-replay.json):
request six is 11,402 bytes versus 12,872 without factoring at the same current
schema/policy, a 1,470-byte reduction. Historical request six was 11,719 bytes.
Earlier requests are larger than that historical run because diagnostic filters
were added; this change alone does not establish a latency improvement. The
native HTTP mock independently reconstructs the view and completes grounded
facts/contrary references through the real broker and isolated worker.

The selected follow-up also replaces the harness's hardcoded two-thread serving
profile with at most four CPUs, bounded by observed Linux affinity, and records
actual affinity/logical CPU counts. GitHub's [runner specification](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
lists four CPUs for public-repository Ubuntu runners; actual execution records
must confirm availability and throughput. This is a serving-resource comparison,
not a controlled single-variable speedup experiment. Weights, model size,
request timeout, context/output/request budgets, sampling, fixed questions and
loopback-only isolation remain unchanged. No paid/larger runner is selected.
Local 373 tests, static/security checks, executable historical compatibility,
five source demos and package builds pass. Actual-model results must be recovered
before claiming any investigation improvement.

## Four-CPU execution and compact native routing

[Run 40323112109](https://github.com/T-rex-G/SCRYVEIL/actions/runs/40323112109)
at `c0645134523e2be54ee3840e51767d09ec68179d` confirmed four affinity CPUs and
four serving threads. [Original result](model-experiments/qwen-run-40323112109.json),
[timing](model-experiments/qwen-run-40323112109-timing.json) and
[resources](model-experiments/qwen-run-40323112109-resources.json) preserve the
execution evidence. The model returned a six-step plan after 25.887s (510 input,
74 output tokens), then timed out after 60.067s on the 6,895-byte second request.
There were **zero evidence queries, accepted facts or completed reports**; the
collection was explicitly skipped. Last second-task prompt progress recorded
1,408 tokens at 58.5s, 24.07 tokens/s, displayed progress 0.93. No second-response
generation was observed. Four CPUs did not resolve this prompt bottleneck.

Originals/state remained unchanged. Server/evaluation wall time was 93.117s,
user CPU time 362.234s and largest-child RSS 6,604,616 KiB. Shutdown exited normally
in 4.422s; request-specific cancellation remains unconfirmed. Report digest was
verified against the preserved JSON. Factual precision is unmeasured with zero
claims; this run did not test adversarial exposure or hypothesis revision.
Changes in plan, wire schemas and resources prevent a controlled speedup claim.

The next bounded correction adds optional `native_tool_layout: "routed-v1"`
for the existing Messages adapter. One `forensic_query` client definition takes
an allowlisted dotted tool name and a bounded argument object. This is a compact
superset of query argument schemas; the isolated worker still validates each
selected tool's exact schema, references and limits. Plan/final schemas remain
separate. No tool, permission, evidence field or inference budget was added.
Default `individual-v1` behavior remains unchanged when the option is omitted.
The layout is part of the exact disclosure consent and provider report contract.

`python scripts/replay_native_request.py --layout routed-v1 --run 40323112109`
reconstructs the last failed context: [second request](native-routed-latest-replay.json)
is now **5,050 versus 6,895 bytes (26.8% less)**. The first request grows by 177
bytes for routing guidance. Replaying the older six-request trace with
`--layout routed-v1` yields [9,709 bytes for request six](native-routed-replay.json),
versus 11,402 in the current individual layout. These are wire-byte measurements,
not tokenizer, speed or reasoning results. Exact result reconstruction passes.

Both layouts complete an eight-step synthetic HTTP/broker/isolated-worker
investigation with exact facts and contrary references. Injected artifact text,
unknown tools, inappropriate arguments, excess result limits, cross-case IDs and
premature finals remain rejected. The first routed end-to-end test caught and
fixed a missing optional field in the embedded report-provider schema. Genuine
provider/model support requires actual execution; this change does not claim
Claude, GLM or universal provider compatibility. The next selected run retains
four available CPUs, pinned model/runtime, 60s requests and all existing budgets.
