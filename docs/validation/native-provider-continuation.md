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
