# Same-model investigation recovery comparison

[Run 40070459394](https://github.com/T-rex-G/SCRYVEIL/actions/runs/40070459394), job `120802573180`, executed exact source `dd27bf6970a8bc61ad357233bd94b2530c990d8a`. This was justified by the bounded feedback/context/completion changes after the [original reconciliation](qwen3-reconciliation.md). Model pins, non-thinking sampling, six questions, generated inputs, request/output/token/time limits and isolation stayed unchanged. The original [actions/reports](model-experiments/qwen-run-40070459394.json) and [resource measurements](model-experiments/qwen-run-40070459394-resources.json) are retained.

**Quality still failed.** Every action used the protocol correctly, but the model retrieved zero events in every scenario. It treated `text` as semantic search, sending phrases such as “recurring failures” to a literal substring filter. It then returned empty final objects. The strengthened nonempty-case gate rejected these, and the third identical rejected action stopped each loop. No permissions or factual validation were relaxed.

| Scenario | Outcome | Requests | Seconds | Actual records retrieved | Accepted facts |
|---|---|---:|---:|---:|---:|
| Mixed formats | repeated_action_limit | 7 | 97.013 | 0 | 0 |
| Recurrence | repeated_action_limit | 7 | 59.893 | 0 | 0 |
| Injected evidence | repeated_action_limit | 7 | 58.845 | 0 | 0 |
| Tool failure | repeated_action_limit | 6 | 49.133 | 0 | 0 |
| Missing evidence | completed, entirely empty response | 4 | 34.541 | 0 | 0 |
| Request-limit control | request_budget_exhausted | 2 | 11.494 | 0 | 0 |

The injected-failure scenario changed tools from diagnostics to timeline after the substituted failure, but retained the ineffective text filter. This demonstrates a changed query, not useful recovery. Injection text was never delivered. No findings were inspected, no hypotheses or contrary citations were accepted, and factual accuracy remains null because none were proposed. The empty-case completion omitted even unanswered questions; it is not a useful response.

Originals/state stayed unchanged in all cases and no forbidden tool was accepted. Model-facing request contexts were 5,920–8,522 bytes and their exact hashes/counts are retained. This bounds context growth; it does not establish reasoning improvement. The separate 30-report mock capacity regression now completes eight steps under the old budget. That is a scripted engineering result.

Server/evaluation wall time was 312.931 seconds, child user CPU 620.417 seconds, system CPU 1.056 seconds, largest-child peak RSS 6,696,048 KiB. Build/download are excluded, memory is not a concurrent aggregate, and no monetary rate was configured. These sequential shared-runner measurements are not controlled latency benchmarks.

## Next narrowly justified correction

The next comparison is justified by the observed retrieval mistake: add immediate owner-authored guidance after zero-match queries, explain literal substring/AND-filter semantics, and show a valid unfiltered action without executing it. Use one leading policy message and alternating assistant/user exchanges, avoiding dependence on a server's treatment of trailing system messages. Require an explicit unanswered question before an empty snapshot can complete. Keep the same model, questions, evidence and budgets; this is a combined protocol-presentation correction, not an isolated causal experiment on each subchange. Results must be reviewed before claiming improvement.

This report intentionally records the failure before that follow-up. The native server/model remains trusted software inside a loopback-only evaluation namespace. Private/genuine Apple-export qualification remains open and separate from synthetic model testing.
