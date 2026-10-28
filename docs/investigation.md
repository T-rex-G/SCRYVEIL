# Diagnostic investigation operator guide

This is an experimental Linux/Python 3.12+ CLI with a real read-only investigation protocol. It has no live acquisition and no validated spyware verdict. Only generated diagnostic fixtures have been executed. A pinned Qwen model has been measured on those fixtures; genuine Apple exports and useful model reasoning remain qualification gates. See the [measured milestone](validation/diagnostic-model-milestone.md). The default provider is a deterministic mock, requiring no credits or network.

## Run the complete offline example

Install as in the README. Investigation additionally needs the system `libseccomp.so.2` library (commonly the distribution's `libseccomp2` package). It is not bundled. All three modes fail closed if the investigator's Linux policy cannot be installed. Deterministic reports do not require this library.

```sh
python scripts/investigation_demo.py
```

An [executed synthetic report](examples/investigation-synthetic.json) is included with the repository. Its temporary case identifiers are fictional and all supporting original bytes are the public generated fixtures.

Expected: five events from four fictional reports, four distinct reported incidents, one nonfatal contrary record, eight provider steps, unchanged originals/state and identical repeated reports. The Jetsam process without a termination reason is not counted as a killed process. This is workflow validation, not a real incident investigation.

For a persistent fictional case:

```sh
umask 077
CASE_ID=$(scryveil case create --label synthetic-diagnostics --consent self | python -c 'import json,sys; print(json.load(sys.stdin)["case_id"])')
scryveil evidence import --case "$CASE_ID" --format ips --synthetic fixtures/synthetic/diagnostic-0.ips
scryveil evidence import --case "$CASE_ID" --format ips --synthetic fixtures/synthetic/diagnostic-1.ips
scryveil diagnostics report --case "$CASE_ID"
scryveil investigate run --case "$CASE_ID" --question 'What supports or contradicts recurring service failures?'
```

`diagnostics report` performs deterministic analysis without AI and without changing stored analysis. It returns `scryveil.snapshot/1`, including events, findings and coverage. `investigate run` returns `scryveil.investigation/1`. Output is JSON on stdout. Explicitly redirect it to a separately chosen private output file if desired; the investigator cannot select or write an output path. Do not redirect onto a source/case file. Use an encrypted host volume for private cases and keep them outside the checkout.

For an independently authorized actual export, omit `--synthetic`; do not upload it or its report to GitHub. `--format ips` is required. The old default remains NDJSON; importing the same bytes using a different parser selection is an explicit conflict, not an invisible reinterpretation. Existing 0.1.0 cases remain readable by the new code. New diagnostic event types are additive to the published schema; older binaries are not promised to read IPS-bearing cases.

## Supported diagnostic scope

The explicit IPS route reads a JSON metadata line, then dispatches on `bug_type`:

| Declared format | Current bounded interpretation |
|---|---|
| 309 / 308, JSON body version 2 | Process, exception/termination, signed raw codes, capture time and simulation/lightweight-corpse declarations; 308 is a diagnostic exception, not automatically fatal |
| 145, disk-write text Report Version 29 | Top summary through the first stack/powerstats section; start/end interval, action taken, displayed quantities and units, exact line bytes |
| 309 body version 104 / 298 Jetsam | Original compatibility reader retained; 104 is the old synthetic profile, not a claim that Apple's modern JSON body schema is version 104 |

New observations expose `format_profile`, `schema_status` and `interpretation_status`. Recognized fields remain a partial interpretation. Other body/report versions warn as unqualified; unknown report types or resource events are rejected. Stacks/powerstats in text reports, panic/stackshots, symbolication and arbitrary IPS streams are unsupported. No original is rewritten. Disk-write units/decimals are preserved as displayed; rounded MB amounts are not silently converted to exact bytes. Report start/end times are separate from metadata tracking time. `python scripts/diagnostic_formats_demo.py` exercises these distinctions with fictional fixtures.

For crashes: declared process/PID/path/bundle/parent, exception, termination, source time and at most 32 faulting frames. For Jetsam: per-process rows, optional reason, resident pages and declared page size. Invalid optional fields become unknown with fixed warning codes. Missing/invalid event time is never replaced by import time or metadata tracking time. Known fields are a subset; no symbolication or inferred stack is performed.

Recurrence groups declared process names and counts distinct non-null incident IDs. Same-name processes from different devices/versions can group; the report says identity is unverified. Nonfatal/simulated entries and resource reports declaring `Action taken: none` are contrary evidence to an assertion that every report is a fatal crash. This detector cannot decide between a software defect, resource pressure or an attack.

## Configure a local model endpoint

Use a model already installed and independently configured to operate offline. SCRYVEIL neither downloads models nor starts servers. A local server's logging, plugins, cloud routing and retention remain the owner's responsibility. For a suitable Ollama server, the endpoint shape is `http://127.0.0.1:11434/v1/chat/completions`; llama.cpp commonly exposes the same path on its configured port. A pinned llama.cpp/Qwen CPU configuration was actually measured with generated cases and an isolated network namespace. Its initial quality failure and subsequent results are in the [milestone report](validation/diagnostic-model-milestone.md); it is not a production model recommendation. Ollama and external providers remain untested.

Create an owner-only config outside the checkout; replace the model with the exact locally installed model name:

```json
{
  "schema_version": "scryveil.provider/1",
  "adapter": "chat-completions-json",
  "mode": "local",
  "endpoint": "http://127.0.0.1:11434/v1/chat/completions",
  "model": "OWNER_SELECTED_LOCAL_MODEL",
  "max_requests": 12,
  "timeout_seconds": 30,
  "max_context_bytes": 131072,
  "max_output_tokens": 2048,
  "max_total_tokens": 131072
}
```

```sh
chmod 600 /private/config/local-provider.json
scryveil investigate preview --case "$CASE_ID" --question 'Why does the named service repeatedly fail?' --provider-config /private/config/local-provider.json
scryveil investigate run --case "$CASE_ID" --question 'Why does the named service repeatedly fail?' --provider-config /private/config/local-provider.json
```

Only literal `127.0.0.1`/`::1` HTTP endpoints are accepted in local mode; `localhost` DNS, LAN hosts and proxy settings are not used. Default snapshots replace app/process/domain identifiers with case-local references. If asking about a named process, explicitly add `--include-identifiers` to preview and run when that disclosure is appropriate. It also includes selected paths, OS fields, termination strings and stack symbols; review the resulting preview. Otherwise the model can correlate aliases but cannot identify them from their private names.

The server must support non-streaming chat-completions with `response_format: {"type":"json_object"}` and return a JSON action inside `choices[0].message.content`. This adapter does not support native Responses, streaming or tool calls. The separate experimental `messages-tools` adapter below supports a bounded Messages client-tool subset. Arbitrary base paths remain unsupported. A compatible HTTP endpoint does not guarantee that a model will follow the action schema or reason well.

## Optional external provider: preview and exact consent

Change the adapter config to `mode: "remote"`, a configured public `https://…/v1/chat/completions` endpoint and a supported model. If needed, set `api_key_env` to a dedicated `SCRYVEIL_…` environment variable populated outside shell history/source control. Never put a key in JSON, a case, a question or the repository. Endpoint userinfo, query strings, fragments and private remote DNS destinations are rejected; TLS verification cannot be disabled by config.

Run `investigate preview` with the exact question/options/config. It performs no provider request and reads no credential. Inspect the categories, counts, omitted records, snapshot size, question and identifier flag. It lists a maximum cumulative serialized-context byte budget; HTTP framing/config metadata add overhead, and conversation history can repeat evidence. Hashes/times remain sensitive even when identifiers are omitted.

Only after explicit owner approval of that manifest, run the same command as `investigate run` with `--consent-sha256` set to the displayed digest. There is deliberately no automatic preview-to-consent pipeline. Any changed scope, config, question, budget or case requires a fresh preview and owner acknowledgment. Configuration alone never transmits case data. Consent covers bounded queries within this selected snapshot, not unlimited future cases or destinations.

## Custom URLs, gateways and API keys

Choose the wire adapter and model independently from the service address. Use
exactly one of `base_url` or `endpoint`. A base URL appends a documented suffix;
`endpoint` sends to the exact custom path. Prefixes are preserved, no version is
guessed, and preview shows the resolved endpoint before consent.

| Adapter | Example base URL | Resolved request path |
|---|---|---|
| `messages-tools` | `https://api.apmix.ai` | `/v1/messages` |
| `chat-completions-json` | `https://api.apmix.ai/v1` | `/v1/chat/completions` |
| `messages-tools` | `https://api.minimax.io/anthropic` | `/anthropic/v1/messages` |
| `messages-tools` | `https://gateway.example.invalid/team/proxy` | `/team/proxy/v1/messages` |

For a gateway route such as `/team/infer`, set the full `endpoint` instead.
Trailing base slashes are removed. `auth_scheme: "bearer"` sends an Authorization
Bearer header; `auth_scheme: "x-api-key"` sends that header instead. Omission
preserves historical defaults: Bearer for JSON-action and `minimax-v1`, otherwise
x-api-key for Messages. No inline key, arbitrary headers or provider code is
accepted. Only `api_key_env` names the dedicated `SCRYVEIL_…` environment variable;
its value stays in the broker, outside model messages and reports.

Example for the owner's selected gateway (candidate, **not live-qualified**):

```json
{
  "adapter": "messages-tools",
  "mode": "remote",
  "base_url": "https://api.apmix.ai",
  "auth_scheme": "x-api-key",
  "model": "minimax/minimax-m3.1-flash",
  "messages_profile": "minimax-v1",
  "reasoning_effort": "medium",
  "api_key_env": "SCRYVEIL_PROVIDER_API_KEY",
  "max_requests": 12,
  "timeout_seconds": 60,
  "max_context_bytes": 131072,
  "max_output_tokens": 4096,
  "max_total_tokens": 200000
}
```

Save owner configuration with mode `0600`. The reviewed fictional benchmark
configuration is [configs/qualification-provider.json](../configs/qualification-provider.json).
Change the URL, model and adapter to match another service's documented API;
changing service does not require a source-code edit. `messages_profile` and
`reasoning_effort` apply only to the tested MiniMax-style Messages protocol;
omit them for the default Messages contract or JSON-action adapter. SCRYVEIL
supports these two wire contracts, not arbitrary proprietary APIs, native
Chat Completions tool calls, Responses or universal model compatibility.

Public HTTPS, certificate checks, public-address DNS pinning and exact consent
still apply to remote URLs. Local mode still requires literal loopback HTTP.
Queries/fragments, userinfo, controls, backslashes, dot segments and ambiguous
encoded routes are rejected. There is no URL discovery, redirect following,
proxy, automatic fallback or model-controlled destination. A new destination,
route, authentication setting or protocol requires a new disclosure approval.

[Apmix's model page](https://apmix.ai/models/minimax-m3.1-flash) documents both
wire endpoints and x-api-key for Messages. Its [privacy policy](https://apmix.ai/privacy)
says requests may go through vendor or intermediary infrastructure. The consent
destination is apmix, not direct MiniMax. Its weighted-token subscription is
not the direct vendor's USD rate; leave USD rates unset unless independently
applicable to your account. Gateway translation, supported effort parameters,
model identity and actual reasoning remain unverified until a reviewed run.

## Tool contract and limits

All tools are `scryveil.tools/1`, and all errors are structured codes without raw paths/provider bodies. See [input](../schemas/investigator-tools-v1.schema.json) and [output](../schemas/investigator-results-v1.schema.json) schemas; choose the output `$defs` entry matching the requested tool.

| Tool | Input / result boundary |
|---|---|
| `case.inspect` | No arguments; snapshot digest and counts |
| `coverage.inspect` | No arguments; selected/omitted counts, families and absent sources |
| `evidence.list` | Optional cursor/limit; artifact hashes, format, size and warnings, never filenames |
| `integrity.verify` | No arguments; verification at snapshot creation, not a new filesystem read |
| `timeline.query`, `diagnostics.search`, `network.query` | Optional type/process/app/domain reference, explicit-offset start/end, literal text ≤128 characters, cursor and limit 1–25; matched count and next cursor |
| `process.inspect` | Required local process reference; bounded matching event page; no inferred identity |
| `evidence.read_excerpt` | Required event ID; normalized/minimized event, never raw file access |
| `findings.inspect` | Optional cursor/limit; deterministic findings, support, contradictions and alternatives |
| `hypotheses.compare` | Required finding ID; that finding's deterministic alternatives and evidence; no model assertion becomes a fact |

Snapshot: earliest 2,000 events by default, configurable 1–20,000 with `--max-events`, maximum 16 MiB. Unknown times sort last. Omitted count is explicit; this is selection, not representative sampling or a complete investigation. Queries are inclusive in UTC; missing source times do not match time ranges. Results cap at 64 KiB. Large findings/identifier-rich excerpts can return `tool_result_too_large`; they are not silently clipped into a misleading complete result. Source files retain the existing 8 MiB limit, with at most 1,024 artifacts/20,000 events per case (256 MiB total originals); the explicit ZIP route has separate bounded archive limits. The original 30-report probe exhausted its budget after six steps. With compact context, three fresh samples now complete eight mock steps using 185203 of an explicitly selected 200000-unit budget. This does not qualify the smaller default budget, larger cases or real-model reasoning. Prefer focused queries/pages and inspect incomplete status.

Provider budgets: 1–32 requests, 1–60 seconds each, 4–256 KiB serialized context, 128–8,192 requested output tokens, and 1,024–200,000 estimated total token units. Estimates use context bytes plus output tokens, not the provider's tokenizer. Reported usage is included when valid; missing usage/cost stays unknown. Rates are optional `input_usd_per_million` / `output_usd_per_million`; cost is an estimate, not a billing guarantee. No automatic retry or framework loop runs beyond these limits.

## Reading results and recovering failures

For explicit diagnostic omissions and interpretation status, run `scryveil --root PRIVATE_CASE_ROOT diagnostics coverage --case CASE_ID --max-events 2000`. The offline owner report binds to the verified selected snapshot, lists artifact-linked warnings and categories absent from that selection, and leaves unimported/rejected-file counts unknown. It does not infer complete device history. See [resource and coverage qualification](validation/resource-format-continuation.md). The established default `coverage.inspect` tool remains unchanged.

A completed report contains the question, plan, tool trace with result hashes, coverage, deterministic findings, exact-field observed facts, derived measurements, unresolved hypotheses, contrary evidence and unanswered questions. Evidence references point to original artifact IDs, byte regions and, JSON fields, JSON pointers; selected text fields carry their exact physical line/byte span. An exact reference proves where a value came from, not that the source or hypothesis is true. Reports include sensitive metadata and model text; review before sharing or rendering elsewhere.

Exit 0 means a completed workflow, not forensic accuracy. Exit 2 includes imported-field warnings; inspect them. Exit 3 includes incomplete/budget-limited investigations; partial reports retain status/trace. Exit 4 includes isolation/integrity/local-state failures. Ctrl-C returns 130, with a partial report if the investigation loop had started. Fixed error codes include `remote_disclosure_consent_required`, `tool_not_allowed`, `reference_out_of_scope`, `unsupported_factual_claim`, `context_budget_exhausted`, `token_budget_exhausted`, `provider_token_budget_exceeded`, `provider_failed`, `provider_timeout`, `repeated_action_limit` and `rejected_action_limit`.

Reruns are explicit, reverify originals and may incur fresh provider requests. There is no automatic resume. The mock report is reproducible for the same case/config/question; actual model output is not promised deterministic. Unsupported or missing sources do not establish a clean device.

## Reproduce model measurements safely

`python scripts/model_qualification.py --mock` checks scripted mechanics.
For another model, supply `--provider-config PRIVATE_CONFIG --preview`; see
[the qualification procedure](validation/provider-qualification.md) for the
consent-bound seven-scenario workflow. Only fixed fictional cases are generated;
there is no owner evidence-path option. Remote inference needs an exact approved
plan, while ordinary case analysis retains its separate disclosure consent.

The [historical local workflow](../.github/workflows/model-qualification.yml)
still pins Qwen weights/runtime and starts server/evaluator in a loopback-only
network namespace. Selecting it requires `--pinned-qwen-baseline`; its opt-in
CI marker remains `[model-qualification]`. There is no unchanged Qwen rerun
scheduled and no implied preferred model.

Review the recorded actions and final narrative alongside exact-field accuracy, contrary citations, query count, errors and budgets. A null accuracy or unexposed injection scenario is unmeasured, not a pass. Actual run outcomes are preserved even when the workflow process exits successfully. No private evidence may be substituted into this public CI harness.

## Investigation-loop recovery qualification

The runtime now stops after three identical rejected actions or five consecutive rejections, preserving a partial report. Rejections include explicit corrective guidance; no invalid action is silently repaired or executed. A nonempty snapshot must yield an actually read event and a grounded field fact before completion, and available deterministic findings must be consulted. An empty case must include an explicit unanswered question. Zero-match guidance explains literal substring filters; it never executes a replacement query. A completed report still requires independent assessment of relevance and hypothesis semantics.

Model context retains up to eight unique recent successful query exchanges plus the plan/latest rejection. Duplicate/older query views can be replaced or evicted with an explicit omission count; the model may re-query. Repeated source-locator bookkeeping is omitted from the model view, while full responses remain in the report trace and accepted facts receive worker-supplied source citations. `context.policy` records `scryveil.context/1`. This changes presentation, not tool permissions, original records, disclosure authorization or budgets.

See [Qwen3 reconciliation](validation/qwen3-reconciliation.md) and [continuity](continuity/SCRYVEIL_WORK_HANDOFF.md). The fixed 30-report mock workload now completes within the previous budget; it is not evidence of improved real-model reasoning. The [two changed-runtime comparisons](validation/qwen3-recovery-comparison.md) remain quality failures: the latest retrieved real records from its generated case in two scenarios, then timed out before conclusions. No actual-model factual claim was accepted.

The [collection workflow](collections.md) adds `--all-events` (complete bounded case or failure), `--diagnostic-details` (separate permission scope), paged inventories and diagnostic signature/resource measurements. These options do not alter default historical snapshot projections. New full-case event queries default to five rows; all eleven tools remain read-only.


## Experimental native Messages adapter

Use `adapter: "messages-tools"` with an explicitly configured loopback HTTP or consent-controlled public HTTPS endpoint. Custom bases/routes are described above. The remaining model, budget and credential options are unchanged. No model is selected automatically. This is a wire-protocol capability, not a claim that Claude, Qwen or any other model is a qualified investigator.

The adapter implements the [Messages client-tool lifecycle](https://platform.claude.com/docs/en/agents-and-tools/tool-use/handle-tool-calls): separate system instructions, `tool_use`/`tool_result` blocks, `x-api-key` credentials and explicit [API version](https://platform.claude.com/docs/en/api/versioning) `2023-06-01`. Public protocol documentation and the pinned local server's implementation informed this original translation; no SDK or agent framework was added. Native tool aliases replace dots with underscores; the worker still authorizes exactly the existing eleven tools. Plan/final operations remain bounded session actions, not additional evidence permissions.

Only the plan definition is advertised until the supervisor records an accepted plan. All eleven queries are then advertised; final submission is added when retained history contains two distinct successful query tools. The worker still requires retrieved evidence, reviewed findings and valid claims. Compacted query views may need re-querying before the final schema is advertised again. History compaction preserves complete call/result pairs; rejected arguments are retained for feedback, never silently repaired. Exactly one client call is accepted per response. Text beside a call is not a forensic claim and is discarded; thinking, server tools, parallel calls, truncation and text-only replies fail closed. Native HTTP/protocol errors are sanitized codes; response bodies are not disclosed.

The native budget includes the complete serialized request, including tool definitions and message wrappers. Cached read/creation input tokens are included in input totals. Optional flat-rate cost estimates do not model distinct cache prices or provider fees. No automatic retry, tool execution, stream, caching policy or additional network permission is introduced. Remote disclosure requires a new preview/consent digest when changing the adapter. Hosted API execution remains untested; synthetic HTTP peers establish only transport/protocol behavior.

The selected CI comparison uses the same pinned local Qwen3 weights and recurrence ground truth with native client tools, explicit Jinja support and improved numeric prompt/generation telemetry. It is justified by the prior invalid-action failures and first-request timeout, not a claim that native calls cure reasoning. Results must be assessed separately from successful CI exit.

Native compact context is reported as `scryveil.context.native/1`: a stable system policy plus a bounded owner-state text block after the latest native tool result. Full worker string/byte limits remain enforced; repeated string-length hints and redundant empty `required` lists are omitted only from model-facing schemas. Page/numeric/array limits and nonempty required/type/unknown-key checks remain in the wire schema. The public collection benchmark is gated on a completed recurrence report with facts, coverage and contrary citations; a skipped collection is not a pass. See the [reconciled native measurements](validation/native-provider-continuation.md).

For servers with expensive tool-schema prefill, the Messages adapter also accepts
`"native_tool_layout": "routed-v1"`. It advertises one `forensic_query` client tool
with an allowlisted dotted name and bounded arguments instead of eleven repeated
query schemas. The same eleven worker operations and exact per-tool validation
remain authoritative; this does not enable arbitrary tools. Plan/final calls are
unchanged. Omitting the setting (or selecting `individual-v1`) retains separate
native definitions. The choice changes the disclosure digest and requires fresh
remote consent. This is experimental protocol configuration, not a qualified
model recommendation. See the measured native validation before selecting it.

### MiniMax Messages profile (experimental)

Use `adapter: "messages-tools"`, `messages_profile: "minimax-v1"`, an explicit
`reasoning_effort` (`low`, `medium`, `high`, `xhigh`, or `max`), and
a configured Messages endpoint. The direct service uses
`https://api.minimax.io/anthropic/v1/messages`; gateways can use another path. Select the model explicitly;
SCRYVEIL does not choose a vendor or model for ordinary cases. The prepared
fictional gateway benchmark selects `minimax/minimax-m3.1-flash` at apmix.
This profile defaults to Bearer authentication through a dedicated
`SCRYVEIL_…` environment-variable reference; `auth_scheme` can override it. Existing native and JSON-action
configurations retain their behavior. Changing profile/effort invalidates
existing disclosure consent.

This profile preserves bounded assistant `thinking`, `text` and `tool_use`
blocks and original call IDs when returning subsequent tool results. Those
blocks are untrusted protocol state, not evidence: they never enter the worker
or reports. Each continuation must translate to exactly the proposed logical
action before it can reach the worker. Rejected actions receive normal bounded
feedback, and compaction removes complete exchanges. The retained wire content
counts toward request/context budgets. Images, server tools, parallel calls,
unknown blocks, oversized state and truncated replies remain unsupported.
Exact credential echoes from a provider response are rejected; this is a
narrow defense, not a complete secret-leak detector.

The provider's Flash model always uses thinking; the profile does not attempt
to disable it. `output_config.effort` is explicit rather than inheriting the
provider's maximum default. Tool choice is `auto` with parallel tools disabled;
text-only responses fail closed instead of becoming unvalidated reports.
Synthetic HTTP peers exercise full native round trips and grounding. Hosted
API compatibility, latency, reasoning quality and provider retention remain
unqualified until an authorized actual-model run is reviewed.

For the fixed fictional evaluation, see
[the qualification procedure](validation/provider-qualification.md).
Never paste a credential into chat, JSON config, command arguments, evidence or
Git. A GitHub Actions repository secret can hold a dedicated test key while the
repository remains public. Configuring that secret does not select a test or
authorize private evidence disclosure.

## Check a provider catalog without disclosing evidence

`scripts/provider_access_check.py` is an owner-operated diagnostic, separate from the eleven investigator tools. Supply an explicit same-origin catalog URL and specific candidate IDs. It supports the `data: [{id: ...}]` list shape; other protocols fail closed. It makes one GET, sends no body or case data, never follows pagination/redirects and never launches inference. A listed ID does not prove entitlement, free pricing, model identity or tool compatibility. A non-listed ID may still be an accepted alias or on an unrequested page.

```sh
python scripts/provider_access_check.py --provider-config PRIVATE_CONFIG \
  --catalog-endpoint https://YOUR_GATEWAY/v1/models \
  --catalog-auth-scheme bearer --candidate-model YOUR_MODEL --preview
```

Review the exact destination, credential reference, auth and source digest. Repeat with `--approve-plan-sha256 REVIEWED_DIGEST` instead of `--preview` to perform the single GET. Omit `--catalog-auth-scheme` to use the configured auth scheme. Credentials stay in the referenced environment variable; never pass them as arguments. Neither preview nor catalog inspection grants consent to send forensic evidence.

Known native API error codes are reported as `provider_http_STATUS_CODE`; unknown error bodies remain `provider_http_STATUS`. The suffix is an allowlisted provider assertion, not a verified account diagnosis. Free-form messages/identifiers are suppressed; credential echoes fail closed. Correct access/configuration before explicitly selecting another inference run.
