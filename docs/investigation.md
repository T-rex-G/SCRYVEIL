# Diagnostic investigation operator guide

This is an experimental Linux/Python 3.12+ CLI with a real read-only investigation protocol. It has no live acquisition and no validated spyware verdict. Only generated diagnostic fixtures have been executed; real Apple exports and model quality remain qualification gates. The default provider is a deterministic mock, requiring no credits or network.

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

Two JSON objects: one metadata line, then the JSON body. Supported dispatch: `bug_type` string `309` and `298`. Body crash version 104 is the qualified synthetic shape; other versions warn. Resource exceptions are supported when represented as a 309 JSON report with `EXC_RESOURCE`; separate text/resource formats (for example 142), stackshots, panic reports and arbitrary IPS streams are unsupported. Original bytes remain unchanged.

For crashes: declared process/PID/path/bundle/parent, exception, termination, source time and at most 32 faulting frames. For Jetsam: per-process rows, optional reason, resident pages and declared page size. Invalid optional fields become unknown with fixed warning codes. Missing/invalid event time is never replaced by import time or metadata tracking time. Known fields are a subset; no symbolication or inferred stack is performed.

Recurrence groups declared process names and counts distinct non-null incident IDs. Same-name processes from different devices/versions can group; the report says identity is unverified. Nonfatal/simulated entries are contrary evidence to an assertion that every report is a fatal crash. This detector cannot decide between a software defect, resource pressure or an attack.

## Configure a local model endpoint

Use a model already installed and independently configured to operate offline. SCRYVEIL neither downloads models nor starts servers. A local server's logging, plugins, cloud routing and retention remain the owner's responsibility. For a suitable Ollama server, the endpoint shape is `http://127.0.0.1:11434/v1/chat/completions`; llama.cpp commonly exposes the same path on its configured port. Actual versions/models are untested here.

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

The server must support non-streaming chat-completions with `response_format: {"type":"json_object"}` and return a JSON action inside `choices[0].message.content`. Native Responses, Messages, streaming, provider-native tool calls and arbitrary base paths are unsupported. A compatible HTTP endpoint does not guarantee that a model will follow the action schema or reason well.

## Optional external provider: preview and exact consent

Change the adapter config to `mode: "remote"`, a configured public `https://…/v1/chat/completions` endpoint and a supported model. If needed, set `api_key_env` to a dedicated `SCRYVEIL_…` environment variable populated outside shell history/source control. Never put a key in JSON, a case, a question or the repository. Endpoint userinfo, query strings, fragments and private remote DNS destinations are rejected; TLS verification cannot be disabled by config.

Run `investigate preview` with the exact question/options/config. It performs no provider request and reads no credential. Inspect the categories, counts, omitted records, snapshot size, question and identifier flag. It lists a maximum cumulative serialized-context byte budget; HTTP framing/config metadata add overhead, and conversation history can repeat evidence. Hashes/times remain sensitive even when identifiers are omitted.

Only after explicit owner approval of that manifest, run the same command as `investigate run` with `--consent-sha256` set to the displayed digest. There is deliberately no automatic preview-to-consent pipeline. Any changed scope, config, question, budget or case requires a fresh preview and owner acknowledgment. Configuration alone never transmits case data. Consent covers bounded queries within this selected snapshot, not unlimited future cases or destinations.

## Tool contract and limits

All tools are `scryveil.tools/1`, and all errors are structured codes without raw paths/provider bodies. See [input](../schemas/investigator-tools-v1.schema.json) and [output](../schemas/investigator-results-v1.schema.json) schemas; choose the output `$defs` entry matching the requested tool.

| Tool | Input / result boundary |
|---|---|
| `case.inspect` | No arguments; snapshot digest and counts |
| `coverage.inspect` | No arguments; selected/omitted counts, families and absent sources |
| `evidence.list` | No arguments; artifact hashes, format, size and warnings, never filenames |
| `integrity.verify` | No arguments; verification at snapshot creation, not a new filesystem read |
| `timeline.query`, `diagnostics.search`, `network.query` | Optional type/process/app/domain reference, explicit-offset start/end, literal text ≤128 characters, cursor and limit 1–25; matched count and next cursor |
| `process.inspect` | Required local process reference; bounded matching event page; no inferred identity |
| `evidence.read_excerpt` | Required event ID; normalized/minimized event, never raw file access |
| `findings.inspect` | No arguments; deterministic findings, support, contradictions and alternatives |
| `hypotheses.compare` | Required finding ID; that finding's deterministic alternatives and evidence; no model assertion becomes a fact |

Snapshot: earliest 2,000 events by default, configurable 1–20,000 with `--max-events`, maximum 16 MiB. Unknown times sort last. Omitted count is explicit; this is selection, not representative sampling or a complete investigation. Queries are inclusive in UTC; missing source times do not match time ranges. Results cap at 64 KiB. Large findings/identifier-rich excerpts can return `tool_result_too_large`; they are not silently clipped into a misleading complete result. Source files retain the existing 8 MiB limit, with at most 32 artifacts/20,000 events per case.

Provider budgets: 1–32 requests, 1–60 seconds each, 4–256 KiB serialized context, 128–8,192 requested output tokens, and 1,024–200,000 estimated total token units. Estimates use context bytes plus output tokens, not the provider's tokenizer. Reported usage is included when valid; missing usage/cost stays unknown. Rates are optional `input_usd_per_million` / `output_usd_per_million`; cost is an estimate, not a billing guarantee. No automatic retry or framework loop runs beyond these limits.

## Reading results and recovering failures

A completed report contains the question, plan, tool trace with result hashes, coverage, deterministic findings, exact-field observed facts, derived measurements, unresolved hypotheses, contrary evidence and unanswered questions. Evidence references point to original artifact IDs, byte regions and, for Jetsam processes, JSON pointers. An exact reference proves where a value came from, not that the source or hypothesis is true. Reports include sensitive metadata and model text; review before sharing or rendering elsewhere.

Exit 0 means a completed workflow, not forensic accuracy. Exit 2 includes imported-field warnings; inspect them. Exit 3 includes incomplete/budget-limited investigations; partial reports retain status/trace. Exit 4 includes isolation/integrity/local-state failures. Ctrl-C returns 130, with a partial report if the investigation loop had started. Fixed error codes include `remote_disclosure_consent_required`, `tool_not_allowed`, `reference_out_of_scope`, `unsupported_factual_claim`, `context_budget_exhausted`, `token_budget_exhausted`, `provider_token_budget_exceeded`, `provider_failed` and `provider_timeout`.

Reruns are explicit, reverify originals and may incur fresh provider requests. There is no automatic resume. The mock report is reproducible for the same case/config/question; actual model output is not promised deterministic. Unsupported or missing sources do not establish a clean device.
