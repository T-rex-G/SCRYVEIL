# ADR-001 — Runtime and language selection

- Date: 2026-10-22
- Status: **Accepted for the bounded Phase 1; performance gate reopened 2026-10-23.** Revisit before archive acquisition or desktop distribution.
- Authority: owner's stack-neutral v2 directive replaces v1's Python prescription.
- Decision: **retain a typed Python 3.12+ single-process offline core with no runtime third-party packages.** No Python upstream library is embedded. Keep versioned JSON contracts at acquisition, parser and report boundaries. No Rust, Go, Swift or TypeScript production component yet.
- This is a scope-dependent engineering choice, not a claim that Python is universally fastest, safest or the permanent implementation of every module.

## 1. Workloads and decision criteria, before languages

The immediate deliverable imports tiny owner-exported NDJSON, retains original bytes and hashes, normalizes explicit-offset timestamps, calculates transparent statistics, links claims to sources and exports deterministic reports. It must run without phone access, model accounts or cloud services. First release limits: 8 MiB/file, 64 KiB/line, 5,000 lines/import, 20,000 normalized records/case and 32 originals. These are intentional workload limits, not iOS device limits.

Separate future workloads: large binary/archive/SQLite/SEGB parsing; multi-million-event graph queries; sustained USB capture; native OS permissions; visual exploration. Those have different safety, concurrency and distribution pressures and are not justified by the tiny first release. Language choice does not make an undocumented Apple service public, authorize pairing, or confer device privileges.

Explicit priority order (not pseudo-precise performance scores):

1. **Hard gates:** byte preservation and source lineage; no invented timestamps; bounded hostile input; offline/no telemetry; transparent unsupported capabilities; licensing compatible with what is actually shipped.
2. **High:** auditability, testability, correctness under malformed records, practical interoperation with maintained tools, small dependency surface, reproducible builds and migration without evidence loss.
3. **Medium for M1:** startup/throughput/RSS within a stated budget; straightforward local installation; development/debugging burden.
4. **High at desktop milestone, medium now:** standalone binaries, Windows/macOS packaging, sustained large-case performance. Weight rises when an actual desktop deployment requirement exists.

No candidate wins merely because existing tools use its language or because a compiler is locally installed. Compiler availability limits this experiment's evidence, not architecture feasibility.

## 2. Existing work and sunk-cost control

Before correction, the uncommitted v1 prototype contained `models`, `parse`, `store`, `engine`, `report`, `cli`, generated fixtures and adversarial tests. No implementation commit or PR had been published. First static check exposed an argparse return-type error; validation was incomplete. This is a candidate, not established verified product progress. Source research and fixtures remain valuable in any runtime.

Retaining this code has **no weight in the runtime comparison**. Reusable findings independently favor strict date handling, separate APR summaries, audit logs and allowlisted reports. A green test gate and corrections are required after this decision. Review findings include broad `Any` in internal state, synchronous whole-state serialization, advisory-only filesystem controls, and no signed audit anchor. Do not equate typing or a hash chain with forensic correctness.

## 3. Comparative decision matrix

| Dimension / priority | Python core | Rust core + external tools | Go core + external tools | Swift core/helper | TypeScript/Node core/UI |
|---|---|---|---|---|---|
| Forensic auditability (hard) | Explicit-offset datetime, integer precision, stdlib JSON hooks; runtime validation required | Enums/Result and ownership aid invariants; timestamp/JSON semantics still must be specified | Strong typed structs/errors; distinguish absent/zero and JSON number conversion | Typed Codable/error paths; explicit date precision needed | Types erased; runtime validation essential; JS Date alone loses sub-ms precision |
| Hostile parsing (hard) | Managed objects, but CPython/native stdlib remain trusted; size/depth limits needed | Strong safe-Rust memory guarantees; unsafe/FFI/dependencies and allocation DoS remain | Managed memory; GC/unsafe/cgo and allocation DoS remain | ARC/value semantics; unsafe pointers/C bridges remain | Managed V8 heap; native runtime/addons and prototype/property hazards remain |
| Resource control (high) | Current bounded workload feasible; full-state copies expensive | Good candidate for isolated binary parsing and predictable layouts; NOT MEASURED | Strong candidate for streams and single CLI; GC overhead NOT MEASURED | Native parsing plausible; NOT MEASURED | Stream APIs viable; current comparison measured, broader behavior unknown |
| Secure subprocesses (high) | argv, timeout, output budget possible; no subprocess adapters shipped | Command argv and child lifetime possible; sandbox is OS responsibility | exec.CommandContext possible; process-tree cleanup still needed | Process executableURL/arguments possible; OS sandbox separate | execFile avoids shell by default; maxBuffer/timeout required; no adapters shipped |
| Apple service compatibility (high future) | PMD3 broad source-reviewed services; GPL/custom license/tool limits | `idevice` has real pcapd/lockdown/RSD; API explicitly research-stage | `go-ios` has real pcapd/profile/lockdown; MIT, substantial dependencies | Apple host frameworks/UI useful; Swift alone does not expose every phone service | Usually external native/tool bridge; UI language does not add acquisition rights |
| MVT/iLEAPP/SAF interop (high) | Same runtime does NOT make direct import desirable; pin CLI contracts | Versioned local subprocess output; separate Python environment | Same process contract; separate Python environment | Same contract; separate tool environment | Same contract; separate tool environment |
| Packaging/portability (medium M1) | Requires supported interpreter; wheel easy; standalone bundling is extra work | Per-target binaries attractive; native library/signing work remains | Pure-Go cross-build/binary attractive; cgo/native transport complicates | Linux/Windows supported; macOS frameworks not portable; static Linux SDK has constraints | Node runtime or SEA packaging; UI separate; native addon matrix possible |
| Iteration/debugging (high) | Small original format rules are easy to inspect; tests/types required | Ownership/types valuable; compiler/dependency/build work for every parser change | Straightforward static CLI development; good standard tooling | Best native Apple integration/debugging with Apple toolchain | Strong UI tooling, but schema/date correctness and npm surface need discipline |
| CI/cost (high) | One Linux interpreter/test toolchain, zero production dependencies | Compiler + crates + optional Python adapter test environments | Compiler + modules + optional Python adapters | Linux core possible; Apple-only validation needs macOS jobs | Node + type checker; possible future frontend build chain |
| Licensing (hard) | Original MIT core; runtime PSF; no copying GPL/EUPL/custom MVT | Original MIT possible; crate notices/features must be audited | Original MIT possible; module notices must be audited | Original MIT possible; Swift license/SDK redistribution constraints distinct | Original MIT possible; Node/TS/dependency notices distinct |
| 2–3 year extensibility (high) | Good parser/rule iteration, poor fit if unrestricted huge in-memory cases become mandatory | Strong long-term native engine contender when binary parsing dominates | Strong contender for distributable local daemon/stream pipelines | Native macOS consent/helper/UI role, only after demonstrated API need | Strong investigation UI role, only after useful backend exists |

All options can meet the hard gates with careful implementation. None is automatically secure. Rust's memory model is a meaningful advantage for native parsers, not proof against path traversal, decompression bombs, misinformation, unsafe dependencies or evidence tampering. Python currently avoids those binary/archive surfaces altogether rather than claiming to solve them.

## 4. Actual compatibility research

The [eight-reference source review](../research/upstream-assessment.md) covers exact source paths, dependencies, licenses, tests and known limitations. Three additional observations challenge Python bias:

- [go-ios @ ca2c56d2c294ff702cadf4821edd30b069d3a264](https://github.com/danielpaulus/go-ios/tree/ca2c56d2c294ff702cadf4821edd30b069d3a264): inspected README, LICENSE (MIT), go.mod (`go 1.26.0`, toolchain `go1.26.5`) and `ios/pcap/pcap.go`. Real `com.apple.pcapd` service access and device header timestamps exist. Source also creates capture files with mode 0755, has unchecked write/unpack results, and inserts an Ethernet header for some packets. This is a bounded review, not an exploit finding or complete audit. A forensic adapter must retain raw bytes, log transformations, restrict permissions and handle errors. CLI includes erase/install/profile mutation: never expose it wholesale. README describes host/iOS tunnel prerequisites; not tested on hardware here.
- [idevice @ 26a28f6a46b5d85a28043c2e62febfa394c8b0a6](https://github.com/jkcoxson/idevice/tree/26a28f6a46b5d85a28043c2e62febfa394c8b0a6): inspected README, LICENSE.txt (MIT), workspace and idevice/Cargo.toml (0.1.68, Rust edition 2024, feature-gated services), `idevice/src/services/pcapd.rs`. Real async `PcapdClient` and checked byte-reader exist. `normalize_data` adds/changes link-layer bytes; raw originals must be separate. README explicitly warns of breaking point releases before 0.2.0. Current default TLS feature pulls aws-lc; 'Rust' is not synonymous with no native dependency surface. Runtime/dependency security and hardware compatibility NOT TESTED.
- Swift has genuine Linux/Windows support; rejecting it as 'macOS only' would be false. [Static Linux SDK](https://www.swift.org/documentation/articles/static-linux-getting-started.html) permits static binaries but forbids dynamic loading and requires compatible static dependencies; Apple frameworks remain Apple-specific. No reviewed public Swift API here establishes a unique capability necessary for M1. A future authorized macOS helper is plausible, not assumed.

Integration-cost accounting: **0** upstream runtimes/adapters shipped in M1. Adopting MVT+iLEAPP+SAF+PMD3 later means **4 separately pinned, version-probed contracts/environments**, whichever core language is chosen. Each requires consent/capability probes, schema checks, bounded execution/output, negative fixtures and license review. Direct Python imports would reduce process marshaling but enlarge the trusted address space and couple incompatible dependencies; rejected. A Rust/Python or Go/Python M1 hybrid adds **one additional toolchain, executable contract, release artifact and failure boundary** with no current input requiring it. No invented engineering-hour estimate is used.

## 5. Reproducible empirical evidence

Run `python docs/architecture/experiments/run.py`. Sources and all 30 samples are under `experiments/`. Two short-lived prototypes perform identical full-buffer JSONL decode, domain case normalization, explicit date normalization to milliseconds, sort, SHA-256 and summary reporting. Both intentionally omit production hostile-input controls and are **not shipped in the wheel**. Same input SHA and exact output SHA were checked for each size. Generated data uses only `example.invalid`.

Host: Linux 6.18.55 x86_64, glibc 2.39, AMD EPYC 9V74, 9 visible CPUs; CPython 3.12.14 and Node 24.19.0. Five isolated processes per size/runtime, alternating order, warm file cache, startup included in wall time; peak RSS obtained from each process on Linux. Shared-runner scheduling is uncontrolled. Node strips TypeScript types; no `tsc` installed, so this is **runtime feasibility**, not a static-type-check/build comparison.

| Records | Python median wall / work (s) | Python max RSS (KiB) | TS/Node median wall / work (s) | TS/Node max RSS (KiB) |
|---:|---:|---:|---:|---:|
| 100 | 0.0416 / 0.0008 | 12,416 | 0.1713 / 0.0016 | 55,672 |
| 5,000 | 0.0682 / 0.0308 | 14,080 | 0.1613 / 0.0280 | 62,832 |
| 20,000 | 0.1852 / 0.1306 | 22,204 | 0.2780 / 0.1138 | 75,680 |

Interpretation: Node's in-process work is slightly faster at larger samples in this spike; Python startup and RSS are lower. Both comfortably handle this limited workload. This does **not** prove Python faster than Go/Rust or a full forensic engine. Rust, Go and Swift performance/build tests: **NOT MEASURED**, toolchains absent. No toolchain was installed solely to manufacture a full benchmark table. No device/USB, plist, archive, FFI, concurrency, cold cache or million-event benchmark was run. Those are concrete uncertainties, not neutral zero scores. A native candidate remains viable.

Initial installation feasibility: `.venv/bin/python -m pip install -e '.[dev]'` completed under 3.12; builds an editable wheel. Full packaging/test results belong in `docs/validation/results.md` after execution. Production pipeline timing (including reparse, checks and report hashing) must be measured separately; spike timings must not be advertised as SCRYVEIL import throughput.

## 6. Decision and strongest counterargument

Retain **Python for this limited original engine** because the bounded inputs, exact-offset handling, raw-byte preservation and transparent rules can be delivered with no production dependencies. The initial narrow processing measurements fit the intended budget; subsequent full-pipeline measurements reopened the performance gate (section 11). There is no current requirement for a binary-format parser, live service concurrency or interpreter-free desktop installer that would justify a second runtime or a rewrite. This reasoning would still apply on a fresh repository; existing code is not the rationale.

**Best counterargument:** choose Rust now to avoid eventual migration, gain stronger compile-time invariants and improve native packaging, especially if huge hostile artifacts become central. Go is similarly attractive if the main product becomes a standalone cross-platform acquisition/orchestration CLI. These alternatives may be better at the next scope boundary. The cost of the selected path is interpreter distribution, weaker static guarantees, per-object memory overhead, synchronous state serialization and future migration work. The current `dict[str, Any]` store needs stronger schema validation; passing mypy does not prove its shape. Do not label this the most scalable lifetime design.

Rejected now: Rust/Python and Go/Python hybrids (unneeded second production runtime); Swift core (no unique M1 Apple API need); TS core (no UI requirement, precision/validation work without demonstrated M1 advantage). No C++ core: untrusted parsing has no measured ABI/performance requirement justifying manual-memory exposure. This is deferral, not a claim that these languages lack capabilities.

## 7. Boundaries and migration contract

- Case service owns consent and audit. Importer owns byte copying/hash/locators. Parser returns schema-versioned records and structured warning codes. Engine consumes only normalized records. Report service revalidates lineage, then projects an explicit safe field set.
- `schemas/` provides interoperable JSON Schema. Absent observation/collection timestamps are JSON null, not host time. UTC timestamps and original offsets/precision remain distinct; hashes refer to exact bytes. Integers and canonicalization are constrained/documented; arbitrary cross-language JSON serializer bytes are not assumed equal.
- Future tool subprocess protocol: versioned `capabilities`, `parse`, `result` envelopes over local files/stdio, explicit argv (no shell), operator-supplied tool location plus pinned version/digest, input artifact hash, record locators, warning/error codes and explicit unsupported status. Max output/records/depth/runtime; terminate the process group; no inherited secrets, network or device access by default. **Design only, not a sandbox implemented in M1.** Prefer subprocess over FFI until a measured benefit outweighs address-space coupling.
- Before replacement, freeze semantic golden fixtures and canonical report rules. Dual-run old/new implementations on synthetic corpus, require same hashes/locators/assessments and stated numeric tolerances. Read legacy schema, write a new version; retain original case untouched and record migration provenance. No in-place silent schema mutation. Deploy one replaced module at a time; retain old read support and rollback path.

## 8. Falsifiable revisit gates

1. Any archive/binary parser enters scope: threat-model subprocess isolation first; implement a bounded Rust comparison with hostile corpus before choosing its production runtime.
2. Full 20,000-event local pipeline exceeds **10 s wall or 256 MiB peak RSS** on a documented reference Linux runner across five runs: profile repeated parsing/serialization and data structures first; compare a Go/Rust prototype only for the demonstrated bottleneck. These are initial acceptance budgets, not promised customer limits.
3. Need sustained capture without loss or >1 million events: define capture/queue/drop semantics and measure Go/Rust streams plus SQLite/indexed queries; do not extrapolate this spike.
4. First Windows/macOS desktop release or interpreter-free install requirement: compare actual signed packaging size, cold startup, install friction and update path. Current POSIX storage is not cross-platform validation.
5. A public Apple framework is essential and inaccessible through reviewed tools: prototype a minimal Swift helper with schema contract and owner-approved hardware test, not a wholesale Swift rewrite.
6. First interactive UI: evaluate TypeScript on UI accessibility, offline boundaries and report consistency, independently from core runtime.

## 9. Source basis and uncertainty

Primary language references read: [Rust ownership](https://doc.rust-lang.org/book/ch04-00-understanding-ownership.html), [Go GC guide](https://go.dev/doc/gc-guide), [Swift static SDK](https://www.swift.org/documentation/articles/static-linux-getting-started.html), [Node TypeScript](https://nodejs.org/api/typescript.html), [Node child_process](https://nodejs.org/api/child_process.html), [Python JSON](https://docs.python.org/3/library/json.html). Python explicitly warns about hostile JSON CPU/memory; bounds are mandatory. Language model guarantees are distinct from runtime/native dependencies. License names are engineering screening, not legal clearance for a future combined distribution.

The choice is defensible for the measured bounded release with these declared gaps. It is not evidence of hardware support, universal spyware detection, throughput leadership or a final 3-year technology lock-in.

## 10. Initial production feasibility measurements (historical)

After the decision, the original full pipeline was measured with four 5,000-record imports, analysis and two checked report exports. First stress run retained both complete report objects and byte strings in the caller: **8.766s, 274,368KiB RSS**, exceeding the 256MiB budget. Inspection identified a needless deep copy of the analysis graph and a verification list retaining every reparsed event. Removing these copies reduced the same retained-report stress to **8.176s, 261,548KiB**; still too close to the ceiling to claim broad headroom.

The reproducible `pipeline.py` then modeled **sequential exports**, releasing the first caller-owned report before generating the second and comparing full-payload SHA-256. This is explicitly a different retention pattern, not a hidden benchmark substitution. Five fresh-process runs: **7.368–8.564s**, max **181,212KiB (~177MiB)**, 20,000 records / four findings; identical repeat export verified in every run. All samples and both earlier stress outcomes are in `experiments/pipeline-results.json`.

At that revision and on that run, this bounded sequential workload met the initial 10s/256MiB gate; callers retaining multiple complete reports could approach/exceed it. Section 11 supersedes that pass as the current performance status. No worst-case hostile-memory bound or large-case claim follows. The measured failure triggered concrete representation fixes and a documented caller-retention contract, not an unsupported native rewrite. Before supporting larger cases, profile/replace whole-state persistence and compare native candidates as specified above.

## 11. APR privacy review and reopened performance gate (2026-10-23)

The new read-only privacy projection interprets documented access boundaries and network summaries from verified originals. It preserves the existing 0.1.0 case and analysis-report contracts. [Research](../research/apr-review-evidence.md) compares Apple field documentation with pinned Plaso source; this is source inspection and original synthetic testing, not executed comparative accuracy testing or device qualification.

`experiments/privacy_pipeline.py` creates four 5,000-record imports (16,000 access boundaries, 8,000 complete intervals and 4,000 separate network summaries), then verifies two sequential exports. It retains only one complete report at a time. All measurements, including failed and intermediate samples, are preserved in [privacy-results.json](experiments/privacy-results.json). The host remains Linux x86_64 / CPython 3.12.14 with uncontrolled shared-runner scheduling; wall and process CPU times are recorded for the later privacy runs. No private exports or hardware were used.

| Executed workload / revision | Wall time | Maximum peak RSS | Interpretation |
|---|---:|---:|---|
| Privacy pipeline, initial five samples | 10.342–28.625 s | 126,072 KiB | Time gate failed |
| Privacy pipeline, control-character regex only, five samples | 12.941–19.596 s | 116,484 KiB | Time gate failed |
| Privacy pipeline, regex plus reduced event copying, five samples | 9.188–14.202 s | 116,256 KiB | Four of five exceeded 10 s |
| Original core pipeline, alternating with those five privacy samples | 10.684–34.221 s | 181,180 KiB | All five exceeded 10 s; earlier pass is not current evidence |
| Privacy capacity smoke after preserving unknown network context | 16.486 s (CPU 16.387 s) | 116,344 KiB | One capacity check, not a five-run acceptance pass |

Every completed export pair was identical. Memory stayed below 256 MiB for these measured sequential workloads; this is not a hostile worst-case bound. The final capacity report was 16,316,912 bytes. The five-run privacy series preceded the null-versus-false context correction. The capacity smoke preceded the final enormous-integer error guards; its source hashes identify the measured files, not a claim that every later file was benchmarked.

Profiling identified repeated parsing, per-character text checks and recursive dataclass serialization as costs (instrumented timings are not benchmark timings). Two bounded changes preserve semantics: a compiled control-character regex and copying only mutable event fields instead of recursively visiting immutable scalars. A five-sample microbenchmark measured the narrow text check at median 0.2360 s before / 0.0655 s after, for the recorded inputs and iteration count. Regression tests cover all ASCII control characters, printable Unicode and nested mutable-field independence. This does **not** establish an end-to-end speedup: whole-pipeline ranges overlap and shared-runner variation is substantial.

**Current decision:** retain the verified single-runtime implementation for this experimental bounded CLI, but the 10-second acceptance gate is **OPEN / NOT PASSED**. No release-performance or scaling claim is justified. The observed CPU work warrants a follow-up that measures an indexed/streamed persistence design and a bounded Go or Rust implementation of the identified hot path against identical correctness fixtures. Those toolchains, and Swift, were unavailable in this environment; native runtime/build comparison remains **NOT MEASURED**. Until that comparison demonstrates a benefit, adding a production runtime would replace an observed limitation with an unmeasured assumption. Real-export conformance, desktop packaging and sustained acquisition retain their separate gates.
