# SCRYVEIL engineering handoff

Branch `feat/forensic-core-genesis`, PR #1 open; never merge automatically.
Verified code: `5be36d3fcbe31ec9ec080254ce2b6ce1ab843940`. [Core CI 41051459230](https://github.com/T-rex-G/SCRYVEIL/actions/runs/41051459230) passed. This handoff update changes no runtime code.

Implemented: `hypotheses.compare` now evaluates explicit propositions instead of aliasing findings inspection. Nonfatal/no-action declarations contradict an all-fatal interpretation, not report recurrence or every proposed cause. Comparisons retain exact source locations, bounded references and omission counts. `diagnostics compare` exposes the same deterministic checks offline. Unknown causes remain unresolved. The mock's contradictory-evidence mapping was corrected; this is not model qualification.

Temporal correlation now excludes conflicting declared bundle IDs, counts uncertain-identity pairs explicitly and retains interval indexing without materializing all pairs. Model views remove repeated finding text and locator bookkeeping while full results remain in reports. The 30-report regression completes within its unchanged 200,000-unit budget.

Reproduce from an installed checkout (output directory must be new):

```sh
python scripts/collection_demo.py --offline-only --output /tmp/scryveil-check
scryveil --root /tmp/scryveil-check/cases diagnostics compare --case "$(cat /tmp/scryveil-check/case-id.txt)" --all-events --finding diag-046ab4a7c407304ec7bd8a08ee8b848d387f452ec86f261e9d26d9b6b2932fc6
```

Observable result: 6,260 events, zero omissions; comparison reports all-fatal `contradicted`, recurrence `supported_as_reported`, common cause `not_established`. Original evidence/state stay unchanged. 546 regressions, static/type/security/hygiene checks, historical case/report compatibility, source workflows and installed-wheel workflows pass in CI. No new downloadable demonstration is a deliverable.

Actual-model gate remains blocked. Independent HTTPS controls at `0a40fa7113eb64ae43038b3bc2b622c5b4a8baa1`, [run 41049511201](https://github.com/T-rex-G/SCRYVEIL/actions/runs/41049511201), returned Chat HTTP 503 (4.605s) and native Google timeout (60.060s). Zero evidence/tools; two distinct requests, no retries. Both failures also occur outside the isolated broker; underlying provider/network cause is unknown. Original compact records/digests remain in `docs/validation/provider-protocol-result.json`. CI execution success is not inference success.

Next: establish availability only after a concrete endpoint/account/model change, then run and independently review the existing fixed fictional investigation. Do not repeat unchanged failed probes or claim actual-model reasoning qualification. Genuine Apple-export accuracy remains open; private diagnostics/devices require separate owner authorization. No private evidence access, billing activation, security-boundary weakening or merges were performed.
