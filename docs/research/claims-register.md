# Claims register

Source inspection proves source control flow only. It is not hardware validation. Exact pinned links are in upstream-assessment.md; runtime comparison is in ADR-001.

| ID | Claim | Source / test method | Confidence and scope | Gaps | Status |
|---|---|---|---|---|---|
| C01 | Original bytes and line/byte references survive import | test_adversarial.py preservation/locator tests | Direct synthetic test | No external custody anchor | VERIFIED |
| C02 | APR hits are counts, not independent packet timings | Apple inspecting-app-activity-data; tracker parser; Plaso parser | Primary schema/source inspection | Real exported device versions not validated | VERIFIED format interpretation; hardware UNTESTED |
| C03 | APR observes seven-day history only after enabled, with private-browser exclusions | https://support.apple.com/en-us/102188 | Primary docs | User's actual retention unknown | DOC-ONLY |
| C04 | Default libimobiledevice crash export removes files; --keep still invokes mover | pinned idevicecrashreport.c | Source control flow | No device run | VERIFIED source only |
| C05 | Periodicity proves spyware | Original engine benign and regular synthetic examples | Regularity cannot distinguish legitimate scheduling | No ground-truth malware corpus | DISPROVEN inference |
| C06 | No public IOC match establishes device safety | MVT README and rule scope | Absence cannot prove unobserved device state | Public indicators incomplete | DISPROVEN inference |
| C07 | Current PMD3 developer transports have version-specific tunnels and side effects | pinned cli_common.py and tunnel guide | Source/docs | Per-host/per-device UNTESTED | DOC-ONLY compatibility |
| C08 | Runtime must be Python to access Apple services | go-ios pcap.go and idevice pcapd.rs | Alternative implementations inspected | Hardware not executed | DISPROVEN requirement |
| C09 | Python beats Rust/Go at forensic workloads | No comparative native measurement | No basis | Compilers absent; future native spike needed | UNTESTED |
| C10 | Python/TS spike yields equal normalized output for 100/5000/20000 records | experiments/run.py SHA assertions and results.json | Direct synthetic runs | Narrow millisecond corpus, no security parity | VERIFIED |
| C11 | SCRYVEIL can certify any phone free of spyware | Unsupported by design | No scope can establish this | No hardware acquisition implemented | DISPROVEN product claim |
| C12 | All upstream dependencies were audited | Only manifests and selected source inspected | Explicit research limit | Full SBOM/audit missing | UNTESTED |
