# Hardware and platform matrix

| Host/input | Status | Evidence |
|---|---|---|
| Linux x86_64, CPython3.12.14, synthetic NDJSON | TESTED | Local tests/demo/package smoke in results.md |
| Linux, experimental APR field shapes | SYNTHETIC FIXTURES TESTED | Not an Apple-produced export |
| iOS/iPadOS15.2–current physical device | NOT TESTED | No connected/authorized device used |
| macOS core | NOT TESTED | POSIX design alone is not validation |
| Windows case store | UNSUPPORTED | Requires POSIX locking/private modes |
| USB/paired device, tunnel/DDI, backup/sysdiagnose/PCAP | UNSUPPORTED | No adapter implemented |
| Android/AI/cloud provider | UNSUPPORTED / NOT CONFIGURED | No implementation |

`doctor` reports implemented capability vs hardware validation separately; it never probes/pairs with a phone. First device test needs owner participation and a separate scoped plan.
