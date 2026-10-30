# Evidence availability and research questions

All hardware rows are NOT TESTED. Host support here describes upstream claims, not SCRYVEIL capability. Only synthetic NDJSON and experimental imported APR records are implemented.

| Source | Access / host / iOS | What is observable | Limits / present status |
|---|---|---|---|
| App Privacy Report | Owner export, Apple docs iOS/iPadOS15.2+; parser on Linux | Sensor access records, app/domain summaries, reported timestamp | Enabled-only last7days, private-browser exclusions; experimental parser; no full session reconstruction |
| Backup | Owner-provided export; encrypted backup needs authorized known password | Artifact-specific databases/plists depending backup coverage | Not implemented; never bypass encryption or assume full filesystem |
| Sysdiagnose | Owner-triggered export; upstream SAF tested-version table | Selected logs, shutdown records, crash/context artifacts | Retention/version variation; not implemented; exact source paths in research |
| Lockdown services | Trusted pairing + host USB transport | Service-dependent device/app/profile metadata | Pairing writes trust state; no blanket read-only claim; unsupported |
| Developer/RSD services | Version-dependent tunnels/DDI/developer permission | Service-specific developer streams | Current PMD3 userspace path/fallback must be tested; unsupported |
| PCAP/pcapd | Explicit authorized capture | Packet metadata, pcapd may add PID/name and device timestamps | Generic PCAP has no reliable PID; TLS contents/operator identity unknown; unsupported |
| Android | Separate future adapter contract | Platform-dependent evidence | No iOS equivalence assumed; unsupported |

## Answers to ten mandatory research questions

1. Paired-device getters exist in PMD3 mobile_config and libimobiledevice installation_proxy; access remains service/version/pairing dependent. Exported APR/sysdiagnose/backups are separate access routes. No comprehensive verified iOS service matrix exists here.
2. PMD3 transport source uses userspace preference with older-version fallback; its getters coexist with erase/profile install/remove. Future adapter must allowlist exact operations, disclose state changes and capability-probe.
3. pcapd headers include PID/name and clocks; generic PCAP does not. Unknown/negative PID must remain unknown. No decrypted TLS or attacker attribution claim.
4. SAF shutdown parser uses system_logs.logarchive/Extra paths; MVT filesystem module uses private/var/db/diagnostics paths. Related copied artifacts are not independent corroboration. MVT3 output changes require pinned adapter schemas.
5. Historical retention cannot be inferred from a brief live stream. APR has documented seven-day scope; source timestamps define available records, not complete coverage. Long-term log persistence is artifact/version dependent and unvalidated here.
6. iLEAPP artifact context carries source metadata; reviewed shutdown EOF tests preserve trailing unknown time. PrivacyAccounting SEGB is different from exported APR. Do not convert source formatting into assumed clock accuracy.
7. IOC/shutdown/campaign heuristics are review leads. Preserve dataset source/date/license/hash and distinguish duplicate source evidence from independent corroboration. Current SCRYVEIL equality uses only operator-supplied indicators; freshness is unverified.
8. Original schema/import/ledger/rule/report core is independent MIT. All eight tools remain study-only. GPL/EUPL/MVT restrictions need review before adoption; subprocess isolation is a technical boundary, not automatic legal clearance.
9. Event schema identifies artifact, type, clock, parser, source locator, provenance mode and explicit unknowns. Future platform/source adapters must declare actual capabilities rather than force iOS/Android fields into equivalence.
10. Scheduled sync, analytics, push, MDM administration, DNS retries, missing observations and clock/order issues create innocent alternatives. Current regularity rule reports a lead; approved-context declarations weaken it but are not independently authenticated. Profile/shutdown rules are deferred.

## Additional research screen

Plaso parser and tests independently confirm APR field shapes; source-only Apache2 reference, no reuse. go-ios and idevice challenge language-lock assumptions (ADR-001). Apple Intelligence Report Parser was independently discovered and screened README/GPL3 only; no adoption until source/fixtures/privacy review. Timesketch, AndroidQF, UnifiedLogs, upstream IOC repositories and the rest of the broader suggestion list were **not deeply assessed** in this bounded run. They are research backlog, not validated components.
