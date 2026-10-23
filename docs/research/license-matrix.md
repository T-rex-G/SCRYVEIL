# License and integration decisions

Reviewed 2026-10-21/22. Exact commits/files are in upstream-assessment.md and ADR-001. No upstream source, fixture, binary, history or runtime dependency is copied or bundled. This is engineering screening, not final legal clearance for future distribution.

| Project | Actual inspected terms | Current decision / future gate |
|---|---|---|
| iLEAPP | MIT; separate dependencies/bundled binaries | Study; review complete output/runtime distribution before adapter |
| SAF | EUPL-1.2 and NOTICE; third-party notices only sampled | Study; full compatibility/notice review before adoption |
| MVT | MVT License 1.1, modified MPL-2.0 with Data Owner consent restriction | Study; never call plain MPL; consent and redistribution review required |
| PyMobileDevice3 | GPL-3.0-or-later declared; GPL3 root text | Study; no library import/bundle; optional process separation is not legal exemption |
| libimobiledevice | Inspected library/CLI headers LGPL2.1+; root GPL2 and LGPL2.1 texts, separate components | Study; selected component and native dependency audit before linking |
| iShutdown | MIT in LICENSE and License.txt with separate copyright notices | Study; retain both notices on future reuse |
| Triangle Check | MIT in both license files; additional third-party packaging notices | Study; transitive/packaged binary review remains |
| iphone-tracker-check | MIT original, but GPL PMD3 dependency | Study; no detector/collector reuse |
| Plaso | Apache-2.0; parser/test source examined at 3733f4d78f9c0c951a56bc8a5749fd0809c31aca | Schema reference only, no copied code or fixture |
| go-ios | MIT; pinned source paths in ADR-001 | Study only; native/dependency notices and side effects need review |
| idevice | MIT LICENSE.txt; features/dependencies in Cargo.toml | Study only; pin unstable API, inspect enabled dependency licenses |
| Apple Intelligence Report Parser | GPL3 LICENSE header; README screened | Not adopted; source behavior and full license not audited |

**SCRYVEIL decision:** MIT for newly authored core, fixtures, tests and documentation. No third-party Python runtime packages; optional investigation dynamically loads system libseccomp (LGPL 2.1), not bundled; Python interpreter has separate PSF terms. Development tools are not bundled into the runtime wheel. No claim that MIT overrides another project's terms. New code reuse requires a notice/provenance entry and renewed review.

## Investigation additions (2026-10-23)

- libseccomp LICENSE at `2814474a2bc105f5ffabf4bbc7ae9fb100997028` and the installed distribution copyright were inspected. LGPL 2.1 library, loaded from the host, no native source/binary copied into the wheel. Revisit notices/source/relinking requirements before any bundled distribution.
- llama.cpp LICENSE at `4231b23dc2c46661d01157aac5245bdcf03ce4b1` is MIT. Only server API documentation was used; no server/model weights distributed. Model licenses are independent. Ollama was researched through official API documentation and not bundled.
- 0xche's assessment PDF declares CC BY-NC-SA 4.0. Only an original brief attributed summary and link are included; the PDF and its source/code are not relicensed or copied into SCRYVEIL.
