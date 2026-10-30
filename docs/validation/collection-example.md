# SCRYVEIL diagnostic investigation

Examined 6260 of 6260 normalized events across 267 retained artifacts. Omitted events: 0.

These are deterministic measurements, not an AI diagnosis or device safety verdict. Genuine Apple-export qualification remains open. Source clocks and common device identity are unverified.

Collection inventory: {&quot;malformed&quot;: 1, &quot;parsed\_subset&quot;: 263, &quot;unsupported&quot;: 2}

## diagnostics.signature\_recurrence/1 — com.example.searchd

Distinct source artifacts declare multiple incident IDs with matching observed exception/termination fields and available symbol slots within the same declared process/OS/build group.

Measured values: {&quot;distinct\_reported\_incidents&quot;: 80, &quot;missing\_incident\_observations&quot;: 0, &quot;missing\_symbol\_slots&quot;: 0, &quot;repeated\_incident\_observations&quot;: 0, &quot;signature\_fields&quot;: &quot;process,bundle,OS/build,exception type/subtype/signal,termination namespace/code,first five symbol slots&quot;, &quot;signature\_sha256&quot;: &quot;7f4b30dae9da9543d62f00429b742c51555fe8bcf8255072bf3d6075b55db7b1&quot;, &quot;source\_artifacts&quot;: 80, &quot;symbol\_slots\_compared&quot;: 1, &quot;symbolication&quot;: &quot;source\_symbols\_only\_no\_address\_resolution&quot;}

Supporting observations:

- `evt-050ded0cb687fe387241c31ba2efdde7562eb5ba0d5e5ece462a438d0b996ed8` — `artifact-5f1550dff418ac693799ebdd7bddc32af55e4ed27d6a88605acba6776ee642ca`; line:2; bytes 122–762 (end exclusive); time 2026-02-03T14:37:00.000000Z.
- `evt-05ca57787ee513ee6922f3e9112450f937b022e346fb60e1ba5c30f27eef7361` — `artifact-f4c53e9e75dbe2764454e5f156676ebaba7b16017a84558cff2996b38ae38c10`; line:2; bytes 121–760 (end exclusive); time 2026-02-03T12:55:00.000000Z.
- `evt-0989c94494729ad37cc0ab0ddb59129685c18f0bfd257abf15c410f11f751892` — `artifact-ae362c245e07ff6acee5f32ef34ee6296a8647bab87e77c353f4098f0168ff99`; line:2; bytes 122–762 (end exclusive); time 2026-02-03T14:46:00.000000Z.
- 5 further retained references are in the JSON report.

Contrary observations:

- `evt-092eb209ced97aa5da68a876c79bb33f26a9b429119ddffa8149f12867570803` — `artifact-436ef9985317b255118bd5d4a1ae38870e1e10901dbcfb2760024e0b24a2313a`; line:2; bytes 124–948 (end exclusive); time 2026-02-03T12:04:00.000000Z.
- `evt-0b80ad6a1bc6475256bcd2370417e79d55fc2dd13995dc72648383281f75b56d` — `artifact-c62baea7531bcfa6ef16b4e1e9f48a4f699259d4b513d0339157a217b928c49e`; line:2; bytes 121–759 (end exclusive); time 2026-02-03T12:30:00.000000Z.
- `evt-0d691039879207f9a59674d65adc1408dd270331af0e3f01c8841d696ea98b4b` — `artifact-56b4b378ffd3e86d8a1e27eb7741f452caca49faa09bc01500ee317d46e49abc`; line:2; bytes 122–761 (end exclusive); time 2026-02-03T13:50:00.000000Z.
- 5 further retained references are in the JSON report.

Reference coverage: {&quot;contradictory&quot;: 44, &quot;contradictory\_omitted&quot;: 36, &quot;supporting&quot;: 80, &quot;supporting\_omitted&quot;: 72}

Competing explanations: software defect or workload; resource policy or operating-system behavior; different devices or executable versions sharing source-declared names.

Limits: Source-declared process/build/incident values are not authenticated identities. A crash, repeated stack, resource warning or temporal neighbor does not establish spyware or causation. Unknown clocks and absent complementary records prevent a complete device history. Reference lists are bounded; omitted counts are explicit. Query the named process and time range for further records.

## diagnostics.signature\_recurrence/1 — com.example.searchd

Distinct source artifacts declare multiple incident IDs with matching observed exception/termination fields and available symbol slots within the same declared process/OS/build group.

Measured values: {&quot;distinct\_reported\_incidents&quot;: 80, &quot;missing\_incident\_observations&quot;: 0, &quot;missing\_symbol\_slots&quot;: 0, &quot;repeated\_incident\_observations&quot;: 0, &quot;signature\_fields&quot;: &quot;process,bundle,OS/build,exception type/subtype/signal,termination namespace/code,first five symbol slots&quot;, &quot;signature\_sha256&quot;: &quot;9cc253c71bd6fa2d9faab2579eff247a0e97ab9503aa3e5b7864a20632f3aa33&quot;, &quot;source\_artifacts&quot;: 80, &quot;symbol\_slots\_compared&quot;: 1, &quot;symbolication&quot;: &quot;source\_symbols\_only\_no\_address\_resolution&quot;}

Supporting observations:

- `evt-01928005520d74d90a57a091a8d0ff321321e12d69265cecab92216d0ce9cc72` — `artifact-87d1fbe954ac7f75fad7b160e2592c150756ec84b8de86c48bf936db3d895da5`; line:2; bytes 122–762 (end exclusive); time 2026-02-03T15:06:00.000000Z.
- `evt-0b80ad6a1bc6475256bcd2370417e79d55fc2dd13995dc72648383281f75b56d` — `artifact-c62baea7531bcfa6ef16b4e1e9f48a4f699259d4b513d0339157a217b928c49e`; line:2; bytes 121–759 (end exclusive); time 2026-02-03T12:30:00.000000Z.
- `evt-0d9dcc8dad5a0774538f352e06c2598c8f29f9a0a751fd78e520ae83cf920fe1` — `artifact-f17970267af137c073fdca97d1f22721da6cc700823766aa8984ad0ffb607bb2`; line:2; bytes 121–760 (end exclusive); time 2026-02-03T13:27:00.000000Z.
- 5 further retained references are in the JSON report.

Contrary observations:

- `evt-092eb209ced97aa5da68a876c79bb33f26a9b429119ddffa8149f12867570803` — `artifact-436ef9985317b255118bd5d4a1ae38870e1e10901dbcfb2760024e0b24a2313a`; line:2; bytes 124–948 (end exclusive); time 2026-02-03T12:04:00.000000Z.
- `evt-0b80ad6a1bc6475256bcd2370417e79d55fc2dd13995dc72648383281f75b56d` — `artifact-c62baea7531bcfa6ef16b4e1e9f48a4f699259d4b513d0339157a217b928c49e`; line:2; bytes 121–759 (end exclusive); time 2026-02-03T12:30:00.000000Z.
- `evt-0d691039879207f9a59674d65adc1408dd270331af0e3f01c8841d696ea98b4b` — `artifact-56b4b378ffd3e86d8a1e27eb7741f452caca49faa09bc01500ee317d46e49abc`; line:2; bytes 122–761 (end exclusive); time 2026-02-03T13:50:00.000000Z.
- 5 further retained references are in the JSON report.

Reference coverage: {&quot;contradictory&quot;: 44, &quot;contradictory\_omitted&quot;: 36, &quot;supporting&quot;: 80, &quot;supporting\_omitted&quot;: 72}

Competing explanations: software defect or workload; resource policy or operating-system behavior; different devices or executable versions sharing source-declared names.

Limits: Source-declared process/build/incident values are not authenticated identities. A crash, repeated stack, resource warning or temporal neighbor does not establish spyware or causation. Unknown clocks and absent complementary records prevent a complete device history. Reference lists are bounded; omitted counts are explicit. Query the named process and time range for further records.

## diagnostics.signature\_recurrence/1 — com.example.searchd

Distinct source artifacts declare multiple incident IDs with matching observed exception/termination fields and available symbol slots within the same declared process/OS/build group.

Measured values: {&quot;distinct\_reported\_incidents&quot;: 80, &quot;missing\_incident\_observations&quot;: 0, &quot;missing\_symbol\_slots&quot;: 0, &quot;repeated\_incident\_observations&quot;: 0, &quot;signature\_fields&quot;: &quot;process,bundle,OS/build,exception type/subtype/signal,termination namespace/code,first five symbol slots&quot;, &quot;signature\_sha256&quot;: &quot;def468b1f781b4986bfcdf12e409b278ccf42a37b4989563f01aeb8574a34604&quot;, &quot;source\_artifacts&quot;: 80, &quot;symbol\_slots\_compared&quot;: 1, &quot;symbolication&quot;: &quot;source\_symbols\_only\_no\_address\_resolution&quot;}

Supporting observations:

- `evt-019ad31c012013a9959008aa15662ab9a4516a117f287d6b78d5293deaa65bfa` — `artifact-f0ec75031d6501e8e3d2a786c2aa5b167f9644a24c5beb0f9748bbbd52ff24e8`; line:2; bytes 122–762 (end exclusive); time 2026-02-03T15:59:00.000000Z.
- `evt-02a52bb3494f472702dd31177a981c2b2eb591997e584fd92ef9290291d4e305` — `artifact-2b1eb85e468296f3bc5d3d467cf3fffe080546a1352cbc6fbd4ee076a4edd26c`; line:2; bytes 122–762 (end exclusive); time 2026-02-03T13:56:00.000000Z.
- `evt-04d657cbd2fac88cfaf6f54ee1b9a7dd0a3b9baa2f85eabb38bc013aafe06724` — `artifact-37158fb448bcb69377c235383f15f4e471ef71ca370eb5f716f3f7c36f5d214f`; line:2; bytes 121–760 (end exclusive); time 2026-02-03T13:14:00.000000Z.
- 5 further retained references are in the JSON report.

Contrary observations:

- `evt-092eb209ced97aa5da68a876c79bb33f26a9b429119ddffa8149f12867570803` — `artifact-436ef9985317b255118bd5d4a1ae38870e1e10901dbcfb2760024e0b24a2313a`; line:2; bytes 124–948 (end exclusive); time 2026-02-03T12:04:00.000000Z.
- `evt-0b80ad6a1bc6475256bcd2370417e79d55fc2dd13995dc72648383281f75b56d` — `artifact-c62baea7531bcfa6ef16b4e1e9f48a4f699259d4b513d0339157a217b928c49e`; line:2; bytes 121–759 (end exclusive); time 2026-02-03T12:30:00.000000Z.
- `evt-0d691039879207f9a59674d65adc1408dd270331af0e3f01c8841d696ea98b4b` — `artifact-56b4b378ffd3e86d8a1e27eb7741f452caca49faa09bc01500ee317d46e49abc`; line:2; bytes 122–761 (end exclusive); time 2026-02-03T13:50:00.000000Z.
- 5 further retained references are in the JSON report.

Reference coverage: {&quot;contradictory&quot;: 44, &quot;contradictory\_omitted&quot;: 36, &quot;supporting&quot;: 80, &quot;supporting\_omitted&quot;: 72}

Competing explanations: software defect or workload; resource policy or operating-system behavior; different devices or executable versions sharing source-declared names.

Limits: Source-declared process/build/incident values are not authenticated identities. A crash, repeated stack, resource warning or temporal neighbor does not establish spyware or causation. Unknown clocks and absent complementary records prevent a complete device history. Reference lists are bounded; omitted counts are explicit. Query the named process and time range for further records.

## diagnostics.jetsam\_reason/1 — com.example.searchd

Jetsam process entries carry explicit reason values. Other listed processes without a reason are not counted as terminations. Resident pages times reported page size is a footprint measurement, not a memory limit.

Measured values: {&quot;listed\_without\_reason&quot;: 0, &quot;peak\_observed\_footprint\_bytes&quot;: 16384, &quot;reason\_counts&quot;: {&quot;vm-pageshortage&quot;: 3}, &quot;reasoned\_entries&quot;: 3}

Supporting observations:

- `evt-2a1b9a6eeca308ef119db6170ec93e5ed7a9afd98108d2c2848e0f667ddae3e3` — `artifact-afa84acd3fe98ac8ebb85b9da37785e3e01653c834c97f2dcc28f05ce45fb805`; line:2; bytes 78–120955 (end exclusive); time 2026-02-02T11:59:00.000000Z.
- `evt-3d533e3a9e233617a8542f1976dab3cf392fcdf50159fdc01fb88001d83d53cf` — `artifact-ea48d95e23976cd6ade909f4c3451f03c9e592068d6b035426b4aff419f7d034`; line:2; bytes 78–120955 (end exclusive); time 2026-02-02T12:00:00.000000Z.
- `evt-b944a9bd874cf96b1cfcc3c438b242ede52bff6e48dd3bdc3e689f76e61a7968` — `artifact-670481eca38fc9893437211104bde7cfc56d2459a25ee429064ce56c7591d1e3`; line:2; bytes 78–120955 (end exclusive); time 2026-02-02T11:58:00.000000Z.

Contrary observations:

- None identified by this rule; this does not establish that none exist.

Reference coverage: {&quot;contradictory&quot;: 0, &quot;contradictory\_omitted&quot;: 0, &quot;supporting&quot;: 3, &quot;supporting\_omitted&quot;: 0}

Competing explanations: software defect or workload; resource policy or operating-system behavior; different devices or executable versions sharing source-declared names.

Limits: Source-declared process/build/incident values are not authenticated identities. A crash, repeated stack, resource warning or temporal neighbor does not establish spyware or causation. Unknown clocks and absent complementary records prevent a complete device history. Reference lists are bounded; omitted counts are explicit. Query the named process and time range for further records.

## diagnostics.resource\_temporal\_neighbors/1 — com.example.searchd

Crash/exception and explicit resource observations share a declared process/OS/build and occur within five minutes on their reported clocks. This is temporal proximity, not a demonstrated causal relationship.

Measured values: {&quot;clock\_accuracy&quot;: &quot;unknown&quot;, &quot;observation\_pairs&quot;: 200, &quot;same\_device\_identity&quot;: &quot;unverified&quot;, &quot;window\_seconds&quot;: 300}

Supporting observations:

- `evt-092eb209ced97aa5da68a876c79bb33f26a9b429119ddffa8149f12867570803` — `artifact-436ef9985317b255118bd5d4a1ae38870e1e10901dbcfb2760024e0b24a2313a`; line:2; bytes 124–948 (end exclusive); time 2026-02-03T12:04:00.000000Z.
- `evt-14401c76f0bbbc09baf4acc046423f0cd742d6c5b33641f5a48d906dc7090e07` — `artifact-41dd6b7b8dc2004908c6d130783faf6f101b471c9b4e4d017b152a67b0303c3c`; line:2; bytes 124–948 (end exclusive); time 2026-02-03T12:04:00.000000Z.
- `evt-146508bf798230ad47234707be2bf15e8751c0c519b9bb2df1ade0cd160b6ca6` — `artifact-92fd298632cc8c4fc7f55e511fccf73b4f86c824b580f21d01cc82328da66384`; line:2; bytes 120–758 (end exclusive); time 2026-02-03T12:07:00.000000Z.
- 5 further retained references are in the JSON report.

Contrary observations:

- `evt-092eb209ced97aa5da68a876c79bb33f26a9b429119ddffa8149f12867570803` — `artifact-436ef9985317b255118bd5d4a1ae38870e1e10901dbcfb2760024e0b24a2313a`; line:2; bytes 124–948 (end exclusive); time 2026-02-03T12:04:00.000000Z.
- `evt-14401c76f0bbbc09baf4acc046423f0cd742d6c5b33641f5a48d906dc7090e07` — `artifact-41dd6b7b8dc2004908c6d130783faf6f101b471c9b4e4d017b152a67b0303c3c`; line:2; bytes 124–948 (end exclusive); time 2026-02-03T12:04:00.000000Z.
- `evt-19ae7d06d4d1659f2d89a597b1df1791092050a4683d1ed9e8318a33f4312882` — `artifact-8294738d2e3c53f2936804e5a7ab2f8eea057e47d7e36b48526e478ab04838ed`; line:2; bytes 125–950 (end exclusive); time 2026-02-03T12:04:00.000000Z.
- 5 further retained references are in the JSON report.

Reference coverage: {&quot;contradictory&quot;: 21, &quot;contradictory\_omitted&quot;: 13, &quot;supporting&quot;: 30, &quot;supporting\_omitted&quot;: 22}

Competing explanations: software defect or workload; resource policy or operating-system behavior; different devices or executable versions sharing source-declared names.

Limits: Source-declared process/build/incident values are not authenticated identities. A crash, repeated stack, resource warning or temporal neighbor does not establish spyware or causation. Unknown clocks and absent complementary records prevent a complete device history. Reference lists are bounded; omitted counts are explicit. Query the named process and time range for further records.

## diagnostics.report\_conditions/1 — com.example.searchd

Report categories and explicit condition flags are counted separately. Nonfatal/simulated conditions and resource reports declaring no action contradict the claim that every supplied report proves a fatal crash.

Measured values: {&quot;categories\_and\_flags\_overlap&quot;: true, &quot;condition\_counts&quot;: {&quot;declared\_no\_action&quot;: 20, &quot;declared\_nonfatal&quot;: 24, &quot;diagnostic.crash&quot;: 240, &quot;diagnostic.resource&quot;: 20}}

Supporting observations:

- `evt-01928005520d74d90a57a091a8d0ff321321e12d69265cecab92216d0ce9cc72` — `artifact-87d1fbe954ac7f75fad7b160e2592c150756ec84b8de86c48bf936db3d895da5`; line:2; bytes 122–762 (end exclusive); time 2026-02-03T15:06:00.000000Z.
- `evt-019ad31c012013a9959008aa15662ab9a4516a117f287d6b78d5293deaa65bfa` — `artifact-f0ec75031d6501e8e3d2a786c2aa5b167f9644a24c5beb0f9748bbbd52ff24e8`; line:2; bytes 122–762 (end exclusive); time 2026-02-03T15:59:00.000000Z.
- `evt-02a52bb3494f472702dd31177a981c2b2eb591997e584fd92ef9290291d4e305` — `artifact-2b1eb85e468296f3bc5d3d467cf3fffe080546a1352cbc6fbd4ee076a4edd26c`; line:2; bytes 122–762 (end exclusive); time 2026-02-03T13:56:00.000000Z.
- 5 further retained references are in the JSON report.

Contrary observations:

- `evt-092eb209ced97aa5da68a876c79bb33f26a9b429119ddffa8149f12867570803` — `artifact-436ef9985317b255118bd5d4a1ae38870e1e10901dbcfb2760024e0b24a2313a`; line:2; bytes 124–948 (end exclusive); time 2026-02-03T12:04:00.000000Z.
- `evt-0b80ad6a1bc6475256bcd2370417e79d55fc2dd13995dc72648383281f75b56d` — `artifact-c62baea7531bcfa6ef16b4e1e9f48a4f699259d4b513d0339157a217b928c49e`; line:2; bytes 121–759 (end exclusive); time 2026-02-03T12:30:00.000000Z.
- `evt-0d691039879207f9a59674d65adc1408dd270331af0e3f01c8841d696ea98b4b` — `artifact-56b4b378ffd3e86d8a1e27eb7741f452caca49faa09bc01500ee317d46e49abc`; line:2; bytes 122–761 (end exclusive); time 2026-02-03T13:50:00.000000Z.
- 5 further retained references are in the JSON report.

Reference coverage: {&quot;contradictory&quot;: 44, &quot;contradictory\_omitted&quot;: 36, &quot;supporting&quot;: 260, &quot;supporting\_omitted&quot;: 252}

Competing explanations: software defect or workload; resource policy or operating-system behavior; different devices or executable versions sharing source-declared names.

Limits: Source-declared process/build/incident values are not authenticated identities. A crash, repeated stack, resource warning or temporal neighbor does not establish spyware or causation. Unknown clocks and absent complementary records prevent a complete device history. Reference lists are bounded; omitted counts are explicit. Query the named process and time range for further records.

## Outstanding questions

- Do independent records establish one device and the executable versions involved?
- Do symbolicated stacks or reproducible software failures support a common defect?
- Do authorized resource histories corroborate the reported pressure and timestamps?
- Which unsupported or malformed members need another qualified reader?

Archive/member relationships are available through collection inventory. No original bytes were modified by this report.
