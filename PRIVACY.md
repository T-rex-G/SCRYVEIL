# Privacy and retention

No telemetry or automatic model/network request. Deterministic analysis and mock investigation operate offline. Optional model requests require explicit configuration and invocation; external transmission additionally requires consent bound to the exact disclosure preview. Package installation and CI setup may use the network. Only synthetic evidence is permitted in this repository/CI; adapter tests contact synthetic loopback peers only.

Case originals and state are local/private, unencrypted. Use an owner-controlled, encrypted host volume. Do not sync case directories to cloud/Git repositories. `.gitignore` and the hygiene scan are defense in depth, not guaranteed DLP.

Default deterministic/snapshot projections omit raw names, domains, app identifiers, labels and payloads. Optional identifier inclusion, the owner's question and model text can disclose sensitive content. Reports retain timestamps, hashes, source offsets and relationships; **redacted does not mean anonymous**. Review before sharing or remote consent. A local model server may itself forward requests unless independently configured offline. Credentials stay outside evidence and model messages, referenced by a dedicated environment variable. stdout redirection permissions are controlled by your shell: use `umask 077`.

Retention is owner-managed. No automatic deletion. To remove a case, first close all processes using it, verify the exact case ID/path and delete that case directory locally. Backups, snapshots, temporary exports and SSD recovery may retain data; no secure erasure guarantee. Delete exported reports separately. No device data is changed by this release.
