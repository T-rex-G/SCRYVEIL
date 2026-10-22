# Privacy and retention

No runtime telemetry, analytics, cloud model or network request. Package/tool installation and GitHub CI setup may use the network; case analysis does not. Synthetic fixtures are the only data permitted in this repository and CI.

Case originals and state are local/private, unencrypted. Use an owner-controlled, encrypted host volume. Do not sync case directories to cloud/Git repositories. `.gitignore` and the hygiene scan are defense in depth, not guaranteed DLP.

Reports omit raw names, domains, app identifiers, labels and payloads. They retain timestamps, hashes, source offsets and rule statistics; **redacted does not mean anonymous**. Review manually before sharing. stdout redirection permissions are controlled by your shell: use `umask 077`.

Retention is owner-managed. No automatic deletion. To remove a case, first close all processes using it, verify the exact case ID/path and delete that case directory locally. Backups, snapshots, temporary exports and SSD recovery may retain data; no secure erasure guarantee. Delete exported reports separately. No device data is changed by this release.
