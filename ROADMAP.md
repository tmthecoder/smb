# SMB Feature Roadmap

Tracks feature progress toward a spec-faithful SMB2/3 server.
[MS-SMB2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5606ad47-5ee0-437a-817e-70c366052962)
is the authoritative reference for all protocol behavior; wire types must be
implemented with the `smb-derive` proc macros (`SMBFromBytes`, `SMBToBytes`,
`SMBByteSize`).

## Phase 1 — Functional read-write file server

| Feature | Command(s) | Status |
|---|---|---|
| File read flow | Create → QueryInfo → Read → Close | ✅ PR #14 |
| File write flow | Write | ✅ PR #21 |
| Directory listing | QueryDirectory (FileIdBothDirectoryInformation) | ✅ |
| Filesystem info | QueryInfo (FileFsSizeInformation) | ✅ (nominal values) |
| Flush | Flush → fsync | ⬜ |
| Delete / rename / truncate | SetInfo (FileDispositionInformation, FileRenameInformation, FileEndOfFileInformation) | ⬜ |
| Directory creation via mkdir | Create (FILE_DIRECTORY_FILE dispositions) | ⬜ (partial — Create exists; verify smbclient `mkdir`) |
| Compound related requests | Wildcard FileId (0xFF…FF) resolution via `prev_command_id` | ⬜ |

## Phase 2 — Protocol robustness

- Enforce granted access masks on Read/Write/QueryDirectory (opens currently
  aren't checked against `granted_access`).
- Real filesystem statistics for FileFsSizeInformation (statvfs) instead of
  nominal values.
- Accurate NT status mapping for I/O errors (e.g. `OBJECT_NAME_NOT_FOUND`
  instead of `NOT_SUPPORTED` for missing files).
- Message signing enforcement and credit management.
- Stable file IDs: session/global open IDs are currently reused after close
  (first-vacant), so a stale client handle can alias a newer open.
- ChangeNotify, Lock/Unlock, Echo handlers.
- Additional QueryDirectory information classes (FileBothDirectoryInformation,
  FileFullDirectoryInformation, FileNamesInformation, FileIdExtdDirectoryInformation).

## Phase 3 — SMB3 features

- Encryption (SMB 3.x transform header).
- Oplocks / leases.
- Durable and persistent handles.
- Multichannel.

## Known issues / debt

- QueryDirectory enumeration snapshots the directory on first query; changes
  between queries of one enumeration are not reflected (acceptable per spec).
- The E2E test harness has a rare port-reuse race between `free_port()` and
  server bind.
- `FullFileificateInformation` variant in `SMBInformationClass` is misnamed
  (should be `FileFullDirectoryInformation`).
