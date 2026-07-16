use std::any::Any;
use std::fmt::{Debug, Formatter};
use std::fs;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::marker::PhantomData;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use smb_core::SMBResult;
use smb_core::error::SMBError;
use smb_core::logging::{debug, warn};
use smb_core::nt_status::NTStatus;

use crate::protocol::body::create::disposition::SMBCreateDisposition;
use crate::protocol::body::create::file_attributes::SMBFileAttributes;
use crate::protocol::body::filetime::FileTime;
use crate::protocol::body::tree_connect::access_mask::SMBAccessMask;
use crate::protocol::body::tree_connect::flags::SMBShareFlags;
use crate::server::share::{
    ConnectAllowed, FilePerms, ResourceHandle, ResourceType, SMBDirectoryEntry, SMBFileMetadata,
    SharedResource,
};

/// Maximum single read size (8 MB), per MS-SMB2 §3.3.5.12 recommendation for SMB 3.x.
const MAX_READ_SIZE: u32 = 8 * 1024 * 1024;
const MAX_WRITE_SIZE: u32 = 8 * 1024 * 1024;

/// Normalize a path by resolving `.` and `..` components lexically (without
/// touching the filesystem). Returns `None` if the normalized path would
/// escape the root (i.e., more `..` than preceding components).
fn normalize_path(path: &str) -> Option<PathBuf> {
    let mut components = Vec::new();
    for component in Path::new(path).components() {
        match component {
            Component::ParentDir => {
                if components.is_empty() {
                    // Attempting to go above root — reject
                    return None;
                }
                components.pop();
            }
            Component::Normal(c) => components.push(c),
            Component::CurDir => {}                         // skip "."
            Component::RootDir | Component::Prefix(_) => {} // skip absolute prefixes
        }
    }
    Some(components.iter().collect())
}

#[derive(Debug)]
pub struct SMBFileSystemHandle {
    path: String,
    resource: SMBFileSystemResourceHandle,
}

#[derive(Debug)]
pub enum SMBFileSystemResourceHandle {
    File(File),
    Directory(SMBDirectoryEnumeration),
}

/// Enumeration state for an open directory handle, backing QueryDirectory
/// (MS-SMB2 §3.3.5.18). The first query (or a RESTART_SCANS query) snapshots
/// the matching entries; subsequent queries drain the snapshot from
/// `position` until no entries remain.
#[derive(Debug, Default)]
pub struct SMBDirectoryEnumeration {
    snapshot: Option<Vec<SMBDirectoryEntry>>,
    position: usize,
}

impl From<SMBFileSystemHandle> for Box<dyn ResourceHandle> {
    fn from(value: SMBFileSystemHandle) -> Self {
        Box::new(value)
    }
}

impl TryFrom<Box<dyn ResourceHandle>> for SMBFileSystemHandle {
    type Error = SMBError;

    fn try_from(value: Box<dyn ResourceHandle>) -> Result<Self, Self::Error> {
        value
            .into_any()
            .downcast::<Self>()
            .ok()
            .ok_or(SMBError::server_error("Invalid resource handle"))
            .map(|val| *val)
    }
}

impl<
    UserName: Send + Sync + 'static,
    Handle: From<SMBFileSystemHandle> + TryInto<SMBFileSystemHandle> + ResourceHandle + 'static,
> From<SMBFileSystemShare<UserName, Handle>>
    for Box<dyn SharedResource<UserName = UserName, Handle = Handle>>
{
    fn from(value: SMBFileSystemShare<UserName, Handle>) -> Self {
        Box::new(value)
    }
}

impl ResourceHandle for SMBFileSystemHandle {
    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }

    fn close(self: Box<Self>) -> SMBResult<()> {
        Ok(())
    }

    fn is_directory(&self) -> bool {
        match &self.resource {
            SMBFileSystemResourceHandle::File(_) => false,
            SMBFileSystemResourceHandle::Directory(_) => true,
        }
    }

    fn path(&self) -> &str {
        &self.path
    }

    fn metadata(&self) -> SMBResult<SMBFileMetadata> {
        let metadata = fs::metadata(self.path()).map_err(|err| {
            SMBError::server_error(format!(
                "Failed to get metadata for path: {}, error: {}",
                self.path(),
                err
            ))
        })?;
        Ok(fs_metadata_to_smb(&metadata))
    }

    fn read_data(&mut self, offset: u64, length: u32) -> SMBResult<Vec<u8>> {
        match &mut self.resource {
            SMBFileSystemResourceHandle::File(file) => {
                // Cap to MAX_READ_SIZE to prevent OOM from malicious clients
                let capped_length = length.min(MAX_READ_SIZE) as u64;
                file.seek(SeekFrom::Start(offset))
                    .map_err(SMBError::io_error)?;
                // Use take() + read_to_end() to handle short reads correctly
                let mut buf = Vec::with_capacity(capped_length as usize);
                file.take(capped_length)
                    .read_to_end(&mut buf)
                    .map_err(SMBError::io_error)?;
                Ok(buf)
            }
            SMBFileSystemResourceHandle::Directory(_) => Err(SMBError::response_error(
                smb_core::nt_status::NTStatus::InvalidDeviceRequest,
            )),
        }
    }

    fn write_data(&mut self, offset: u64, data: &[u8]) -> SMBResult<u32> {
        match &mut self.resource {
            SMBFileSystemResourceHandle::File(file) => {
                let capped = &data[..data.len().min(MAX_WRITE_SIZE as usize)];
                file.seek(SeekFrom::Start(offset))
                    .map_err(SMBError::io_error)?;
                file.write_all(capped).map_err(SMBError::io_error)?;
                Ok(capped.len() as u32)
            }
            SMBFileSystemResourceHandle::Directory(_) => {
                Err(SMBError::response_error(NTStatus::InvalidDeviceRequest))
            }
        }
    }

    fn query_directory(
        &mut self,
        pattern: &str,
        restart: bool,
    ) -> SMBResult<Vec<SMBDirectoryEntry>> {
        match &mut self.resource {
            // MS-SMB2 §3.3.5.18: QueryDirectory on a non-directory open fails
            // with STATUS_INVALID_PARAMETER
            SMBFileSystemResourceHandle::File(_) => {
                Err(SMBError::response_error(NTStatus::InvalidParameter))
            }
            SMBFileSystemResourceHandle::Directory(enumeration) => {
                if restart || enumeration.snapshot.is_none() {
                    let entries = scan_directory(&self.path, pattern)?;
                    if entries.is_empty() {
                        // MS-SMB2 §3.3.5.18: a fresh scan matching nothing
                        // fails with STATUS_NO_SUCH_FILE
                        return Err(SMBError::response_error(NTStatus::NoSuchFile));
                    }
                    enumeration.snapshot = Some(entries);
                    enumeration.position = 0;
                }
                let snapshot = enumeration
                    .snapshot
                    .as_ref()
                    .expect("snapshot populated above");
                Ok(snapshot[enumeration.position.min(snapshot.len())..].to_vec())
            }
        }
    }

    fn consume_directory_entries(&mut self, count: usize) {
        if let SMBFileSystemResourceHandle::Directory(enumeration) = &mut self.resource
            && let Some(snapshot) = &enumeration.snapshot
        {
            enumeration.position = (enumeration.position + count).min(snapshot.len());
        }
    }
}

/// Convert filesystem metadata into the SMB metadata representation.
fn fs_metadata_to_smb(metadata: &fs::Metadata) -> SMBFileMetadata {
    let time_transform =
        |time: SystemTime| time.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    SMBFileMetadata::new(
        FileTime::from_unix(metadata.created().map(time_transform).unwrap_or(0)),
        FileTime::from_unix(metadata.accessed().map(time_transform).unwrap_or(0)),
        FileTime::from_unix(metadata.modified().map(time_transform).unwrap_or(0)),
        FileTime::from_unix(metadata.modified().map(time_transform).unwrap_or(0)),
        metadata.len(),
        metadata.len(),
    )
}

/// Map filesystem metadata to SMB file attributes (MS-FSCC 2.6).
fn fs_metadata_to_attributes(metadata: &fs::Metadata) -> SMBFileAttributes {
    let mut attributes = if metadata.is_dir() {
        SMBFileAttributes::DIRECTORY
    } else {
        SMBFileAttributes::ARCHIVE
    };
    if metadata.permissions().readonly() {
        attributes |= SMBFileAttributes::READONLY;
    }
    attributes
}

/// The 8-byte file reference number for a directory entry (MS-FSCC 2.4.17
/// FileId). Uses the inode number where available.
#[cfg(unix)]
fn fs_metadata_file_id(metadata: &fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    metadata.ino()
}

#[cfg(not(unix))]
fn fs_metadata_file_id(_metadata: &fs::Metadata) -> u64 {
    0
}

fn directory_entry_from_metadata(name: &str, metadata: &fs::Metadata) -> SMBDirectoryEntry {
    SMBDirectoryEntry::new(
        name.into(),
        fs_metadata_to_smb(metadata),
        fs_metadata_to_attributes(metadata),
        fs_metadata_file_id(metadata),
    )
}

/// Scan `path` for entries matching `pattern`, sorted by name. Includes the
/// `.` and `..` entries when they match, per MS-FSCC 2.4.17. Entries whose
/// metadata cannot be read are skipped rather than failing the whole scan.
fn scan_directory(path: &str, pattern: &str) -> SMBResult<Vec<SMBDirectoryEntry>> {
    let mut entries = Vec::new();
    let dir_metadata = fs::metadata(path).map_err(SMBError::io_error)?;
    for dot in [".", ".."] {
        if matches_search_pattern(dot, pattern) {
            entries.push(directory_entry_from_metadata(dot, &dir_metadata));
        }
    }
    for dir_entry in fs::read_dir(path).map_err(SMBError::io_error)? {
        let dir_entry = dir_entry.map_err(SMBError::io_error)?;
        let name = dir_entry.file_name().to_string_lossy().into_owned();
        if !matches_search_pattern(&name, pattern) {
            continue;
        }
        let Ok(metadata) = dir_entry.metadata() else {
            warn!(name = %name, "skipping directory entry with unreadable metadata");
            continue;
        };
        entries.push(directory_entry_from_metadata(&name, &metadata));
    }
    entries.sort_by(|a, b| a.name().cmp(b.name()));
    Ok(entries)
}

/// Case-insensitive wildcard match for QueryDirectory search patterns
/// (MS-SMB2 §2.2.33): `*` matches any run of characters, `?` matches exactly
/// one. An empty pattern is treated as `*`.
fn matches_search_pattern(name: &str, pattern: &str) -> bool {
    let pattern = pattern.trim_end_matches('\0');
    if pattern.is_empty() || pattern == "*" {
        return true;
    }
    let name: Vec<char> = name.to_lowercase().chars().collect();
    let pattern: Vec<char> = pattern.to_lowercase().chars().collect();
    let (mut n, mut p) = (0usize, 0usize);
    let mut backtrack: Option<(usize, usize)> = None;
    while n < name.len() {
        if p < pattern.len() && (pattern[p] == '?' || pattern[p] == name[n]) {
            n += 1;
            p += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            backtrack = Some((p, n));
            p += 1;
        } else if let Some((star_p, star_n)) = backtrack {
            // Let the last `*` absorb one more character and retry
            backtrack = Some((star_p, star_n + 1));
            p = star_p + 1;
            n = star_n + 1;
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|c| *c == '*')
}

impl SMBFileSystemResourceHandle {
    fn file(path: &str, disposition: SMBCreateDisposition) -> SMBResult<Self> {
        let mut options = OpenOptions::new();
        options.read(true).write(true);
        match disposition {
            SMBCreateDisposition::Supersede => options.truncate(true).create(true),
            SMBCreateDisposition::Open => options.create(false),
            SMBCreateDisposition::Create => options.create_new(true),
            SMBCreateDisposition::OpenIf => options.truncate(false).create(true),
            SMBCreateDisposition::Overwrite => options.truncate(true).create(false),
            // MS-SMB2 §2.2.13: FILE_OVERWRITE_IF overwrites (truncates) an
            // existing file, unlike FILE_OPEN_IF which preserves its contents
            SMBCreateDisposition::OverwriteIf => options.truncate(true).create(true),
        };
        let file = options.open(path).map_err(SMBError::io_error)?;
        Ok(Self::File(file))
    }

    fn directory(path: &str) -> SMBResult<Self> {
        // Validate that the directory exists and is readable up front;
        // enumeration itself is driven lazily by QueryDirectory
        std::fs::read_dir(path).map_err(SMBError::io_error)?;
        Ok(Self::Directory(SMBDirectoryEnumeration::default()))
    }
}

pub struct SMBFileSystemShare<UserName: Send + Sync, Handle: TryFrom<SMBFileSystemHandle>> {
    name: String,
    server_name: String,
    local_path: String,
    connect_security: ConnectAllowed<UserName>,
    file_security: FilePerms<UserName>,
    csc_flags: SMBShareFlags,
    dfs_enabled: bool,
    do_access_based_directory_enumeration: bool,
    allow_namespace_caching: bool,
    force_shared_delete: bool,
    restrict_exclusive_options: bool,
    remark: String,
    max_uses: u64,
    current_uses: u64,
    force_level_2_oplock: bool,
    hash_enabled: bool,
    snapshot_list: Vec<u8>,
    ca_timeout: u64,
    continuously_available: bool,
    encrypt_data: bool,
    supports_identity_remoting: bool,
    compress_data: bool,
    user_name_type: PhantomData<UserName>,
    handle_phantom: PhantomData<Handle>,
}

impl<
    UserName: Send + Sync,
    Handle: From<SMBFileSystemHandle> + ResourceHandle + TryInto<SMBFileSystemHandle>,
> SharedResource for SMBFileSystemShare<UserName, Handle>
{
    type UserName = UserName;
    type Handle = Handle;

    fn name(&self) -> &str {
        &self.name
    }

    fn resource_type(&self) -> ResourceType {
        ResourceType::DISK
    }

    fn flags(&self) -> SMBShareFlags {
        self.csc_flags
    }

    fn handle_create(
        &self,
        path: &str,
        disposition: SMBCreateDisposition,
        directory: bool,
    ) -> SMBResult<Handle> {
        // Sanitize: strip NUL terminators from UTF-16LE wire encoding,
        // convert Windows backslashes to forward slashes
        let sanitized = path.trim_end_matches('\0').replace('\\', "/");

        // Normalize and reject path traversal attempts (e.g. "../../etc/passwd")
        let relative = normalize_path(&sanitized).ok_or_else(|| {
            warn!(path = %sanitized, "rejected path traversal attempt");
            SMBError::response_error(NTStatus::AccessDenied)
        })?;
        let path = format!("{}/{}", self.local_path, relative.display());

        let resource = match directory {
            true => SMBFileSystemResourceHandle::directory(&path),
            false => SMBFileSystemResourceHandle::file(&path, disposition),
        }?;
        let handle = SMBFileSystemHandle { resource, path };
        debug!(?handle, "created filesystem handle");
        Ok(handle.into())
    }

    fn connect_allowed(&self, uid: &Self::UserName) -> bool {
        (self.connect_security)(uid)
    }

    fn resource_perms(&self, uid: &Self::UserName) -> SMBAccessMask {
        (self.file_security)(uid)
    }
}

impl<UserName: Send + Sync, Handle: TryFrom<SMBFileSystemHandle>>
    SMBFileSystemShare<UserName, Handle>
{
    pub fn root(
        name: String,
        connect_security: ConnectAllowed<UserName>,
        file_security: FilePerms<UserName>,
    ) -> Self {
        Self::path(name, "".into(), connect_security, file_security)
    }
    pub fn path(
        name: String,
        path: String,
        connect_security: ConnectAllowed<UserName>,
        file_security: FilePerms<UserName>,
    ) -> Self {
        Self {
            name,
            server_name: "localhost".into(),
            local_path: path,
            connect_security,
            file_security,
            csc_flags: SMBShareFlags::default(),
            dfs_enabled: false,
            do_access_based_directory_enumeration: false,
            allow_namespace_caching: false,
            force_shared_delete: false,
            restrict_exclusive_options: false,
            remark: "some share comment".into(),
            max_uses: 10,
            current_uses: 0,
            force_level_2_oplock: false,
            hash_enabled: true,
            snapshot_list: vec![],
            ca_timeout: 1000,
            continuously_available: true,
            encrypt_data: true,
            supports_identity_remoting: true,
            compress_data: false,
            user_name_type: PhantomData,
            handle_phantom: PhantomData,
        }
    }
}

impl<UserName: Send + Sync, Handle: TryFrom<SMBFileSystemHandle>> Debug
    for SMBFileSystemShare<UserName, Handle>
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SMBServer")
            .field("name", &self.name)
            .field("server_name", &self.server_name)
            .field("local_path", &self.local_path)
            .field("csc_flags", &self.csc_flags)
            .field("dfs_enabled", &self.dfs_enabled)
            .field(
                "do_access_based_directory_enumeration",
                &self.do_access_based_directory_enumeration,
            )
            .field("allow_namespace_caching", &self.allow_namespace_caching)
            .field("force_shared_delete", &self.force_shared_delete)
            .field(
                "restrict_exclusive_options",
                &self.restrict_exclusive_options,
            )
            .field("remark", &self.remark)
            .field("max_uses", &self.max_uses)
            .field("current_uses", &self.current_uses)
            .field("force_level_2_oplock", &self.force_level_2_oplock)
            .field("hash_enabled", &self.hash_enabled)
            .field("snapshot_list", &self.snapshot_list)
            .field("ca_timeout", &self.ca_timeout)
            .field("continuously_available", &self.continuously_available)
            .field("encrypt_data", &self.encrypt_data)
            .field(
                "supports_identity_remoting",
                &self.supports_identity_remoting,
            )
            .field("compress_data", &self.compress_data)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_path_simple() {
        assert_eq!(
            normalize_path("foo/bar.txt"),
            Some(PathBuf::from("foo/bar.txt"))
        );
    }

    #[test]
    fn normalize_path_strips_current_dir() {
        assert_eq!(
            normalize_path("./foo/./bar.txt"),
            Some(PathBuf::from("foo/bar.txt"))
        );
    }

    #[test]
    fn normalize_path_resolves_parent_within_subtree() {
        assert_eq!(
            normalize_path("foo/bar/../baz.txt"),
            Some(PathBuf::from("foo/baz.txt"))
        );
    }

    #[test]
    fn normalize_path_rejects_traversal_above_root() {
        assert_eq!(normalize_path("../etc/passwd"), None);
    }

    #[test]
    fn normalize_path_rejects_deep_traversal() {
        assert_eq!(normalize_path("foo/../../etc/passwd"), None);
    }

    #[test]
    fn normalize_path_empty() {
        assert_eq!(normalize_path(""), Some(PathBuf::from("")));
    }

    #[test]
    fn normalize_path_backslash_after_sanitize() {
        assert_eq!(
            normalize_path("subdir/file.txt"),
            Some(PathBuf::from("subdir/file.txt"))
        );
    }

    #[test]
    fn read_data_returns_full_contents() {
        let dir = std::env::temp_dir().join("smb_test_read_full");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("read_test.bin");
        let data: Vec<u8> = (0..4096).map(|i| (i % 256) as u8).collect();
        std::fs::write(&path, &data).unwrap();

        let mut handle = SMBFileSystemHandle {
            path: path.to_string_lossy().into(),
            resource: SMBFileSystemResourceHandle::file(
                path.to_str().unwrap(),
                SMBCreateDisposition::Open,
            )
            .unwrap(),
        };

        let result = handle.read_data(0, 4096).unwrap();
        assert_eq!(
            result.len(),
            4096,
            "read_data must return all requested bytes when available"
        );
        assert_eq!(result, data);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn read_data_at_offset_returns_remaining() {
        let dir = std::env::temp_dir().join("smb_test_read_offset");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("offset_test.bin");
        let data = vec![0xAA; 100];
        std::fs::write(&path, &data).unwrap();

        let mut handle = SMBFileSystemHandle {
            path: path.to_string_lossy().into(),
            resource: SMBFileSystemResourceHandle::file(
                path.to_str().unwrap(),
                SMBCreateDisposition::Open,
            )
            .unwrap(),
        };

        // Read past end of file — should return only remaining bytes
        let result = handle.read_data(90, 50).unwrap();
        assert_eq!(result.len(), 10);

        // Read at exact EOF — should return empty
        let result = handle.read_data(100, 50).unwrap();
        assert!(result.is_empty());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn read_data_capped_at_max_read_size() {
        let dir = std::env::temp_dir().join("smb_test_read_cap");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cap_test.bin");
        // Write a small file but request more than MAX_READ_SIZE
        let data = vec![0xBB; 64];
        std::fs::write(&path, &data).unwrap();

        let mut handle = SMBFileSystemHandle {
            path: path.to_string_lossy().into(),
            resource: SMBFileSystemResourceHandle::file(
                path.to_str().unwrap(),
                SMBCreateDisposition::Open,
            )
            .unwrap(),
        };

        // Request u32::MAX bytes — should be capped and not OOM
        let result = handle.read_data(0, u32::MAX).unwrap();
        assert_eq!(result.len(), 64);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn read_data_directory_returns_error() {
        let dir = std::env::temp_dir().join("smb_test_read_dir");
        std::fs::create_dir_all(&dir).unwrap();

        let mut handle = SMBFileSystemHandle {
            path: dir.to_string_lossy().into(),
            resource: SMBFileSystemResourceHandle::directory(dir.to_str().unwrap()).unwrap(),
        };

        let result = handle.read_data(0, 100);
        assert!(result.is_err());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn write_data_writes_all_bytes() {
        let dir = std::env::temp_dir().join("smb_test_write_all");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("write_test.bin");
        // Create the file first
        std::fs::write(&path, b"").unwrap();

        let mut handle = SMBFileSystemHandle {
            path: path.to_string_lossy().into(),
            resource: SMBFileSystemResourceHandle::file(
                path.to_str().unwrap(),
                SMBCreateDisposition::Open,
            )
            .unwrap(),
        };

        let data = vec![0xCC; 4096];
        let written = handle.write_data(0, &data).unwrap();
        assert_eq!(written, 4096);

        // Verify the file contents
        let contents = std::fs::read(&path).unwrap();
        assert_eq!(contents, data);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn write_data_at_offset() {
        let dir = std::env::temp_dir().join("smb_test_write_offset");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("offset_write.bin");
        std::fs::write(&path, vec![0xAA; 100]).unwrap();

        let mut handle = SMBFileSystemHandle {
            path: path.to_string_lossy().into(),
            resource: SMBFileSystemResourceHandle::file(
                path.to_str().unwrap(),
                SMBCreateDisposition::Open,
            )
            .unwrap(),
        };

        let patch = vec![0xBB; 10];
        let written = handle.write_data(50, &patch).unwrap();
        assert_eq!(written, 10);

        let contents = std::fs::read(&path).unwrap();
        assert_eq!(&contents[..50], &[0xAA; 50]);
        assert_eq!(&contents[50..60], &[0xBB; 10]);
        assert_eq!(&contents[60..], &[0xAA; 40]);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn write_data_capped_at_max_write_size() {
        let dir = std::env::temp_dir().join("smb_test_write_cap");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cap_write.bin");
        std::fs::write(&path, b"").unwrap();

        let mut handle = SMBFileSystemHandle {
            path: path.to_string_lossy().into(),
            resource: SMBFileSystemResourceHandle::file(
                path.to_str().unwrap(),
                SMBCreateDisposition::Open,
            )
            .unwrap(),
        };

        // Write a small amount — just verify capping logic doesn't break small writes
        let data = vec![0xDD; 64];
        let written = handle.write_data(0, &data).unwrap();
        assert_eq!(written, 64);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn write_data_directory_returns_error() {
        let dir = std::env::temp_dir().join("smb_test_write_dir");
        std::fs::create_dir_all(&dir).unwrap();

        let mut handle = SMBFileSystemHandle {
            path: dir.to_string_lossy().into(),
            resource: SMBFileSystemResourceHandle::directory(dir.to_str().unwrap()).unwrap(),
        };

        let result = handle.write_data(0, &[0xFF; 10]);
        assert!(result.is_err());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn write_then_read_round_trip() {
        let dir = std::env::temp_dir().join("smb_test_write_read_rt");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("round_trip.bin");
        std::fs::write(&path, b"").unwrap();

        let mut handle = SMBFileSystemHandle {
            path: path.to_string_lossy().into(),
            resource: SMBFileSystemResourceHandle::file(
                path.to_str().unwrap(),
                SMBCreateDisposition::Open,
            )
            .unwrap(),
        };

        let data: Vec<u8> = (0..256).map(|i| i as u8).collect();
        let written = handle.write_data(0, &data).unwrap();
        assert_eq!(written, 256);

        let read_back = handle.read_data(0, 256).unwrap();
        assert_eq!(read_back, data);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn overwrite_if_truncates_existing_file() {
        let dir = std::env::temp_dir().join("smb_test_overwrite_if");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("overwrite.bin");
        std::fs::write(&path, vec![0xAA; 40]).unwrap();

        // Re-opening with OverwriteIf must truncate the existing contents,
        // otherwise a shorter rewrite leaves stale trailing bytes behind
        let mut handle = SMBFileSystemHandle {
            path: path.to_string_lossy().into(),
            resource: SMBFileSystemResourceHandle::file(
                path.to_str().unwrap(),
                SMBCreateDisposition::OverwriteIf,
            )
            .unwrap(),
        };

        let written = handle.write_data(0, b"short").unwrap();
        assert_eq!(written, 5);

        let contents = std::fs::read(&path).unwrap();
        assert_eq!(contents, b"short");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn matches_search_pattern_wildcards() {
        assert!(matches_search_pattern("anything", "*"));
        assert!(matches_search_pattern("anything", ""));
        assert!(matches_search_pattern("file.txt", "*.txt"));
        assert!(!matches_search_pattern("file.log", "*.txt"));
        assert!(matches_search_pattern("file.txt", "file.???"));
        assert!(!matches_search_pattern("file.txt", "file.??"));
        assert!(matches_search_pattern("abc", "a*c"));
        assert!(!matches_search_pattern("abd", "a*c"));
        assert!(matches_search_pattern("a", "*a*"));
        // Case-insensitive per SMB naming conventions
        assert!(matches_search_pattern("FILE.TXT", "file.txt"));
        assert!(matches_search_pattern("file.txt", "FILE.*"));
        // Wire strings may carry trailing NULs
        assert!(matches_search_pattern("file.txt", "*.txt\0"));
        // Literal (no wildcard) patterns are exact matches
        assert!(matches_search_pattern("exact.txt", "exact.txt"));
        assert!(!matches_search_pattern("exact.txt", "exact"));
    }

    #[test]
    fn query_directory_lists_matching_entries_and_drains() {
        let dir = std::env::temp_dir().join("smb_test_query_dir");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("alpha.txt"), b"a").unwrap();
        std::fs::write(dir.join("beta.log"), b"b").unwrap();
        std::fs::create_dir(dir.join("subdir")).unwrap();

        let mut handle = SMBFileSystemHandle {
            path: dir.to_string_lossy().into(),
            resource: SMBFileSystemResourceHandle::directory(dir.to_str().unwrap()).unwrap(),
        };

        let entries = handle.query_directory("*", false).unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name()).collect();
        assert_eq!(names, vec![".", "..", "alpha.txt", "beta.log", "subdir"]);
        assert!(
            entries[4]
                .attributes()
                .contains(SMBFileAttributes::DIRECTORY)
        );
        assert!(entries[2].attributes().contains(SMBFileAttributes::ARCHIVE));

        // Consume the first three; a follow-up query returns the remainder
        handle.consume_directory_entries(3);
        let entries = handle.query_directory("*", false).unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name()).collect();
        assert_eq!(names, vec!["beta.log", "subdir"]);

        // Drain fully — enumeration is exhausted but not restarted
        handle.consume_directory_entries(2);
        assert!(handle.query_directory("*", false).unwrap().is_empty());

        // Restart rescans from the beginning with the new pattern
        let entries = handle.query_directory("*.txt", true).unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name()).collect();
        assert_eq!(names, vec!["alpha.txt"]);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn query_directory_no_match_returns_error() {
        let dir = std::env::temp_dir().join("smb_test_query_dir_nomatch");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mut handle = SMBFileSystemHandle {
            path: dir.to_string_lossy().into(),
            resource: SMBFileSystemResourceHandle::directory(dir.to_str().unwrap()).unwrap(),
        };

        // Pattern matching nothing on a fresh scan → STATUS_NO_SUCH_FILE
        assert!(handle.query_directory("missing.txt", false).is_err());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn query_directory_on_file_returns_error() {
        let dir = std::env::temp_dir().join("smb_test_query_dir_on_file");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("plain.txt");
        std::fs::write(&path, b"x").unwrap();

        let mut handle = SMBFileSystemHandle {
            path: path.to_string_lossy().into(),
            resource: SMBFileSystemResourceHandle::file(
                path.to_str().unwrap(),
                SMBCreateDisposition::Open,
            )
            .unwrap(),
        };

        assert!(handle.query_directory("*", false).is_err());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn open_if_preserves_existing_file() {
        let dir = std::env::temp_dir().join("smb_test_open_if");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("preserve.bin");
        std::fs::write(&path, vec![0xBB; 40]).unwrap();

        let mut handle = SMBFileSystemHandle {
            path: path.to_string_lossy().into(),
            resource: SMBFileSystemResourceHandle::file(
                path.to_str().unwrap(),
                SMBCreateDisposition::OpenIf,
            )
            .unwrap(),
        };

        let read_back = handle.read_data(0, 40).unwrap();
        assert_eq!(read_back, vec![0xBB; 40]);

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
