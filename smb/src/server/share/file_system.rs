use std::any::Any;
use std::fmt::{Debug, Formatter};
use std::fs;
use std::fs::{File, OpenOptions, ReadDir};
use std::marker::PhantomData;
use std::time::{SystemTime, UNIX_EPOCH};

use smb_core::error::SMBError;
use smb_core::logging::debug;
use smb_core::SMBResult;

use crate::protocol::body::create::disposition::SMBCreateDisposition;
use crate::protocol::body::filetime::FileTime;
use crate::protocol::body::tree_connect::access_mask::SMBAccessMask;
use crate::protocol::body::tree_connect::flags::SMBShareFlags;
use crate::server::share::{ConnectAllowed, FilePerms, ResourceHandle, ResourceType, SharedResource, SMBFileMetadata};

#[derive(Debug)]
pub struct SMBFileSystemHandle {
    path: String,
    resource: SMBFileSystemResourceHandle,
}

#[derive(Debug)]
pub enum SMBFileSystemResourceHandle {
    File(File),
    Directory(ReadDir)
}

impl From<SMBFileSystemHandle> for Box<dyn ResourceHandle> {
    fn from(value: SMBFileSystemHandle) -> Self {
        Box::new(value)
    }
}

impl TryFrom<Box<dyn ResourceHandle>> for SMBFileSystemHandle {
    type Error = SMBError;

    fn try_from(value: Box<dyn ResourceHandle>) -> Result<Self, Self::Error> {
        value.into_any().downcast::<Self>()
            .ok().ok_or(SMBError::server_error("Invalid resource handle"))
            .map(|val| *val)
    }
}

impl<UserName: Send + Sync + 'static, Handle: From<SMBFileSystemHandle> + TryInto<SMBFileSystemHandle> + ResourceHandle + 'static> From<SMBFileSystemShare<UserName, Handle>> for Box<dyn SharedResource<UserName=UserName, Handle=Handle>> {
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
            SMBFileSystemResourceHandle::Directory(_) => true
        }
    }

    fn path(&self) -> &str {
        &self.path
    }

    fn metadata(&self) -> SMBResult<SMBFileMetadata> {
        let metadata = fs::metadata(&self.path())
            .map_err(|err| SMBError::server_error(format!("Failed to get metadata for path: {}, error: {}", self.path(), err)))?;
        let time_transform = |time: SystemTime| {
            time.duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
        };
        Ok(SMBFileMetadata {
            creation_time: FileTime::from_unix(metadata.created().map(time_transform).unwrap_or(0)),
            last_access_time: FileTime::from_unix(metadata.accessed().map(time_transform).unwrap_or(0)),
            last_write_time: FileTime::from_unix(metadata.modified().map(time_transform).unwrap_or(0)),
            last_modification_time: FileTime::from_unix(metadata.modified().map(time_transform).unwrap_or(0)),
            allocated_size: metadata.len(),
            actual_size: metadata.len(),
        })
    }
}

impl SMBFileSystemResourceHandle {
    fn file(path: &str, disposition: SMBCreateDisposition) -> SMBResult<Self> {
        let mut options = OpenOptions::new();
        options.read(true)
            .write(true);
        match disposition {
            SMBCreateDisposition::Supersede => options
                .truncate(true)
                .create(true),
            SMBCreateDisposition::Open => options
                .create(false),
            SMBCreateDisposition::Create => options
                .create_new(true),
            SMBCreateDisposition::OpenIf => options
                .truncate(false)
                .create(true),
            SMBCreateDisposition::Overwrite => options
                .truncate(true)
                .create(false),
            SMBCreateDisposition::OverwriteIf => options
                .truncate(false)
                .create(true)
        };
        let file = options.open(path).map_err(SMBError::io_error)?;
        Ok(Self::File(file))
    }

    fn directory(path: &str) -> SMBResult<Self> {
        let res = std::fs::read_dir(path)
            .map_err(SMBError::io_error)?;
        Ok(Self::Directory(res))
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

impl<UserName: Send + Sync, Handle: From<SMBFileSystemHandle> + ResourceHandle + TryInto<SMBFileSystemHandle>> SharedResource for SMBFileSystemShare<UserName, Handle> {
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

    fn handle_create(&self, path: &str, disposition: SMBCreateDisposition, directory: bool) -> SMBResult<Handle> {
        let path = format!("{}/{}", self.local_path, path);
        let resource = match directory {
            true => SMBFileSystemResourceHandle::directory(&path),
            false => SMBFileSystemResourceHandle::file(&path, disposition)
        }?;
        let handle = SMBFileSystemHandle {
            resource,
            path: path.into(),
        };
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

impl<UserName: Send + Sync, Handle: TryFrom<SMBFileSystemHandle>> SMBFileSystemShare<UserName, Handle> {
    pub fn root(name: String, connect_security: ConnectAllowed<UserName>, file_security: FilePerms<UserName>) -> Self {
        Self::path(name, "".into(), connect_security, file_security)
    }
    pub fn path(name: String, path: String, connect_security: ConnectAllowed<UserName>, file_security: FilePerms<UserName>) -> Self {
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
            handle_phantom: PhantomData
        }
    }
}

impl<UserName: Send + Sync, Handle: TryFrom<SMBFileSystemHandle>> Debug for SMBFileSystemShare<UserName, Handle> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SMBServer")
            .field("name", &self.name)
            .field("server_name", &self.server_name)
            .field("local_path", &self.local_path)
            .field("csc_flags", &self.csc_flags)
            .field("dfs_enabled", &self.dfs_enabled)
            .field("do_access_based_directory_enumeration", &self.do_access_based_directory_enumeration)
            .field("allow_namespace_caching", &self.allow_namespace_caching)
            .field("force_shared_delete", &self.force_shared_delete)
            .field("restrict_exclusive_options", &self.restrict_exclusive_options)
            .field("remark", &self.remark)
            .field("max_uses", &self.max_uses)
            .field("current_uses", &self.current_uses)
            .field("force_level_2_oplock", &self.force_level_2_oplock)
            .field("hash_enabled", &self.hash_enabled)
            .field("snapshot_list", &self.snapshot_list)
            .field("ca_timeout", &self.ca_timeout)
            .field("continuously_available", &self.continuously_available)
            .field("encrypt_data", &self.encrypt_data)
            .field("supports_identity_remoting", &self.supports_identity_remoting)
            .field("compress_data", &self.compress_data)
            .finish()
    }
}