use std::fmt::{Debug, Formatter};
use std::fs::{File, OpenOptions, ReadDir};
use std::marker::PhantomData;

use smb_core::error::SMBError;
use smb_core::SMBResult;

use crate::protocol::body::create::disposition::SMBCreateDisposition;
use crate::protocol::body::tree_connect::access_mask::SMBAccessMask;
use crate::protocol::body::tree_connect::flags::SMBShareFlags;
use crate::server::share::{ResourceHandle, ResourceType, SharedResource};

#[derive(Debug)]
pub enum SMBFileSystemHandle {
    File(File),
    Directory(ReadDir)
}

impl TryFrom<SMBFileSystemHandle> for Box<dyn ResourceHandle> {
    type Error = SMBError;

    fn try_from(value: SMBFileSystemHandle) -> Result<Self, Self::Error> {
        Ok(Box::new(value))
    }
}

impl ResourceHandle for SMBFileSystemHandle {
    fn close(self: Box<Self>) -> SMBResult<()> {
        Ok(())
    }

    fn is_directory(&self) -> bool {
        match &self {
            SMBFileSystemHandle::File(_) => false,
            SMBFileSystemHandle::Directory(_) => true
        }
    }
}

impl SMBFileSystemHandle {
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

pub struct SMBFileSystemShare<UserName: Send + Sync, ConnectAllowed: Fn(&UserName) -> bool + Send, FilePerms: Fn(&UserName) -> SMBAccessMask + Send, Handle: TryFrom<SMBFileSystemHandle>> {
    name: String,
    server_name: String,
    local_path: String,
    connect_security: ConnectAllowed,
    file_security: FilePerms,
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

impl<UserName: Send + Sync, ConnectAllowed: Fn(&UserName) -> bool + Send, FilePerms: Fn(&UserName) -> SMBAccessMask + Send, Handle: TryFrom<SMBFileSystemHandle>> Debug for SMBFileSystemShare<UserName, ConnectAllowed, FilePerms, Handle> {
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

// Todo rework this to have two handle types (local and server-global)
impl<UserName: Send + Sync, ConnectAllowed: Fn(&UserName) -> bool + Send + Sync, FilePerms: Fn(&UserName) -> SMBAccessMask + Send + Sync, Handle: TryFrom<SMBFileSystemHandle> + ResourceHandle> SharedResource for SMBFileSystemShare<UserName, ConnectAllowed, FilePerms, Handle> {
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
        let handle = match directory {
            true => SMBFileSystemHandle::directory(&path),
            false => SMBFileSystemHandle::file(&path, disposition)
        }?;
        println!("Created fs handle: {:?}", handle);
        Ok(handle.try_into().ok().unwrap())
    }

    fn connect_allowed(&self, uid: &Self::UserName) -> bool {
        (self.connect_security)(uid)
    }

    fn resource_perms(&self, uid: &Self::UserName) -> SMBAccessMask {
        (self.file_security)(uid)
    }
}

impl<UserName: Send + Sync, ConnectAllowed: Fn(&UserName) -> bool + Send, FilePerms: Fn(&UserName) -> SMBAccessMask + Send, Handle: TryFrom<SMBFileSystemHandle>> SMBFileSystemShare<UserName, ConnectAllowed, FilePerms, Handle> {
    pub fn root(name: String, connect_security: ConnectAllowed, file_security: FilePerms) -> Self {
        Self {
            name,
            server_name: "localhost".into(),
            local_path: "".into(),
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