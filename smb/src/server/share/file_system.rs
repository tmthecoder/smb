use std::fmt::{Debug, Formatter};
use std::fs::{File, OpenOptions};
use std::marker::PhantomData;

use smb_core::error::SMBError;
use smb_core::SMBResult;

use crate::protocol::body::create::disposition::SMBCreateDisposition;
use crate::protocol::body::tree_connect::access_mask::SMBAccessMask;
use crate::protocol::body::tree_connect::flags::SMBShareFlags;
use crate::server::share::{ResourceHandle, ResourceType, SharedResource};

pub enum SMBFileSystemHandle {
    File(File),
    Directory(String)
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
        Ok(Self::Directory(path.into()))
    }
}

pub struct SMBFileSystemShare<UserName: Send + Sync, ConnectAllowed: Fn(&UserName) -> bool + Send, FilePerms: Fn(&UserName) -> SMBAccessMask + Send> {
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
    user_name_type: PhantomData<UserName>
}

impl<UserName: Send + Sync, ConnectAllowed: Fn(&UserName) -> bool + Send, FilePerms: Fn(&UserName) -> SMBAccessMask + Send> Debug for SMBFileSystemShare<UserName, ConnectAllowed, FilePerms> {
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

impl<UserName: Send + Sync, ConnectAllowed: Fn(&UserName) -> bool + Send + Sync, FilePerms: Fn(&UserName) -> SMBAccessMask + Send + Sync> SharedResource for SMBFileSystemShare<UserName, ConnectAllowed, FilePerms> {
    type UserName = UserName;

    fn name(&self) -> &str {
        &self.name
    }

    fn resource_type(&self) -> ResourceType {
        ResourceType::DISK
    }

    fn flags(&self) -> SMBShareFlags {
        self.csc_flags
    }

    fn handle_create(&self, path: &str, disposition: SMBCreateDisposition) -> SMBResult<Box<dyn ResourceHandle>> {
        let handle = SMBFileSystemHandle::file(path, disposition)?;
        Ok(Box::new(handle))
    }

    fn connect_allowed(&self, uid: &Self::UserName) -> bool {
        (self.connect_security)(uid)
    }

    fn resource_perms(&self, uid: &Self::UserName) -> SMBAccessMask {
        (self.file_security)(uid)
    }
}

impl<UserName: Send + Sync, ConnectAllowed: Fn(&UserName) -> bool + Send, FilePerms: Fn(&UserName) -> SMBAccessMask + Send> SMBFileSystemShare<UserName, ConnectAllowed, FilePerms> {
    pub fn root(name: String, connect_security: ConnectAllowed, file_security: FilePerms) -> Self {
        Self {
            name,
            server_name: "localhost".into(),
            local_path: "/".into(),
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
            user_name_type: PhantomData
        }
    }
}