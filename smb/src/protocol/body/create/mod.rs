use std::marker::PhantomData;

use serde::{Deserialize, Serialize};

use smb_core::error::SMBError;
use smb_core::nt_status::NTStatus;
use smb_core::SMBResult;
use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

use crate::protocol::body::create::action::SMBCreateAction;
use crate::protocol::body::create::disposition::SMBCreateDisposition;
use crate::protocol::body::create::file_attributes::SMBFileAttributes;
use crate::protocol::body::create::file_id::SMBFileId;
use crate::protocol::body::create::flags::SMBCreateFlags;
use crate::protocol::body::create::impersonation_level::SMBImpersonationLevel;
use crate::protocol::body::create::oplock::SMBOplockLevel;
use crate::protocol::body::create::options::SMBCreateOptions;
use crate::protocol::body::create::request_context::CreateRequestContext;
use crate::protocol::body::create::response_context::CreateResponseContext;
use crate::protocol::body::create::share_access::SMBShareAccess;
use crate::protocol::body::filetime::FileTime;
use crate::protocol::body::tree_connect::access_mask::SMBAccessMask;
use crate::server::share::{ResourceType, SharedResource};

pub mod options;
pub mod oplock;
pub mod impersonation_level;
pub mod file_attributes;
pub mod share_access;
pub mod disposition;
pub mod request_context;
pub mod file_id;
mod flags;
mod action;
mod response_context;

#[macro_use]
pub(crate) mod context_helper;

#[derive(Debug, PartialEq, Eq, SMBByteSize, SMBToBytes, SMBFromBytes, Serialize, Deserialize)]
#[smb_byte_tag(57)]
pub struct SMBCreateRequest {
    #[smb_direct(start(fixed = 3))]
    oplock_level: SMBOplockLevel,
    #[smb_direct(start(fixed = 4))]
    impersonation_level: SMBImpersonationLevel,
    #[smb_enum(start(fixed = 24), discriminator(inner(start = 28, num_type = "u32")), modifier(and = 0x10), modifier(right_shift = 4))]
    desired_access: SMBAccessMask,
    #[smb_direct(start(fixed = 28))]
    attributes: SMBFileAttributes,
    #[smb_direct(start(fixed = 32))]
    share_access: SMBShareAccess,
    #[smb_direct(start(fixed = 36))]
    create_disposition: SMBCreateDisposition,
    #[smb_direct(start(fixed = 40))]
    create_options: SMBCreateOptions,
    #[smb_string(order = 0, start(inner(start = 44, num_type = "u16", subtract = 68)), length(inner(start = 46, num_type = "u16")), underlying = "u16")]
    file_name: String,
    #[smb_vector(order = 1, align = 8, length(inner(start = 52, num_type = "u32")), offset(inner(start = 48, num_type = "u32", subtract = 64)))]
    contexts: Vec<CreateRequestContext>,
}

impl SMBCreateRequest {
    pub fn file_name(&self) -> &str {
        &self.file_name
    }

    pub fn disposition(&self) -> SMBCreateDisposition {
        self.create_disposition
    }

    fn validate_directory(&self) -> bool {
        self.create_disposition.validate_directory() && self.create_options.validate_directory()
    }

    fn validate_print(&self) -> bool {
        !self.attributes.contains(SMBFileAttributes::DIRECTORY) &&
            self.desired_access.validate_print() &&
            self.create_disposition == SMBCreateDisposition::Create
    }

    pub fn validate<R: SharedResource>(&self, resource: &R) -> SMBResult<(&str, SMBCreateDisposition, bool)> {
        if resource.resource_type() == ResourceType::PRINT_QUEUE && !self.validate_print() {
            return Err(SMBError::response_error(NTStatus::NotSupported))
        }
        if self.create_options.contains(SMBCreateOptions::DIRECTORY_FILE) &&
            !self.validate_directory() {
            // TODO make this the right error code
            return Err(SMBError::response_error(NTStatus::NotSupported));
        }
        Ok((&self.file_name(), self.disposition(), self.create_options.contains(SMBCreateOptions::DIRECTORY_FILE)))
    }
}

#[derive(Debug, PartialEq, Eq, SMBByteSize, SMBToBytes, SMBFromBytes, Serialize, Deserialize)]
#[smb_byte_tag(89)]
pub struct SMBCreateResponse {
    #[smb_direct(start(fixed = 2))]
    oplock_level: SMBOplockLevel,
    #[smb_direct(start(fixed = 3))]
    flags: SMBCreateFlags,
    #[smb_direct(start(fixed = 4))]
    action: SMBCreateAction,
    #[smb_direct(start(fixed = 8))]
    creation_time: FileTime,
    #[smb_direct(start(fixed = 16))]
    last_access_time: FileTime,
    #[smb_direct(start(fixed = 24))]
    last_write_time: FileTime,
    #[smb_direct(start(fixed = 32))]
    change_time: FileTime,
    #[smb_direct(start(fixed = 40))]
    allocation_size: u64,
    #[smb_direct(start(fixed = 48))]
    end_of_file: u64,
    #[smb_skip(start = 56, length = 4)]
    reserved: PhantomData<Vec<u8>>,
    #[smb_direct(start(fixed = 60))]
    file_id: SMBFileId,
    #[smb_vector(order = 0, align = 8, offset(inner(start = 64, num_type = "u32", subtract = 64)), count(inner(start = 68, num_type = "u32")), )]
    contexts: Vec<CreateResponseContext>,
}