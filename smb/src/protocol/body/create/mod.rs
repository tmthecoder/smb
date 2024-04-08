use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

use crate::protocol::body::create::context::CreateContext;
use crate::protocol::body::create::disposition::SMBCreateDisposition;
use crate::protocol::body::create::file_attributes::SMBFileAttributes;
use crate::protocol::body::create::impersonation_level::SMBImpersonationLevel;
use crate::protocol::body::create::oplock::SMBOplockLevel;
use crate::protocol::body::create::options::SMBCreateOptions;
use crate::protocol::body::create::share_access::SMBShareAccess;
use crate::protocol::body::tree_connect::access_mask::SMBFilePipePrinterAccessMask;

pub mod options;
pub mod oplock;
pub mod impersonation_level;
pub mod file_attributes;
mod share_access;
mod disposition;
mod context;

#[derive(Debug, PartialEq, Eq, SMBByteSize, SMBToBytes, SMBFromBytes, Serialize, Deserialize)]
#[smb_byte_tag(57)]
pub struct SMBCreateRequest {
    #[smb_direct(start(fixed = 3))]
    oplock_level: SMBOplockLevel,
    #[smb_direct(start(fixed = 4))]
    impersonation_level: SMBImpersonationLevel,
    #[smb_direct(start(fixed = 24))]
    desired_access: SMBFilePipePrinterAccessMask,
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
    #[smb_vector(order = 1, align = 8, count(inner(start = 52, num_type = "u32")), offset(inner(start = 48, num_type = "u32", subtract = 64)))]
    contexts: Vec<CreateContext>,
}