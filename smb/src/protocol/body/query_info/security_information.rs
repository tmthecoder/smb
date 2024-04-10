use bitflags::bitflags;
use serde::{Deserialize, Serialize};

use crate::util::flags_helper::{impl_smb_byte_size_for_bitflag, impl_smb_from_bytes_for_bitflag, impl_smb_to_bytes_for_bitflag};

bitflags! {
    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub struct SMBSecurityInformation: u32 {
        const OWNER_SECURITY_INFORMATION = 0x00000001;
        const GROUP_SECURITY_INFORMATION = 0x00000002;
        const DACL_SECURITY_INFORMATION = 0x00000004;
        const SACL_SECURITY_INFORMATION = 0x00000008;
        const LABEL_SECURITY_INFORMATION = 0x00000010;
        const ATTRIBUTE_SECURITY_INFORMATION = 0x00000020;
        const SCOPE_SECURITY_INFORMATION = 0x00000040;
        const BACKUP_SECURITY_INFORMATION = 0x00010000;
    }
}

impl_smb_byte_size_for_bitflag!(SMBSecurityInformation);
impl_smb_to_bytes_for_bitflag!(SMBSecurityInformation);
impl_smb_from_bytes_for_bitflag!(SMBSecurityInformation);
