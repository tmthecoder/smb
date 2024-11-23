use bitflags::bitflags;
use serde::{Deserialize, Serialize};

bitflags! {
    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone, Copy)]
    pub struct SMBTreeConnectFlags: u16 {
        const EXTENSION_PRESENT    = 0b100;
        const REDIRECT_TO_OWNER    = 0b10;
        const CLUSTER_RECONNECT    = 0b1;
        const RESERVED             = 0b0;
    }
}

bitflags! {
    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Copy, Clone)]
    pub struct SMBShareFlags: u32 {
        const MANUAL_CACHING              = 0x000000;
        const AUTO_CACHING                = 0x000010;
        const VDO_CACHING                 = 0x000020;
        const NO_CACHING                  = 0x000030;
        const DFS                         = 0x000001;
        const DFS_ROOT                    = 0x000002;
        const RESTRICT_EXCLUSIVE_OPENS    = 0x000100;
        const FORCE_SHARED_DELETE         = 0x000200;
        const ALLOW_NAMESPACE_CACHING     = 0x000400;
        const ACCESS_BASED_DIRECTORY_ENUM = 0x000800;
        const FORCE_LEVEL_II_OPLOCK       = 0x001000;
        const ENABLE_HASH_V1              = 0x002000;
        const ENABLE_HASH_V2              = 0x004000;
        const ENCRYPT_DATA                = 0x008000;
        const IDENTITY_REMOTING           = 0x040000;
        const COMPRESS_DATA               = 0x100000;
        const ISOLATED_TRANSPORT          = 0x200000;
    }
}

impl Default for SMBShareFlags {
    fn default() -> Self {
        Self::MANUAL_CACHING
    }
}