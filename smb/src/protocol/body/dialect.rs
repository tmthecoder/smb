use num_enum::TryFromPrimitive;
use serde::{Deserialize, Serialize};

use smb_derive::{SMBByteSize, SMBFromBytes, SMBToBytes};

#[repr(u16)]
#[derive(Debug, Eq, PartialEq, TryFromPrimitive, Serialize, Deserialize, Copy, Clone, Ord, PartialOrd, SMBFromBytes, SMBByteSize, SMBToBytes, Default)]
#[allow(non_camel_case_types)]
pub enum SMBDialect {
    V2_0_2 = 0x202,
    V2_1_0 = 0x210,
    V3_0_0 = 0x300,
    V3_0_2 = 0x302,
    V3_1_1 = 0x311,
    #[default]
    V2_X_X = 0x2FF
}

impl SMBDialect {
    pub fn is_smb3(&self) -> bool {
        *self as u16 >= 0x300
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smb_core::{SMBFromBytes, SMBToBytes};

    #[test]
    fn dialect_values_match_spec() {
        assert_eq!(SMBDialect::V2_0_2 as u16, 0x0202);
        assert_eq!(SMBDialect::V2_1_0 as u16, 0x0210);
        assert_eq!(SMBDialect::V3_0_0 as u16, 0x0300);
        assert_eq!(SMBDialect::V3_0_2 as u16, 0x0302);
        assert_eq!(SMBDialect::V3_1_1 as u16, 0x0311);
        assert_eq!(SMBDialect::V2_X_X as u16, 0x02FF);
    }

    #[test]
    fn is_smb3_classification() {
        assert!(!SMBDialect::V2_0_2.is_smb3());
        assert!(!SMBDialect::V2_1_0.is_smb3());
        assert!(!SMBDialect::V2_X_X.is_smb3());
        assert!(SMBDialect::V3_0_0.is_smb3());
        assert!(SMBDialect::V3_0_2.is_smb3());
        assert!(SMBDialect::V3_1_1.is_smb3());
    }

    #[test]
    fn dialect_ordering() {
        assert!(SMBDialect::V2_0_2 < SMBDialect::V2_1_0);
        assert!(SMBDialect::V2_1_0 < SMBDialect::V3_0_0);
        assert!(SMBDialect::V3_0_0 < SMBDialect::V3_0_2);
        assert!(SMBDialect::V3_0_2 < SMBDialect::V3_1_1);
    }

    #[test]
    fn dialect_round_trip() {
        let dialect = SMBDialect::V3_1_1;
        let bytes = dialect.smb_to_bytes();
        assert_eq!(bytes, [0x11, 0x03]);
        let (_, parsed) = SMBDialect::smb_from_bytes(&bytes).unwrap();
        assert_eq!(parsed, dialect);
    }
}