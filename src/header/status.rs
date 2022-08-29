use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub enum SMBStatus {
    NTStatus(NTStatusLevel),
    DosError(char, char, u16)
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct NTStatusCode {
    level: NTStatusLevel,
}

#[repr(u8)]
#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub enum NTStatusLevel {
    Success,
    Information,
    Warning,
    Error
}

impl SMBStatus {
    pub(crate) fn from_bytes(bytes: &[u8]) {

    }
}

impl SMBStatus {
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &[0_u8]
    }
}