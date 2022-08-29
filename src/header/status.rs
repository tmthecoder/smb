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