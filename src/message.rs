use crate::header::SMBHeader;
use crate::data::SMBData;
use crate::parameters::SMBParameters;

pub struct SMBMessage {
    pub(crate) header: SMBHeader,
    pub(crate) parameters: Vec<SMBParameters>,
    pub(crate) data: Vec<SMBData>
}