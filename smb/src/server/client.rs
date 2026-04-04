use uuid::Uuid;

use crate::protocol::body::dialect::SMBDialect;

#[derive(Debug)]
#[allow(dead_code)]
pub struct SMBClient {
    client_guid: Uuid,
    dialect: SMBDialect
}