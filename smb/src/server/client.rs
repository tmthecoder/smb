use uuid::Uuid;

use crate::protocol::body::dialect::SMBDialect;

#[derive(Debug)]
pub struct SMBClient {
    client_guid: Uuid,
    dialect: SMBDialect
}