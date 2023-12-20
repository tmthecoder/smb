use uuid::Uuid;

use crate::protocol::body::SMBDialect;

pub struct SMBClient {
    client_guid: Uuid,
    dialect: SMBDialect
}