use uuid::Uuid;
use crate::body::SMBDialect;

pub struct SMBClient {
    client_guid: Uuid,
    dialect: SMBDialect
}