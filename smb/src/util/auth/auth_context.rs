#[derive(Debug)]
#[allow(dead_code)]
pub struct GenericAuthContext {
    domain_name: String,
    user_name: String,
    work_station: String,
    version: String,
    guest: bool,
}