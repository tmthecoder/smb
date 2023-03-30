mod session_setup;
mod session_setup_security_mode;

pub type SMBSessionSetupRequest = session_setup::SMBSessionSetupRequest;
pub type SMBSessionSetupResponse = session_setup::SMBSessionSetupResponse;

pub type SessionSetupSecurityMode = session_setup_security_mode::SessionSetupSecurityMode;