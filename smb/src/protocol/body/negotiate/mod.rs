mod negotiate_context;
mod negotiate;
mod negotiate_security_mode;

pub type SMBNegotiateRequest = negotiate::SMBNegotiateRequest;
pub type SMBNegotiateResponse = negotiate::SMBNegotiateResponseBody;

pub type NegotiateSecurityMode = negotiate_security_mode::NegotiateSecurityMode;
pub type NegotiateContext = negotiate_context::NegotiateContext;
pub type CompressionAlgorithm = negotiate_context::CompressionAlgorithm;
pub type RDMATransformID = negotiate_context::RDMATransformID;
