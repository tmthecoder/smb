mod negotiate_context;
mod negotiate;

pub type SMBNegotiateRequest = negotiate::SMBNegotiateRequestBody;
pub type SMBNegotiateResponse = negotiate::SMBNegotiateResponseBody;

pub type NegotiateContext = negotiate_context::NegotiateContext;
pub type CompressionAlgorithm = negotiate_context::CompressionAlgorithm;
pub type RDMATransformID = negotiate_context::RDMATransformID;