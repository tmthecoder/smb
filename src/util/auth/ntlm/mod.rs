mod ntlm_auth_provider;
mod ntlm_message;

pub type NTLMAuthProvider = ntlm_auth_provider::NTLMAuthProvider;
pub type NTLMMessage = ntlm_message::NTLMMessage;
pub type NTLMNegotiateMessageBody = ntlm_message::NTLMNegotiateMessageBody;
pub type NTLMChallengeMessageBody = ntlm_message::NTLMChallengeMessageBody;