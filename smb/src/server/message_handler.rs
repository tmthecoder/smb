use std::future::Future;

use smb_core::error::SMBError;
use smb_core::SMBResult;

use crate::protocol::body::cancel::SMBCancelRequest;
use crate::protocol::body::change_notify::SMBChangeNotifyRequest;
use crate::protocol::body::close::SMBCloseRequest;
use crate::protocol::body::create::SMBCreateRequest;
use crate::protocol::body::echo::SMBEchoRequest;
use crate::protocol::body::flush::SMBFlushRequest;
use crate::protocol::body::ioctl::SMBIoCtlRequest;
use crate::protocol::body::lock::SMBLockRequest;
use crate::protocol::body::logoff::SMBLogoffRequest;
use crate::protocol::body::negotiate::SMBNegotiateRequest;
use crate::protocol::body::oplock_break::SMBOplockBreakAcknowledgement;
use crate::protocol::body::query_directory::SMBQueryDirectoryRequest;
use crate::protocol::body::query_info::SMBQueryInfoRequest;
use crate::protocol::body::read::SMBReadRequest;
use crate::protocol::body::session_setup::SMBSessionSetupRequest;
use crate::protocol::body::set_info::SMBSetInfoRequest;
use crate::protocol::body::SMBBody;
use crate::protocol::body::tree_connect::SMBTreeConnectRequest;
use crate::protocol::body::tree_disconnect::SMBTreeDisconnectRequest;
use crate::protocol::body::write::SMBWriteRequest;
use crate::protocol::header::{Header, SMBSyncHeader};
use crate::protocol::message::SMBMessage;

pub type SMBMessageType = SMBMessage<SMBSyncHeader, SMBBody>;

pub struct SMBValidatedMessage<H: Header, B> {
    pub header: H,
    pub body: B,
}

pub type SMBRequestMessage<B> = SMBValidatedMessage<SMBSyncHeader, B>;

pub enum SMBHandlerState<H> {
    Finished(SMBMessageType),
    Next(Option<H>),
}

impl<H> SMBHandlerState<H> {
    pub fn get_message(self) -> SMBResult<SMBMessageType> {
        if let Self::Finished(msg) = self {
            Ok(msg)
        } else {
            Err(SMBError::server_error("Invalid handler structure"))
        }
    }
}

pub trait SMBLockedMessageHandlerBase {
    type Inner;

    fn inner(&self, message: &SMBMessageType) -> impl Future<Output=Option<Self::Inner>>;
    fn handle_message_inner(&self, message: &SMBMessageType) -> impl Future<Output=SMBResult<SMBHandlerState<Self::Inner>>> {
        async {
            match &message.body {
                SMBBody::NegotiateRequest(req) => self.handle_negotiate(&message.header, req).await,
                SMBBody::SessionSetupRequest(req) => self.handle_session_setup(&message.header, req).await,
                SMBBody::LogoffRequest(req) => self.handle_logoff(&message.header, req).await,
                SMBBody::TreeConnectRequest(req) => self.handle_tree_connect(&message.header, req).await,
                SMBBody::TreeDisconnectRequest(req) => self.handle_tree_disconnect(&message.header, req).await,
                SMBBody::CreateRequest(req) => self.handle_create(&message.header, req).await,
                SMBBody::CloseRequest(req) => self.handle_close(&message.header, req).await,
                SMBBody::FlushRequest(req) => self.handle_flush(&message.header, req).await,
                SMBBody::ReadRequest(req) => self.handle_read(&message.header, req).await,
                SMBBody::WriteRequest(req) => self.handle_write(&message.header, req).await,
                SMBBody::LockRequest(req) => self.handle_lock(&message.header, req).await,
                SMBBody::IoCtlRequest(req) => self.handle_ioctl(&message.header, req).await,
                SMBBody::CancelRequest(req) => self.handle_cancel(&message.header, req).await,
                SMBBody::EchoRequest(req) => self.handle_echo(&message.header, req).await,
                SMBBody::QueryDirectoryRequest(req) => self.handle_query_directory(&message.header, req).await,
                SMBBody::ChangeNotifyRequest(req) => self.handle_change_notify(&message.header, req).await,
                SMBBody::QueryInfoRequest(req) => self.handle_query_info(&message.header, req).await,
                SMBBody::SetInfoRequest(req) => self.handle_set_info(&message.header, req).await,
                SMBBody::OplockBreakAcknowledgement(req) => self.handle_oplock_break(&message.header, req).await,
                _ => Err(SMBError::server_error("Command not implemented")),
            }
        }
    }

    fn handle_negotiate(&self, header: &SMBSyncHeader, message: &SMBNegotiateRequest) -> impl Future<Output=SMBResult<SMBHandlerState<Self::Inner>>> {
        async { Ok(SMBHandlerState::Next(None)) }
    }

    fn handle_session_setup(&self, header: &SMBSyncHeader, message: &SMBSessionSetupRequest) -> impl Future<Output=SMBResult<SMBHandlerState<Self::Inner>>> {
        async { Ok(SMBHandlerState::Next(None)) }
    }

    fn handle_logoff(&self, header: &SMBSyncHeader, message: &SMBLogoffRequest) -> impl Future<Output=SMBResult<SMBHandlerState<Self::Inner>>> {
        async { Ok(SMBHandlerState::Next(None)) }
    }

    fn handle_tree_connect(&self, header: &SMBSyncHeader, message: &SMBTreeConnectRequest) -> impl Future<Output=SMBResult<SMBHandlerState<Self::Inner>>> {
        async { Ok(SMBHandlerState::Next(None)) }
    }

    fn handle_tree_disconnect(&self, header: &SMBSyncHeader, message: &SMBTreeDisconnectRequest) -> impl Future<Output=SMBResult<SMBHandlerState<Self::Inner>>> {
        async { Ok(SMBHandlerState::Next(None)) }
    }

    fn handle_create(&self, header: &SMBSyncHeader, message: &SMBCreateRequest) -> impl Future<Output=SMBResult<SMBHandlerState<Self::Inner>>> {
        async { Ok(SMBHandlerState::Next(None)) }
    }

    fn handle_close(&self, header: &SMBSyncHeader, message: &SMBCloseRequest) -> impl Future<Output=SMBResult<SMBHandlerState<Self::Inner>>> {
        async { Ok(SMBHandlerState::Next(None)) }
    }

    fn handle_flush(&self, header: &SMBSyncHeader, message: &SMBFlushRequest) -> impl Future<Output=SMBResult<SMBHandlerState<Self::Inner>>> {
        async { Ok(SMBHandlerState::Next(None)) }
    }

    fn handle_read(&self, header: &SMBSyncHeader, message: &SMBReadRequest) -> impl Future<Output=SMBResult<SMBHandlerState<Self::Inner>>> {
        async { Ok(SMBHandlerState::Next(None)) }
    }

    fn handle_write(&self, header: &SMBSyncHeader, message: &SMBWriteRequest) -> impl Future<Output=SMBResult<SMBHandlerState<Self::Inner>>> {
        async { Ok(SMBHandlerState::Next(None)) }
    }

    fn handle_lock(&self, header: &SMBSyncHeader, message: &SMBLockRequest) -> impl Future<Output=SMBResult<SMBHandlerState<Self::Inner>>> {
        async { Ok(SMBHandlerState::Next(None)) }
    }

    fn handle_ioctl(&self, header: &SMBSyncHeader, message: &SMBIoCtlRequest) -> impl Future<Output=SMBResult<SMBHandlerState<Self::Inner>>> {
        async { Ok(SMBHandlerState::Next(None)) }
    }

    fn handle_cancel(&self, header: &SMBSyncHeader, message: &SMBCancelRequest) -> impl Future<Output=SMBResult<SMBHandlerState<Self::Inner>>> {
        async { Ok(SMBHandlerState::Next(None)) }
    }

    fn handle_echo(&self, header: &SMBSyncHeader, message: &SMBEchoRequest) -> impl Future<Output=SMBResult<SMBHandlerState<Self::Inner>>> {
        async { Ok(SMBHandlerState::Next(None)) }
    }

    fn handle_query_directory(&self, header: &SMBSyncHeader, message: &SMBQueryDirectoryRequest) -> impl Future<Output=SMBResult<SMBHandlerState<Self::Inner>>> {
        async { Ok(SMBHandlerState::Next(None)) }
    }

    fn handle_change_notify(&self, header: &SMBSyncHeader, message: &SMBChangeNotifyRequest) -> impl Future<Output=SMBResult<SMBHandlerState<Self::Inner>>> {
        async { Ok(SMBHandlerState::Next(None)) }
    }

    fn handle_query_info(&self, header: &SMBSyncHeader, message: &SMBQueryInfoRequest) -> impl Future<Output=SMBResult<SMBHandlerState<Self::Inner>>> {
        async { Ok(SMBHandlerState::Next(None)) }
    }

    fn handle_set_info(&self, header: &SMBSyncHeader, message: &SMBSetInfoRequest) -> impl Future<Output=SMBResult<SMBHandlerState<Self::Inner>>> {
        async { Ok(SMBHandlerState::Next(None)) }
    }

    fn handle_oplock_break(&self, header: &SMBSyncHeader, message: &SMBOplockBreakAcknowledgement) -> impl Future<Output=SMBResult<SMBHandlerState<Self::Inner>>> {
        async { Ok(SMBHandlerState::Next(None)) }
    }
}

pub trait SMBLockedMessageHandler: SMBLockedMessageHandlerBase where <Self as SMBLockedMessageHandlerBase>::Inner: SMBLockedMessageHandlerBase {
    fn handle_message_full(&self, message: &SMBMessageType) -> impl Future<Output=SMBResult<SMBMessageType>>;
}

impl<H: SMBLockedMessageHandlerBase> SMBLockedMessageHandler for H where H::Inner: SMBLockedMessageHandlerBase {
    async fn handle_message_full(&self, message: &SMBMessageType) -> SMBResult<SMBMessageType> {
        println!("Got message in handler: {:?}", message);
        let state = self.handle_message_inner(message).await?;

        match state {
            SMBHandlerState::Finished(msg) => Ok(msg),
            SMBHandlerState::Next(Some(handler)) => handler
                .handle_message_inner(message)
                .await?
                .get_message(),
            SMBHandlerState::Next(None) => self.inner(message).await
                .ok_or(SMBError::server_error("Invalid handler defined"))?
                .handle_message_inner(message)
                .await?
                .get_message()
        }
    }
}