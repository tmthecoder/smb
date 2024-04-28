use std::future::Future;

use smb_core::error::SMBError;
use smb_core::SMBResult;

use crate::protocol::body::SMBBody;
use crate::protocol::header::command_code::SMBCommandCode;
use crate::protocol::header::SMBSyncHeader;
use crate::protocol::message::SMBMessage;

pub type SMBMessageType = SMBMessage<SMBSyncHeader, SMBBody>;

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
            match message.header.command {
                SMBCommandCode::Negotiate => self.handle_negotiate(message).await,
                SMBCommandCode::SessionSetup => self.handle_session_setup(message).await,
                SMBCommandCode::LogOff => self.handle_logoff(message).await,
                SMBCommandCode::TreeConnect => self.handle_tree_connect(message).await,
                SMBCommandCode::TreeDisconnect => self.handle_logoff(message).await,
                SMBCommandCode::Create => self.handle_tree_disconnect(message).await,
                SMBCommandCode::Close => self.handle_close(message).await,
                SMBCommandCode::Flush => self.handle_flush(message).await,
                SMBCommandCode::Read => self.handle_read(message).await,
                SMBCommandCode::Write => self.handle_write(message).await,
                SMBCommandCode::Lock => self.handle_lock(message).await,
                SMBCommandCode::IOCTL => self.handle_ioctl(message).await,
                SMBCommandCode::Cancel => self.handle_cancel(message).await,
                SMBCommandCode::Echo => self.handle_echo(message).await,
                SMBCommandCode::QueryDirectory => self.handle_query_directory(message).await,
                SMBCommandCode::ChangeNotify => self.handle_change_notify(message).await,
                SMBCommandCode::QueryInfo => self.handle_query_info(message).await,
                SMBCommandCode::SetInfo => self.handle_set_info(message).await,
                SMBCommandCode::OplockBreak => self.handle_oplock_break(message).await,
                _ => Err(SMBError::server_error("Command not implemented")),
            }
        }
    }

    fn handle_negotiate(&self, message: &SMBMessageType) -> impl Future<Output=SMBResult<SMBHandlerState<Self::Inner>>> {
        async { Ok(SMBHandlerState::Next(None)) }
    }

    fn handle_session_setup(&self, message: &SMBMessageType) -> impl Future<Output=SMBResult<SMBHandlerState<Self::Inner>>> {
        async { Ok(SMBHandlerState::Next(None)) }
    }

    fn handle_logoff(&self, message: &SMBMessageType) -> impl Future<Output=SMBResult<SMBHandlerState<Self::Inner>>> {
        async { Ok(SMBHandlerState::Next(None)) }
    }

    fn handle_tree_connect(&self, message: &SMBMessageType) -> impl Future<Output=SMBResult<SMBHandlerState<Self::Inner>>> {
        async { Ok(SMBHandlerState::Next(None)) }
    }

    fn handle_tree_disconnect(&self, message: &SMBMessageType) -> impl Future<Output=SMBResult<SMBHandlerState<Self::Inner>>> {
        async { Ok(SMBHandlerState::Next(None)) }
    }

    fn handle_create(&self, message: &SMBMessageType) -> impl Future<Output=SMBResult<SMBHandlerState<Self::Inner>>> {
        async { Ok(SMBHandlerState::Next(None)) }
    }

    fn handle_close(&self, message: &SMBMessageType) -> impl Future<Output=SMBResult<SMBHandlerState<Self::Inner>>> {
        async { Ok(SMBHandlerState::Next(None)) }
    }

    fn handle_flush(&self, message: &SMBMessageType) -> impl Future<Output=SMBResult<SMBHandlerState<Self::Inner>>> {
        async { Ok(SMBHandlerState::Next(None)) }
    }

    fn handle_read(&self, message: &SMBMessageType) -> impl Future<Output=SMBResult<SMBHandlerState<Self::Inner>>> {
        async { Ok(SMBHandlerState::Next(None)) }
    }

    fn handle_write(&self, message: &SMBMessageType) -> impl Future<Output=SMBResult<SMBHandlerState<Self::Inner>>> {
        async { Ok(SMBHandlerState::Next(None)) }
    }

    fn handle_lock(&self, message: &SMBMessageType) -> impl Future<Output=SMBResult<SMBHandlerState<Self::Inner>>> {
        async { Ok(SMBHandlerState::Next(None)) }
    }

    fn handle_ioctl(&self, message: &SMBMessageType) -> impl Future<Output=SMBResult<SMBHandlerState<Self::Inner>>> {
        async { Ok(SMBHandlerState::Next(None)) }
    }

    fn handle_cancel(&self, message: &SMBMessageType) -> impl Future<Output=SMBResult<SMBHandlerState<Self::Inner>>> {
        async { Ok(SMBHandlerState::Next(None)) }
    }

    fn handle_echo(&self, message: &SMBMessageType) -> impl Future<Output=SMBResult<SMBHandlerState<Self::Inner>>> {
        async { Ok(SMBHandlerState::Next(None)) }
    }

    fn handle_query_directory(&self, message: &SMBMessageType) -> impl Future<Output=SMBResult<SMBHandlerState<Self::Inner>>> {
        async { Ok(SMBHandlerState::Next(None)) }
    }

    fn handle_change_notify(&self, message: &SMBMessageType) -> impl Future<Output=SMBResult<SMBHandlerState<Self::Inner>>> {
        async { Ok(SMBHandlerState::Next(None)) }
    }

    fn handle_query_info(&self, message: &SMBMessageType) -> impl Future<Output=SMBResult<SMBHandlerState<Self::Inner>>> {
        async { Ok(SMBHandlerState::Next(None)) }
    }

    fn handle_set_info(&self, message: &SMBMessageType) -> impl Future<Output=SMBResult<SMBHandlerState<Self::Inner>>> {
        async { Ok(SMBHandlerState::Next(None)) }
    }

    fn handle_oplock_break(&self, message: &SMBMessageType) -> impl Future<Output=SMBResult<SMBHandlerState<Self::Inner>>> {
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