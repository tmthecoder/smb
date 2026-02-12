use std::fmt::Debug;
use std::ops::Deref;
use std::sync::{Arc, Weak};

use tokio::sync::RwLock;

use smb_core::{SMBByteSize, SMBResult, SMBToBytes};
use smb_core::error::SMBError;
use smb_core::logging::{debug, trace};
use smb_core::nt_status::NTStatus;

use crate::protocol::body::close::{SMBCloseRequest, SMBCloseResponse};
use crate::protocol::body::create::{SMBCreateRequest, SMBCreateResponse};
use crate::protocol::body::create::file_attributes::SMBFileAttributes;
use crate::protocol::body::create::file_id::SMBFileId;
use crate::protocol::body::file_info::{
    FileBasicInformation, FileStandardInformation, FileNetworkOpenInformation,
    FileAllInformation, FileInternalInformation, FileEaInformation,
    FileAccessInformation, FilePositionInformation, FileModeInformation,
    FileAlignmentInformation, FileNameInformation,
};
use crate::protocol::body::filetime::FileTime;
use crate::protocol::body::query_info::{SMBQueryInfoRequest, SMBQueryInfoResponse};
use crate::protocol::body::query_info::info_type::SMBInfoType;
use crate::protocol::body::read::{SMBReadRequest, SMBReadResponse};
use crate::protocol::body::SMBBody;
use crate::protocol::body::tree_connect::access_mask::SMBAccessMask;
use crate::protocol::header::SMBSyncHeader;
use crate::protocol::message::SMBMessage;
use crate::server::message_handler::{SMBHandlerState, SMBLockedMessageHandler, SMBLockedMessageHandlerBase, SMBMessageType};
use crate::server::open::{Open, SMBOpen};
use crate::server::safe_locked_getter::SafeLockedGetter;
use crate::server::Server;
use crate::server::session::Session;
use crate::server::share::SharedResource;

#[derive(Debug)]
pub struct SMBTreeConnect<S: Server> {
    tree_id: u32,
    session: Weak<RwLock<S::Session>>,
    share: Arc<S::Share>,
    open_count: u64,
    // tree_global_id: u64,
    creation_time: FileTime,
    maximal_access: SMBAccessMask,
    remoted_identity_security_context: Vec<u8>, // TODO
}

impl<S: Server> SMBTreeConnect<S> {
    pub fn init(tree_id: u32, session: Weak<RwLock<S::Session>>, share: Arc<S::Share>, maximal_access: SMBAccessMask) -> SMBTreeConnect<S> {
        Self {
            tree_id,
            session,
            share,
            open_count: 0,
            creation_time: FileTime::now(),
            maximal_access,
            remoted_identity_security_context: vec![],
        }
    }
}

impl<S: Server> SMBTreeConnect<S> {
    fn get_session(&self) -> SMBResult<Arc<RwLock<S::Session>>> {
        self.session.upgrade()
            .ok_or(SMBError::server_error("No Session Found"))
    }

    async fn find_open(&self, file_id: &SMBFileId) -> SMBResult<Arc<RwLock<S::Open>>> {
        let session = self.get_session()?;
        let session_rd = session.read().await;
        session_rd.open_table()
            .get(&file_id.volatile)
            .cloned()
            .ok_or(SMBError::response_error(NTStatus::FileClosed))
    }

    fn build_basic_info(open: &S::Open) -> SMBResult<FileBasicInformation> {
        let metadata = open.file_metadata()?;
        Ok(FileBasicInformation {
            creation_time: metadata.creation_time,
            last_access_time: metadata.last_access_time,
            last_write_time: metadata.last_write_time,
            change_time: metadata.last_modification_time,
            file_attributes: open.file_attributes(),
            reserved: 0,
        })
    }

    fn build_standard_info(open: &S::Open) -> SMBResult<FileStandardInformation> {
        let metadata = open.file_metadata()?;
        let is_dir = open.file_attributes().contains(SMBFileAttributes::DIRECTORY);
        Ok(FileStandardInformation {
            allocation_size: metadata.allocated_size,
            end_of_file: metadata.actual_size,
            number_of_links: 1,
            delete_pending: 0,
            directory: if is_dir { 1 } else { 0 },
            reserved: 0,
        })
    }

    fn build_network_open_info(open: &S::Open) -> SMBResult<FileNetworkOpenInformation> {
        let metadata = open.file_metadata()?;
        Ok(FileNetworkOpenInformation {
            creation_time: metadata.creation_time,
            last_access_time: metadata.last_access_time,
            last_write_time: metadata.last_write_time,
            change_time: metadata.last_modification_time,
            allocation_size: metadata.allocated_size,
            end_of_file: metadata.actual_size,
            file_attributes: open.file_attributes(),
            reserved: 0,
        })
    }

    fn build_all_info(open: &S::Open) -> SMBResult<FileAllInformation> {
        let name = open.file_name();
        let name_byte_len = (name.encode_utf16().count() * 2) as u32;
        Ok(FileAllInformation {
            basic: Self::build_basic_info(open)?,
            standard: Self::build_standard_info(open)?,
            internal: FileInternalInformation { index_number: 0 },
            ea: FileEaInformation { ea_size: 0 },
            access: FileAccessInformation { access_flags: 0x001f01ff },
            position: FilePositionInformation { current_byte_offset: 0 },
            mode: FileModeInformation { mode: 0 },
            alignment: FileAlignmentInformation { alignment_requirement: 0 },
            name: FileNameInformation {
                file_name_length: name_byte_len,
                file_name: name.into(),
            },
        })
    }
}

impl<S: Server> SMBLockedMessageHandlerBase for Arc<SMBTreeConnect<S>> {
    type Inner = Arc<SMBOpen<S>>;

    async fn inner(&self, _message: &SMBMessageType) -> Option<Self::Inner> {
        None
    }

    async fn handle_create(&mut self, header: &SMBSyncHeader, message: &SMBCreateRequest) -> SMBResult<SMBHandlerState<Self::Inner>> {
        let (path, disposition, directory) = message.validate(self.share.deref())?;
        let handle = self.share.handle_create(path, disposition, directory)?;
        let open_raw = Open::init(handle, message);
        let response = SMBBody::CreateResponse(SMBCreateResponse::for_open::<S>(&open_raw)?);
        let open = Arc::new(RwLock::new(open_raw));
        let session = self.get_session()?;
        // Register with server first (outermost), then session (inner)
        let server = session.upper().await?
            .upper().await?;
        {
            server.write().await.add_open(open.clone()).await;
        }
        session.write().await.add_open(open.clone()).await;
        {
            let file_id = open.read().await.file_id();
            session.write().await.set_previous_file_id(file_id);
        }
        debug!("tree connect create handled");
        let header = header.create_response_header(header.channel_sequence, header.session_id, header.tree_id);
        trace!(response_size = response.smb_byte_size(), "create response built");
        Ok(SMBHandlerState::Finished(SMBMessage::new(header, response)))
    }

    async fn handle_close(&mut self, header: &SMBSyncHeader, message: &SMBCloseRequest) -> SMBResult<SMBHandlerState<Self::Inner>> {
        debug!(file_id = ?message.file_id(), "handling close request");

        // Phase 1: Read open data (session_rd → open_rd, outer before inner)
        let session = self.get_session()?;
        let open = {
            let session_rd = session.read().await;
            session_rd.open_table()
                .get(&message.file_id().volatile)
                .cloned()
                .ok_or(SMBError::response_error(NTStatus::FileClosed))?
        };
        let (response, file_id) = {
            let open_rd = open.read().await;
            let response = if message.flags().contains(crate::protocol::body::close::flags::SMBCloseFlags::POSTQUERY_ATTRIB) {
                let metadata = open_rd.file_metadata()?;
                SMBCloseResponse::from_metadata(&metadata, open_rd.file_attributes())
            } else {
                SMBCloseResponse::empty()
            };
            (response, open_rd.file_id())
        };

        // Phase 2: Cleanup — acquire locks outer to inner (server_wr, then session_wr)
        // Server write first (outermost)
        if let Ok(conn) = session.upper().await {
            if let Ok(server) = conn.upper().await {
                server.write().await.remove_open(file_id.volatile as u32);
            }
        }
        // Session write second (inner relative to server)
        {
            let mut session_wr = session.write().await;
            session_wr.open_table_mut().remove(&file_id.volatile);
        }

        debug!(file_id = ?file_id, "close completed");
        let header = header.create_response_header(0, header.session_id, header.tree_id);
        Ok(SMBHandlerState::Finished(SMBMessage::new(header, SMBBody::CloseResponse(response))))
    }

    async fn handle_read(&mut self, header: &SMBSyncHeader, message: &SMBReadRequest) -> SMBResult<SMBHandlerState<Self::Inner>> {
        debug!(file_id = ?message.file_id(), offset = message.read_offset(), length = message.read_length(), "handling read request");
        let open = self.find_open(message.file_id()).await?;
        let mut open_wr = open.write().await;
        let data = open_wr.read_data(message.read_offset(), message.read_length())?;
        drop(open_wr);

        if data.len() < message.minimum_count() as usize {
            return Err(SMBError::response_error(NTStatus::EndOfFile));
        }

        debug!(bytes_read = data.len(), "read completed");
        trace!(data_len = data.len(), "read response data");
        let response = SMBReadResponse::new(data, 0);
        let header = header.create_response_header(0, header.session_id, header.tree_id);
        Ok(SMBHandlerState::Finished(SMBMessage::new(header, SMBBody::ReadResponse(response))))
    }

    async fn handle_query_info(&mut self, header: &SMBSyncHeader, message: &SMBQueryInfoRequest) -> SMBResult<SMBHandlerState<Self::Inner>> {
        debug!(file_id = ?message.file_id(), info_type = ?message.info_type(), class = message.file_info_class(), "handling query_info request");
        let open = self.find_open(message.file_id()).await?;
        let open_rd = open.read().await;

        let data = match message.info_type() {
            SMBInfoType::File => {
                // MS-FSCC file information classes
                match message.file_info_class() {
                    4 => SMBTreeConnect::<S>::build_basic_info(&*open_rd)?.smb_to_bytes(),
                    5 => SMBTreeConnect::<S>::build_standard_info(&*open_rd)?.smb_to_bytes(),
                    18 => SMBTreeConnect::<S>::build_all_info(&*open_rd)?.to_bytes(),
                    34 => SMBTreeConnect::<S>::build_network_open_info(&*open_rd)?.smb_to_bytes(),
                    _ => {
                        debug!(class = message.file_info_class(), "unsupported file info class");
                        return Err(SMBError::response_error(NTStatus::InvalidInfoClass));
                    }
                }
            }
            _ => {
                debug!(info_type = ?message.info_type(), "unsupported info type");
                return Err(SMBError::response_error(NTStatus::InvalidInfoClass));
            }
        };

        debug!(data_len = data.len(), "query_info completed");
        let response = SMBQueryInfoResponse::new(data);
        let header = header.create_response_header(0, header.session_id, header.tree_id);
        Ok(SMBHandlerState::Finished(SMBMessage::new(header, SMBBody::QueryInfoResponse(response))))
    }
}

impl<S: Server> SMBLockedMessageHandler for Arc<SMBTreeConnect<S>> {}