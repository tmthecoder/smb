use std::fmt::Debug;
use std::ops::Deref;
use std::sync::{Arc, Weak};

use tokio::sync::RwLock;

#[cfg(feature = "logging")]
use smb_core::SMBByteSize;
use smb_core::error::SMBError;
use smb_core::logging::{debug, trace, warn};
use smb_core::nt_status::NTStatus;
use smb_core::{SMBResult, SMBToBytes};

use crate::protocol::body::SMBBody;
use crate::protocol::body::close::{SMBCloseRequest, SMBCloseResponse};
use crate::protocol::body::create::file_attributes::SMBFileAttributes;
use crate::protocol::body::create::file_id::SMBFileId;
use crate::protocol::body::create::{SMBCreateRequest, SMBCreateResponse};
use crate::protocol::body::file_info::{
    FileAccessFlags, FileAccessInformation, FileAlignmentInformation, FileAlignmentRequirement,
    FileAllInformation, FileBasicInformation, FileEaInformation, FileFsSizeInformation,
    FileIdBothDirectoryInformation, FileInternalInformation, FileModeFlags, FileModeInformation,
    FileNameInformation, FileNetworkOpenInformation, FilePositionInformation,
    FileStandardInformation, chain_directory_entries,
};
use crate::protocol::body::filetime::FileTime;
use crate::protocol::body::query_directory::flags::SMBQueryDirectoryFlags;
use crate::protocol::body::query_directory::information_class::SMBInformationClass;
use crate::protocol::body::query_directory::{SMBQueryDirectoryRequest, SMBQueryDirectoryResponse};
use crate::protocol::body::query_info::info_type::SMBInfoType;
use crate::protocol::body::query_info::{SMBQueryInfoRequest, SMBQueryInfoResponse};
use crate::protocol::body::read::{SMBReadRequest, SMBReadResponse};
use crate::protocol::body::tree_connect::access_mask::SMBAccessMask;
use crate::protocol::body::write::{SMBWriteRequest, SMBWriteResponse};
use crate::protocol::header::SMBSyncHeader;
use crate::protocol::message::SMBMessage;
use crate::server::Server;
use crate::server::message_handler::{
    SMBHandlerState, SMBLockedMessageHandler, SMBLockedMessageHandlerBase, SMBMessageType,
};
use crate::server::open::{Open, SMBOpen};
use crate::server::safe_locked_getter::SafeLockedGetter;
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
    pub fn init(
        tree_id: u32,
        session: Weak<RwLock<S::Session>>,
        share: Arc<S::Share>,
        maximal_access: SMBAccessMask,
    ) -> SMBTreeConnect<S> {
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
        self.session
            .upgrade()
            .ok_or(SMBError::server_error("No Session Found"))
    }

    async fn find_open(&self, file_id: &SMBFileId) -> SMBResult<Arc<RwLock<S::Open>>> {
        let session = self.get_session()?;
        let session_rd = session.read().await;
        let open = session_rd
            .open_table()
            .get(&file_id.volatile())
            .cloned()
            .ok_or(SMBError::response_error(NTStatus::FileClosed))?;
        // MS-SMB2 §3.3.5.10/12/20: verify Open.DurableFileId == FileId.Persistent
        let open_rd = open.read().await;
        if open_rd.file_id().persistent() != file_id.persistent() {
            return Err(SMBError::response_error(NTStatus::FileClosed));
        }
        drop(open_rd);
        Ok(open)
    }

    fn build_basic_info(open: &S::Open) -> SMBResult<FileBasicInformation> {
        let metadata = open.file_metadata()?;
        Ok(FileBasicInformation::new(
            metadata.creation_time().clone(),
            metadata.last_access_time().clone(),
            metadata.last_write_time().clone(),
            metadata.last_modification_time().clone(),
            open.file_attributes(),
        ))
    }

    fn build_standard_info(open: &S::Open) -> SMBResult<FileStandardInformation> {
        let metadata = open.file_metadata()?;
        let is_dir = open
            .file_attributes()
            .contains(SMBFileAttributes::DIRECTORY);
        Ok(FileStandardInformation::new(
            metadata.allocated_size(),
            metadata.actual_size(),
            1,
            false,
            is_dir,
        ))
    }

    fn build_network_open_info(open: &S::Open) -> SMBResult<FileNetworkOpenInformation> {
        let metadata = open.file_metadata()?;
        Ok(FileNetworkOpenInformation::new(
            metadata.creation_time().clone(),
            metadata.last_access_time().clone(),
            metadata.last_write_time().clone(),
            metadata.last_modification_time().clone(),
            metadata.allocated_size(),
            metadata.actual_size(),
            open.file_attributes(),
        ))
    }

    fn build_all_info(open: &S::Open) -> SMBResult<FileAllInformation> {
        Ok(FileAllInformation::new(
            Self::build_basic_info(open)?,
            Self::build_standard_info(open)?,
            FileInternalInformation::new(0),
            FileEaInformation::new(0),
            FileAccessInformation::new(FileAccessFlags::from_bits_truncate(0x001f01ff)),
            FilePositionInformation::new(0),
            FileModeInformation::new(FileModeFlags::empty()),
            FileAlignmentInformation::new(FileAlignmentRequirement::Byte),
            FileNameInformation::from_name(open.file_name().into()),
        ))
    }
}

impl<S: Server> SMBLockedMessageHandlerBase for Arc<SMBTreeConnect<S>> {
    type Inner = Arc<SMBOpen<S>>;

    async fn inner(&self, _message: &SMBMessageType) -> Option<Self::Inner> {
        None
    }

    async fn handle_create(
        &mut self,
        header: &SMBSyncHeader,
        message: &SMBCreateRequest,
    ) -> SMBResult<SMBHandlerState<Self::Inner>> {
        let (path, disposition, directory) = message.validate(self.share.deref())?;
        let handle = self.share.handle_create(path, disposition, directory)?;
        let open_raw = Open::init(handle, message);
        let open = Arc::new(RwLock::new(open_raw));
        let session = self.get_session()?;
        // Register with server first (outermost), then session (inner)
        let server = session.upper().await?.upper().await?;
        {
            server.write().await.add_open(open.clone()).await;
        }
        session.write().await.add_open(open.clone()).await;
        // Build response AFTER registration so file_id reflects assigned IDs
        let (response, file_id) = {
            let open_rd = open.read().await;
            let resp = SMBBody::CreateResponse(SMBCreateResponse::for_open::<S>(&*open_rd)?);
            (resp, open_rd.file_id())
        };
        session.write().await.set_previous_file_id(file_id);
        debug!("tree connect create handled");
        let header = header.create_response_header(0, header.session_id, header.tree_id);
        trace!(
            response_size = response.smb_byte_size(),
            "create response built"
        );
        Ok(SMBHandlerState::Finished(SMBMessage::new(header, response)))
    }

    async fn handle_close(
        &mut self,
        header: &SMBSyncHeader,
        message: &SMBCloseRequest,
    ) -> SMBResult<SMBHandlerState<Self::Inner>> {
        debug!(file_id = ?message.file_id(), "handling close request");

        // Phase 1: Validate and read open data via shared find_open logic
        let open = self.find_open(message.file_id()).await?;
        let (response, file_id) = {
            let open_rd = open.read().await;
            let response = if message
                .flags()
                .contains(crate::protocol::body::close::flags::SMBCloseFlags::POSTQUERY_ATTRIB)
            {
                let metadata = open_rd.file_metadata()?;
                SMBCloseResponse::from_metadata(&metadata, open_rd.file_attributes())
            } else {
                SMBCloseResponse::empty()
            };
            (response, open_rd.file_id())
        };

        // Phase 2: Cleanup — acquire locks outer to inner (server_wr, then session_wr)
        let session = self.get_session()?;
        let global_id: u32 = file_id
            .persistent()
            .try_into()
            .expect("global_id fits in u32");
        // Server write first (outermost)
        if let Ok(conn) = session.upper().await {
            if let Ok(server) = conn.upper().await {
                server.write().await.remove_open(global_id);
            } else {
                warn!(file_id = ?file_id, "failed to acquire server lock during close; global open table entry leaked");
            }
        } else {
            warn!(file_id = ?file_id, "failed to acquire connection lock during close; global open table entry leaked");
        }
        // Session write second (inner relative to server)
        {
            let mut session_wr = session.write().await;
            session_wr.open_table_mut().remove(&file_id.volatile());
        }

        debug!(file_id = ?file_id, "close completed");
        let header = header.create_response_header(0, header.session_id, header.tree_id);
        Ok(SMBHandlerState::Finished(SMBMessage::new(
            header,
            SMBBody::CloseResponse(response),
        )))
    }

    async fn handle_read(
        &mut self,
        header: &SMBSyncHeader,
        message: &SMBReadRequest,
    ) -> SMBResult<SMBHandlerState<Self::Inner>> {
        debug!(file_id = ?message.file_id(), offset = message.read_offset(), length = message.read_length(), "handling read request");
        let open = self.find_open(message.file_id()).await?;
        let mut open_wr = open.write().await;
        let data = open_wr.read_data(message.read_offset(), message.read_length())?;
        drop(open_wr);

        // MS-SMB2 §3.3.5.12: if read returns 0 bytes at/past EOF, fail with STATUS_END_OF_FILE
        if data.is_empty() && message.read_length() > 0 {
            return Err(SMBError::response_error(NTStatus::EndOfFile));
        }

        if data.len() < message.minimum_count() as usize {
            return Err(SMBError::response_error(NTStatus::EndOfFile));
        }

        debug!(bytes_read = data.len(), "read completed");
        trace!(data_len = data.len(), "read response data");
        let response = SMBReadResponse::new(data, 0);
        let header = header.create_response_header(0, header.session_id, header.tree_id);
        Ok(SMBHandlerState::Finished(SMBMessage::new(
            header,
            SMBBody::ReadResponse(response),
        )))
    }

    async fn handle_write(
        &mut self,
        header: &SMBSyncHeader,
        message: &SMBWriteRequest,
    ) -> SMBResult<SMBHandlerState<Self::Inner>> {
        debug!(file_id = ?message.file_id(), offset = message.write_offset(), length = message.write_length(), "handling write request");
        let open = self.find_open(message.file_id()).await?;
        let mut open_wr = open.write().await;
        let bytes_written = open_wr.write_data(message.write_offset(), message.data_to_write())?;
        drop(open_wr);

        debug!(bytes_written, "write completed");
        let response = SMBWriteResponse::new(bytes_written);
        let header = header.create_response_header(0, header.session_id, header.tree_id);
        Ok(SMBHandlerState::Finished(SMBMessage::new(
            header,
            SMBBody::WriteResponse(response),
        )))
    }

    async fn handle_query_directory(
        &mut self,
        header: &SMBSyncHeader,
        message: &SMBQueryDirectoryRequest,
    ) -> SMBResult<SMBHandlerState<Self::Inner>> {
        debug!(
            file_id = ?message.file_id(),
            class = ?message.information_class(),
            pattern = message.search_pattern(),
            "handling query_directory request"
        );
        let open = self.find_open(message.file_id()).await?;
        let mut open_wr = open.write().await;

        // MS-SMB2 §3.3.5.18: RESTART_SCANS and REOPEN both restart the
        // enumeration from the beginning with the supplied pattern
        let restart = message
            .flags()
            .intersects(SMBQueryDirectoryFlags::RESTART_SCANS | SMBQueryDirectoryFlags::REOPEN);
        let mut remaining = open_wr.query_directory(message.search_pattern(), restart)?;
        if remaining.is_empty() {
            // Enumeration previously started and fully drained
            return Err(SMBError::response_error(NTStatus::NoMoreFiles));
        }
        if message
            .flags()
            .contains(SMBQueryDirectoryFlags::RETURN_SINGLE_ENTRY)
        {
            remaining.truncate(1);
        }

        let max_output = message.max_output_len() as usize;
        let (buffer, consumed) = match message.information_class() {
            SMBInformationClass::FileIdBothDirectoryInformation => {
                let entries = remaining
                    .iter()
                    .map(|entry| {
                        let metadata = entry.metadata();
                        FileIdBothDirectoryInformation::new(
                            metadata.creation_time().clone(),
                            metadata.last_access_time().clone(),
                            metadata.last_write_time().clone(),
                            metadata.last_modification_time().clone(),
                            metadata.actual_size(),
                            metadata.allocated_size(),
                            entry.attributes(),
                            entry.file_id(),
                            entry.name().into(),
                        )
                    })
                    .collect();
                chain_directory_entries(entries, max_output)
            }
            _ => {
                debug!(class = ?message.information_class(), "unsupported directory information class");
                return Err(SMBError::response_error(NTStatus::InvalidInfoClass));
            }
        };

        if consumed == 0 {
            // Not even a single entry fits in the client's output buffer
            return Err(SMBError::response_error(NTStatus::InfoLengthMismatch));
        }
        open_wr.consume_directory_entries(consumed);
        drop(open_wr);

        debug!(
            entries = consumed,
            buffer_len = buffer.len(),
            "query_directory completed"
        );
        let response = SMBQueryDirectoryResponse::new(buffer);
        let header = header.create_response_header(0, header.session_id, header.tree_id);
        Ok(SMBHandlerState::Finished(SMBMessage::new(
            header,
            SMBBody::QueryDirectoryResponse(response),
        )))
    }

    async fn handle_query_info(
        &mut self,
        header: &SMBSyncHeader,
        message: &SMBQueryInfoRequest,
    ) -> SMBResult<SMBHandlerState<Self::Inner>> {
        debug!(file_id = ?message.file_id(), info_type = ?message.info_type(), class = message.file_info_class(), "handling query_info request");
        let open = self.find_open(message.file_id()).await?;
        let open_rd = open.read().await;

        let mut data = match message.info_type() {
            SMBInfoType::File => {
                // MS-FSCC file information classes
                match message.file_info_class() {
                    4 => SMBTreeConnect::<S>::build_basic_info(&*open_rd)?.smb_to_bytes(),
                    5 => SMBTreeConnect::<S>::build_standard_info(&*open_rd)?.smb_to_bytes(),
                    18 => SMBTreeConnect::<S>::build_all_info(&*open_rd)?.smb_to_bytes(),
                    34 => SMBTreeConnect::<S>::build_network_open_info(&*open_rd)?.smb_to_bytes(),
                    _ => {
                        debug!(
                            class = message.file_info_class(),
                            "unsupported file info class"
                        );
                        return Err(SMBError::response_error(NTStatus::InvalidInfoClass));
                    }
                }
            }
            SMBInfoType::Filesystem => {
                // MS-FSCC filesystem information classes
                match message.file_info_class() {
                    // FileFsSizeInformation (MS-FSCC 2.5.8). Reported as a
                    // nominal 4 KiB-cluster volume until real filesystem
                    // statistics are plumbed through the share layer.
                    3 => FileFsSizeInformation::new(1 << 28, 1 << 27, 8, 512).smb_to_bytes(),
                    _ => {
                        debug!(
                            class = message.file_info_class(),
                            "unsupported filesystem info class"
                        );
                        return Err(SMBError::response_error(NTStatus::InvalidInfoClass));
                    }
                }
            }
            _ => {
                debug!(info_type = ?message.info_type(), "unsupported info type");
                return Err(SMBError::response_error(NTStatus::InvalidInfoClass));
            }
        };

        // MS-SMB2 §3.3.5.20.1: enforce OutputBufferLength — truncate and
        // return STATUS_BUFFER_OVERFLOW for variable-length info classes
        let max_output = message.output_buffer_length() as usize;
        if max_output > 0 && data.len() > max_output {
            debug!(
                data_len = data.len(),
                max_output, "truncating response to output_buffer_length"
            );
            data.truncate(max_output);
            let response = SMBQueryInfoResponse::new(data);
            let header = header.create_response_header(
                NTStatus::BufferOverflow as u32,
                header.session_id,
                header.tree_id,
            );
            return Ok(SMBHandlerState::Finished(SMBMessage::new(
                header,
                SMBBody::QueryInfoResponse(response),
            )));
        }

        debug!(data_len = data.len(), "query_info completed");
        let response = SMBQueryInfoResponse::new(data);
        let header = header.create_response_header(0, header.session_id, header.tree_id);
        Ok(SMBHandlerState::Finished(SMBMessage::new(
            header,
            SMBBody::QueryInfoResponse(response),
        )))
    }
}

impl<S: Server> SMBLockedMessageHandler for Arc<SMBTreeConnect<S>> {}
