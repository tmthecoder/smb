use smb_reader::protocol::body::echo::SMBEchoRequest;
use smb_reader::protocol::body::SMBBody;
use smb_reader::protocol::header::SMBSyncHeader;
use smb_reader::protocol::message::{Message, SMBMessage};

#[test]
fn test_as_bytes_empty_body() {
    use smb_reader::protocol::header::command_code::SMBCommandCode;
    use smb_reader::protocol::header::flags::SMBFlags;

    let header = SMBSyncHeader::new(SMBCommandCode::Negotiate, SMBFlags::empty(), 0, 0, 0, 0, [0; 16]);
    let body = SMBBody::EchoRequest(SMBEchoRequest {});
    let message = SMBMessage::new(header, body);

    let bytes = message.as_bytes();

    assert!(!bytes.is_empty());
    assert_eq!(bytes[0..4], [0, 0, 0, 68]);  // First 4 bytes should be [0, 0, (len..)] -->
    let expected_len = u16::from_be_bytes([bytes[2], bytes[3]]);
    assert_eq!(bytes.len(), expected_len as usize + 4);  // Total length should match
}

#[test]
fn test_as_bytes_consistency() {
    use smb_reader::protocol::header::command_code::SMBCommandCode;
    use smb_reader::protocol::header::flags::SMBFlags;

    let header = SMBSyncHeader::new(SMBCommandCode::Negotiate, SMBFlags::empty(), 0, 0, 0, 0, [0; 16]);
    let body = SMBBody::EchoRequest(SMBEchoRequest {});
    let message1 = SMBMessage::new(header.clone(), body.clone());
    let message2 = SMBMessage::new(header, body);

    let bytes1 = message1.as_bytes();
    let bytes2 = message2.as_bytes();

    assert_eq!(bytes1, bytes2, "Byte representations should be identical for the same message content");
    assert!(!bytes1.is_empty(), "Byte representation should not be empty");
}

#[test]
fn test_as_bytes_serialization_deserialization() {
    use smb_reader::protocol::header::command_code::SMBCommandCode;
    use smb_reader::protocol::header::flags::SMBFlags;

    let header = SMBSyncHeader::new(SMBCommandCode::Echo, SMBFlags::empty(), 0, 0, 0, 0, [0; 16]);
    let body = SMBBody::EchoRequest(SMBEchoRequest {});
    let original_message = SMBMessage::new(header, body);

    let serialized = original_message.as_bytes();
    let (_, deserialized_message) = SMBMessage::<SMBSyncHeader, SMBBody>::parse(&serialized[4..]).unwrap();

    assert_eq!(original_message, deserialized_message);
}