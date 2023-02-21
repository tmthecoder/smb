use smb_reader::protocol::body::negotiate::SMBNegotiateResponse;
use smb_reader::protocol::body::{
    Capabilities, FileTime, SMBBody, SMBDialect, SMBSessionSetupResponse, SecurityMode,
};
use smb_reader::protocol::header::{SMBCommandCode, SMBFlags, SMBSyncHeader};
use smb_reader::protocol::message::SMBMessage;
use smb_reader::util::auth::ntlm::{NTLMAuthProvider, NTLMMessage};
use smb_reader::util::auth::spnego::SPNEGOToken;
use smb_reader::util::auth::{AuthProvider, User};
use smb_reader::SMBListener;

const NTLM_ID: [u8; 10] = [0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a];
const SPNEGO_ID: [u8; 6] = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];

fn main() -> anyhow::Result<()> {
    let server = SMBListener::new("127.0.0.1:50122")?;
    let start_time = FileTime::now();
    for mut connection in server.connections() {
        let mut cloned_connection = connection.try_clone()?;
        for message in connection.messages() {
            match message.header.command {
                SMBCommandCode::LegacyNegotiate => {
                    let resp_body = SMBBody::NegotiateResponse(SMBNegotiateResponse::new(
                        SecurityMode::empty(),
                        SMBDialect::V2_X_X,
                        Capabilities::empty(),
                        100,
                        100,
                        100,
                        start_time.clone(),
                        Vec::new(),
                    ));
                    let resp_header = SMBSyncHeader::new(
                        SMBCommandCode::Negotiate,
                        SMBFlags::SERVER_TO_REDIR,
                        0,
                        0,
                        65535,
                        65535,
                        [0; 16],
                    );
                    let resp_msg = SMBMessage::new(resp_header, resp_body);
                    cloned_connection.send_message(resp_msg)?;
                }
                SMBCommandCode::Negotiate => {
                    if let SMBBody::NegotiateRequest(request) = message.body {
                        let resp_body = SMBBody::NegotiateResponse(
                            SMBNegotiateResponse::from_request(request, spnego_init_buffer(true))
                                .unwrap(),
                        );
                        let resp_header = message.header.create_response_header(0x0);
                        let resp_msg = SMBMessage::new(resp_header, resp_body);
                        cloned_connection.send_message(resp_msg)?;
                    }
                }
                SMBCommandCode::SessionSetup => {
                    if let SMBBody::SessionSetupRequest(request) = message.body {
                        let spnego_init_buffer: SPNEGOToken<NTLMAuthProvider> =
                            SPNEGOToken::parse(&request.get_buffer_copy()).unwrap().1;
                        println!("SPNEGOBUFFER: {:?}", spnego_init_buffer);
                        let helper = NTLMAuthProvider::new(
                            vec![User::new("tejas".into(), "test".into())],
                            true,
                        );
                        match spnego_init_buffer {
                            SPNEGOToken::Init(init_msg) => {
                                let ntlm_msg =
                                    NTLMMessage::parse(&init_msg.mech_token.unwrap()).unwrap().1;
                                let (status, output) = helper.accept_security_context(&ntlm_msg);
                                let resp = SMBSessionSetupResponse::from_request(
                                    request,
                                    spnego_resp_buffer(&output.as_bytes()),
                                )
                                .unwrap();
                                let resp_body = SMBBody::SessionSetupResponse(resp);
                                let resp_header = message.header.create_response_header(0);
                                let resp_msg = SMBMessage::new(resp_header, resp_body);
                                cloned_connection.send_message(resp_msg)?;
                            }
                            SPNEGOToken::Response(resp_msg) => {
                                println!("SPNEGOToken: {:?}", resp_msg);
                                let ntlm_msg =
                                    NTLMMessage::parse(&resp_msg.response_token.unwrap())
                                        .unwrap()
                                        .1;
                                println!("NTLM: {:?}", ntlm_msg);

                                let (status, output) = helper.accept_security_context(&ntlm_msg);
                                println!("input: {:?}", ntlm_msg);
                            }
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
    }
    Ok(())
}

fn spnego_init_buffer(header: bool) -> Vec<u8> {
    let oid_size = get_field_size(NTLM_ID.len()) + 1 + NTLM_ID.len();
    let field_size = get_field_size(oid_size);
    let const_len = 1 + oid_size + field_size;
    let const_field_size = get_field_size(const_len);
    let sequence_length = 1 + const_field_size + 1 + field_size + oid_size;

    // after sequence_length
    let seq_length_size = get_field_size(sequence_length);
    let construction_length = 1 + seq_length_size + sequence_length;
    let header_vec = if header {
        let size = spnego_init_buffer(false).len();
        get_header(size)
    } else {
        Vec::new()
    };

    [
        &*header_vec,
        &[160][0..],
        &*get_length(construction_length),
        &[48],
        &*get_length(sequence_length),
        &[160],
        &*get_length(const_len),
        &[48],
        &*get_length(oid_size),
        &[6],
        &*get_length(NTLM_ID.len()),
        &NTLM_ID,
    ]
    .concat()
}

fn spnego_resp_buffer(response: &Vec<u8>) -> Vec<u8> {
    let nego_status_len = 5;
    let token_field_len = get_field_size(response.len());
    let mechanism_len = get_field_size(NTLM_ID.len());

    let mechanism_construction_len = 1 + mechanism_len + NTLM_ID.len();
    let token_construction_len = 1 + token_field_len + response.len();

    let mechanism_construction_field_size = get_field_size(mechanism_construction_len);
    let token_construction_field_size = get_field_size(token_construction_len);
    let sequence_len = 1
        + token_construction_field_size
        + 1
        + token_field_len
        + response.len()
        + nego_status_len
        + 1
        + mechanism_construction_field_size
        + 1
        + mechanism_len
        + NTLM_ID.len();

    let seq_field_size = get_field_size(sequence_len);
    let construction_len = 1 + seq_field_size + sequence_len;
    println!("len {}", 1 + token_field_len + response.len());
    [
        &[161][0..],
        &*get_length(construction_len),
        &[48],
        &*get_length(sequence_len),
        &[160],
        &*get_length(3),
        &[10],
        &*get_length(1),
        &[0x01],
        &[161],
        &*get_length(1 + mechanism_len + NTLM_ID.len()),
        &[6],
        &*get_length(NTLM_ID.len()),
        &NTLM_ID,
        &[162],
        &*get_length(1 + token_field_len + response.len()),
        &[4],
        &*get_length(response.len()),
        response,
    ]
    .concat()
}

fn get_field_size(len: usize) -> usize {
    if len < 0x80 {
        return 1;
    }
    let mut adder = 1;
    let mut len = len;
    while len > 0 {
        len /= 256;
        adder += 1;
    }
    adder
}

fn get_header(size: usize) -> Vec<u8> {
    let oid_field_size = get_field_size(SPNEGO_ID.len());
    let token_len = 1 + oid_field_size + SPNEGO_ID.len() + size;
    [
        &[96][0..],
        &*get_length(token_len),
        &[6][0..],
        &*get_length(SPNEGO_ID.len()),
        &SPNEGO_ID,
    ]
    .concat()
}

fn get_length(length: usize) -> Vec<u8> {
    if length < 0x80 {
        return vec![length as u8];
    }
    let mut len = length;
    let mut len_bytes = Vec::new();
    while len > 0 {
        let byte = len % 256;
        len_bytes.push(byte as u8);
        len /= 256;
    }
    len_bytes.reverse();
    [&[(0x80 | len_bytes.len()) as u8][0..], &*len_bytes].concat()
}

