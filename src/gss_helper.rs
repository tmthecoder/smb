use std::ffi::c_uint;
use std::ptr::{null, null_mut};

#[derive(Debug)]
#[repr(C)]
pub struct GSSCtxID {
    private: [u8; 0],
}

#[derive(Debug)]
#[repr(C)]
pub struct GSSCredID {
    private: [u8; 0],
}

#[derive(Debug)]
#[repr(C)]
pub struct GSSRawPtr {
    private: [u8; 0],
}

#[derive(Debug)]
#[repr(C)]
pub struct GSSName {
    private: [u8; 0],
}

#[derive(Debug)]
#[repr(C)]
pub struct GSSBufferDesc {
    length: isize,
    value: *mut u8
}

#[derive(Debug)]
#[repr(C)]
pub struct GSSChannelBindings {
    initiator_addrtype: u32,
    initiator_address: GSSBufferDesc,
    acceptor_addrtype: u32,
    acceptor_address: GSSBufferDesc,
    application_data: GSSBufferDesc
}

impl GSSChannelBindings {
    fn no_bindings() -> Self {
        Self {
            initiator_addrtype: 0,
            initiator_address: GSSBufferDesc { length: 0, value: &mut 0},
            acceptor_addrtype: 0,
            acceptor_address: GSSBufferDesc { length: 0, value: &mut 0},
            application_data: GSSBufferDesc { length: 0, value: &mut 0}
        }
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct GSSOIDDesc {
    elements: *mut u8,
    length: u32
}

#[repr(C)]
pub struct GSSOIDSetDesc {
    count: isize,
    elements: *mut GSSOIDDesc
}

extern "C" {
    pub(crate) fn gss_accept_sec_context(minor_status: *mut c_uint, context_handle: *mut *mut GSSCtxID, acceptor_cred_handle: *mut GSSCredID, input_token: *mut GSSBufferDesc, input_chan_bindings: *mut GSSChannelBindings, src_name: *mut *mut GSSName, mech_type: *mut *mut GSSOIDDesc, output_token: *mut GSSBufferDesc, ret_flags: *mut c_uint, time_rec: *mut c_uint, delegated_cred_handle: *mut *mut GSSCredID) -> c_uint;
    pub(crate) fn gss_acquire_cred(minor_status: *mut c_uint, desired_name: *mut GSSName, time_req: c_uint, desired_mechs: *mut GSSOIDSetDesc, cred_usage: i32, output_cred_handle: *mut *mut GSSCredID, actual_mechs: *mut *mut GSSOIDSetDesc, time_rec: *mut c_uint) -> c_uint;
}

pub(crate) fn send_negprot_resp() {
    let mut min_stat = 0;
    let mut handle = GSSCredID { private: [] };
    let mut name = GSSName { private: [] };
    let mut oid_desc = GSSOIDSetDesc { count: 0, elements: &mut GSSOIDDesc { elements: &mut 0, length: 0} };
    let mut acc_desc = GSSOIDSetDesc { count: 0, elements: &mut GSSOIDDesc { elements: &mut 0, length: 0} };
    unsafe {
        gss_acquire_cred(&mut min_stat, &mut name, 10000, &mut oid_desc, 0, &mut (&mut handle as *mut GSSCredID), &mut (&mut acc_desc as *mut GSSOIDSetDesc), null_mut());
    }
    println!("HANDLE: {:?} {:?}", handle, name);
    let mut input_token = GSSBufferDesc { length: 0, value: null_mut() };
    let mut output_token = GSSBufferDesc { length: 0, value: null_mut() };
    unsafe {
        gss_accept_sec_context(&mut min_stat, null_mut(), &mut handle, &mut input_token, null_mut(), null_mut(), null_mut(), &mut output_token, null_mut(), null_mut(), null_mut());
    };
    println!("RESP: {:?}", output_token);
}
//
// pub(crate) fn get_resp_buffer(ctx: PendingServerCtx, tkn: &[u8]) -> Option<(Vec<u8>, PendingServerCtx)> {
//     ctx.write_all(&(tkn.len() as u32).to_be_bytes()).unwrap();
//     println!("Len: {} Be: {:?}", tkn.len(), tkn.len().to_be_bytes());
//     ctx.write_all(tkn).unwrap();
//     let mut len_buf = [0_u8; 4];
//     ctx.read_exact(&mut len_buf).unwrap();
//     let len = u32::from_be_bytes(len_buf);
//     let mut buffer = vec![0; len as usize];
//     ctx.read_exact(&mut buffer).unwrap();
//     // println!("Comp: {}", ctx.);
//     // Some(buf?.to_vec())
// }