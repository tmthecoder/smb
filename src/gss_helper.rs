use std::cmp::min;
use std::os::raw::c_uint;
use std::ptr::{null, null_mut};
use libgssapi::context::{SecurityContext, ServerCtx};

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

// extern "C" {
//     pub(crate) fn gss_accept_sec_context(minor_status: *mut c_uint, context_handle: *mut *mut GSSCtxID, acceptor_cred_handle: *mut GSSCredID, input_token: *mut GSSBufferDesc, input_chan_bindings: *mut GSSChannelBindings, src_name: *mut *mut GSSName, mech_type: *mut *mut GSSOIDDesc, output_token: *mut GSSBufferDesc, ret_flags: *mut c_uint, time_rec: *mut c_uint, delegated_cred_handle: *mut *mut GSSCredID) -> c_uint;
//     pub(crate) fn gss_acquire_cred(minor_status: *mut c_uint, desired_name: *mut GSSName, time_req: c_uint, desired_mechs: *mut GSSOIDSetDesc, cred_usage: i32, output_cred_handle: *mut *mut GSSCredID, actual_mechs: *mut *mut GSSOIDSetDesc, time_rec: *mut c_uint) -> c_uint;
// }

pub(crate) fn get_resp_buffer(ctx: &mut ServerCtx, tkn: &[u8]) -> Option<Vec<u8>> {
    let buf = ctx.step(tkn).unwrap();
    println!("Comp: {}", ctx.is_complete());
    Some(buf?.to_vec())
}