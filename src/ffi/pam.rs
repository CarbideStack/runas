// Copyright (c) 2024 Daniel Bergløv
// 
// Permission is hereby granted, free of charge, to any person obtaining a 
// copy of this software and associated documentation files (the "Software"), 
// to deal in the Software without restriction, including without limitation 
// the rights to use, copy, modify, merge, publish, distribute, sublicense, 
// and/or sell copies of the Software, and to permit persons to whom the 
// Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in 
// all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER 
// DEALINGS IN THE SOFTWARE. 

/**
 * PAM (Pluggable Authentication Module) bindings and wrappers for `runas`.
 *
 * This module implements minimal and memory-safe Rust bindings around
 * the PAM (Pluggable Authentication Module) C API. 
 * It allows `runas` to perform password-based authentication and account validation
 * using system PAM policies, without directly linking against or maintaining its own
 * C glue code elsewhere.
 *
 * All `unsafe` FFI operations are fully encapsulated inside this file.
 * The public interface is designed to be safe for external use, provided
 * it is used as intended. Rust’s safety guarantees cannot extend into the
 * C library, but every call is validated and checked at the boundary.
 */

use crate::shared::*;
use std::cell::Cell;
use zeroize::Zeroize;
use std::ffi::CStr;

use std::panic::{
    AssertUnwindSafe, 
    catch_unwind
};

use crate::{
    unwrap,
    cstring,
    errx
};
    
use std::{
    mem, 
    ptr,
    slice
};
    
use nix::libc::{
    c_char,
    c_int, 
    c_void, 
    size_t, 
    free, 
    calloc, 
    strdup
};

// -------------------------
// Raw C FFI declarations
// -------------------------
// The `c_ffi` module exposes unmodified libc-compatible bindings for libpam.
// These are kept private to isolate `unsafe` usage and reduce public API surface.

mod c_ffi {    

    use nix::libc::{
        c_int, 
        c_char, 
        c_void
    };
    
    use super::{
        pam_conv,
        pam_handle_t
    };

    unsafe extern "C" {
        pub fn pam_start(service_name: *const c_char, user: *const c_char, 
                            pam_conversation: *const pam_conv, pamh: *mut *mut super::pam_handle_t) -> c_int;
                            
        pub fn pam_authenticate(pamh: *mut pam_handle_t, flags: c_int) -> c_int;
        pub fn pam_chauthtok(pamh: *mut pam_handle_t, flags: c_int) -> c_int;
        pub fn pam_acct_mgmt(pamh: *mut pam_handle_t, flags: c_int) -> c_int;
        pub fn pam_end(pamh: *mut pam_handle_t, pam_status: c_int) -> c_int;
        pub fn pam_getenvlist(pamh: *mut pam_handle_t) -> *mut *mut c_char;
        pub fn pam_setcred(pamh: *mut pam_handle_t, flags: c_int) -> c_int;
        pub fn pam_open_session(pamh: *mut pam_handle_t, flags: c_int) -> c_int;
        pub fn pam_close_session(pamh: *mut pam_handle_t, flags: c_int) -> c_int;
        pub fn pam_set_item(pamh: *mut pam_handle_t, item_type: c_int, item: *const c_void) -> c_int;
    }
}

// Internal wrapper to apply attributes to the bindgen output
#[allow(
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case,
    dead_code,
    unused
)]
mod bindings {
    include!("../pam_bindings.rs");
}

// Re-export everything at this level
pub use bindings::*;

/**
 * Defines the message types emitted during PAM conversation callbacks.
 */
#[allow(non_camel_case_types)]
#[derive(PartialEq)]
pub enum CONV {
    ECHO_ON,
    ECHO_OFF,
    MSG,
    ERROR
}

/**
 * High-level conversation interface for PAM authentication.
 *
 * Implementations of this trait receive messages and prompts
 * during authentication and respond accordingly.
 */
pub trait PamConv {
    fn prompt(&mut self, msg: &str, style: CONV) -> Result<String, NULL>;
    fn msg(&mut self, msg: &str, style: CONV);
}

// -------------------------
// Conversation bridge
// -------------------------

/**
 * 
 */
struct PamResponses {
    ptr: *mut pam_response,
    count: usize,
}

impl PamResponses {
    /**
     * 
     */
    fn new(count: usize) -> Option<Self> {
        let ptr = unsafe {
            calloc(count as size_t, mem::size_of::<pam_response>() as size_t) as *mut pam_response
        };

        if ptr.is_null() {
            None
        } else {
            Some(Self { ptr, count })
        }
    }

    /**
     * 
     */
    unsafe fn get_ptr(&mut self, index: usize) -> &mut pam_response {
        unsafe { 
            &mut *self.ptr.add(index) 
        }
    }

    /**
     * 
     */
    unsafe fn transfer_to(mut self, output: *mut *mut pam_response) {
        unsafe {
            *output = self.ptr;
        }
        self.ptr = ptr::null_mut();
    }
}

impl Drop for PamResponses {
    /**
     * 
     */
    fn drop(&mut self) {
        if self.ptr.is_null() {
            return;
        }

        for index in 0..self.count {
            let response = unsafe { 
                &mut *self.ptr.add(index) 
            };

            if !response.resp.is_null() {
                let len = unsafe { 
                    CStr::from_ptr(response.resp).to_bytes_with_nul().len() 
                };

                let bytes = unsafe { 
                    slice::from_raw_parts_mut(response.resp as *mut u8, len) 
                };

                bytes.zeroize();
                unsafe {
                    free(response.resp as *mut c_void);
                }
                response.resp = ptr::null_mut();
            }
        }

        unsafe {
            free(self.ptr as *mut c_void);
        }
    }
}

/**
 * FFI-compatible callback adapter between PAM and a Rust `PamConv` object.
 *
 * Called internally by PAM through the `pam_conv` structure.
 * Performs string decoding, allocates a response array, and invokes the
 * user-defined callback. Errors are mapped to PAM_CONV_ERR.
 */
unsafe extern "C" fn pam_conv_process<T: PamConv>(
        num_msg: c_int, 
        msg: *mut *const pam_message, 
        resp: *mut *mut pam_response, 
        appdata_ptr: *mut c_void
) -> c_int {

    if num_msg <= 0
        || num_msg as u32 > PAM_MAX_NUM_MSG
        || msg.is_null()
        || resp.is_null()
        || appdata_ptr.is_null()
    {
        return PAM_CONV_ERR as c_int;
    }

    unsafe {
        *resp = ptr::null_mut();
    }

    let mut replies = match PamResponses::new(num_msg as usize) {
        Some(replies) => replies,
        None => return PAM_BUF_ERR as c_int,
    };

    let callback = unsafe {
        &mut *(appdata_ptr as *mut T)
    };

    for i in 0..num_msg {
        let request_ptr = unsafe { 
            *(msg.add(i as usize)) as *const pam_message 
        };
        
        if request_ptr.is_null() {
            return PAM_CONV_ERR as c_int;
        }
        
        let request = unsafe {
            &(*request_ptr)
        };
        
        let msg = if request.msg.is_null() {
            EMPTY
            
        } else {
            match unsafe { CStr::from_ptr(request.msg) }.to_str() {
                Ok(message) => message,
                Err(_) => return PAM_CONV_ERR as c_int,
            }
        };
        
        match request.msg_style as u32 {
            PAM_PROMPT_ECHO_ON |
            PAM_PROMPT_ECHO_OFF => {
            
                let style = if request.msg_style as u32 == PAM_PROMPT_ECHO_ON
                        && !msg.to_lowercase().contains("password") {
                    CONV::ECHO_ON
                } else {
                    CONV::ECHO_OFF
                };
                
                let zero_out = style == CONV::ECHO_OFF;
                let answer = match callback.prompt(msg, style) {
                    Ok(answer) => answer,
                    Err(_) => return PAM_CONV_ERR as c_int,
                };

                // Consume into bytes
                let mut bytes = answer.into_bytes();

                // Make it CString compatible
                bytes.push(0u8);

                // Copy the data using PAM compatible allocator
                let dup_ptr = unsafe { 
                    strdup(bytes.as_ptr() as *const c_char) 
                };

                if zero_out {
                    bytes.zeroize();
                }

                if dup_ptr.is_null() {
                    return PAM_BUF_ERR as c_int;
                }
            
                /*
                 * Give PamResponses ownership immediately so any later panic or
                 * error clears this allocation along with earlier responses.
                 */
                let response = unsafe { replies.get_ptr(i as usize) };
                response.resp = dup_ptr;
                response.resp_retcode = 0;
            }
            
            PAM_ERROR_MSG => {
                callback.msg(msg, CONV::ERROR);
            }
            
            PAM_TEXT_INFO => {
                callback.msg(msg, CONV::MSG);
            }
            
            _ => {
                return PAM_CONV_ERR as c_int;
            }
        }
    }
    
    unsafe {
        replies.transfer_to(resp);
    }

    PAM_SUCCESS as c_int
}

/**
 * 
 */
unsafe extern "C" fn pam_conv_wrap<T: PamConv>(
    num_msg: c_int,
    msg: *mut *const pam_message,
    resp: *mut *mut pam_response,
    appdata_ptr: *mut c_void,
) -> c_int {
    match catch_unwind(AssertUnwindSafe(|| unsafe {
        pam_conv_process::<T>(num_msg, msg, resp, appdata_ptr)
    })) {
        Ok(result) => result,
        Err(_) => PAM_CONV_ERR as c_int,
    }
}

// -------------------------
// Wrapper functions
// -------------------------

/**
 *
 */
pub struct PamHandle {
    handle: *mut pam_handle_t,
    result: Cell<u32>,
    session: Cell<bool>
}

/**
 *
 */
impl PamHandle {
    /**
     * Authenticate a user associated with the given PAM handle.
     */
    pub fn authenticate(&self, flags: u32) -> u32 {
        unsafe {
            self.result.set(c_ffi::pam_authenticate(self.handle, flags as c_int) as u32);
        }
        
        self.result.get()
    }

    /**
     * Perform PAM account management checks (e.g., expiration, validity).
     */
    #[allow(unused)]
    pub fn acct_mgmt(&self, flags: u32) -> u32 {
        unsafe {
            self.result.set(c_ffi::pam_acct_mgmt(self.handle, flags as c_int) as u32);
        }
        
        self.result.get()
    }
    
    /**
     *
     */
    #[allow(unused)]
    pub fn chauthtok(&self, flags: u32) -> u32 {
        unsafe {
            self.result.set(c_ffi::pam_chauthtok(self.handle, flags as c_int) as u32);
        }
        
        self.result.get()
    }

    /**
     * Open a new PAM session for the authenticated user.
     *
     * This should be called after successful authentication and account checks.
     * It initializes session modules like pam_systemd, pam_env, etc.
     */
    #[allow(unused)]
    pub fn open_session(&self, flags: u32) -> u32 {
        if self.session.get() {
            return PAM_SUCCESS;
        }
    
        unsafe { 
            let mut result = c_ffi::pam_setcred(self.handle, PAM_REINITIALIZE_CRED as c_int) as u32;
            
            if result == PAM_SUCCESS {
                result = c_ffi::pam_open_session(self.handle, flags as c_int) as u32;
                
                if result != PAM_SUCCESS {
                    c_ffi::pam_setcred(self.handle, PAM_DELETE_CRED as c_int);
                }
            }
            
            self.result.set(result);
        }
        
        if self.result.get() == PAM_SUCCESS {
            self.session.set(true);
        }
        
        self.result.get()
    }

    /**
     * Close a previously opened PAM session.
     *
     * This should be called once the session process terminates.
     */
    #[allow(unused)]
    pub fn close_session(&self, flags: u32) -> u32 {
        if !self.session.get() {
            return PAM_SUCCESS;
        }
    
        unsafe {
            let result = c_ffi::pam_close_session(self.handle, flags as c_int) as u32;
            
            if result == PAM_SUCCESS {
                c_ffi::pam_setcred(self.handle, PAM_DELETE_CRED as c_int);
            }
            
            self.result.set(result);
        }
        
        if self.result.get() == PAM_SUCCESS {
            self.session.set(false);
        }
        
        self.result.get()
    }
    
    /**
     * 
     */
    #[allow(unused)]
    pub fn set_item(&self, item_type: u32, value: &str) -> u32 {
        let c_value = cstring!(value);
    
        unsafe {
            self.result.set(c_ffi::pam_set_item(self.handle, item_type as c_int, c_value.as_ptr() as *const c_void) as u32);
        }
        
        self.result.get()
    }
    
    /**
     * Get a list of environment variables from PAM.
     */
    #[allow(unused)]
    pub fn getenvlist(&self) -> Vec<String> {
        let mut envs = Vec::new();

        unsafe {
            let list = c_ffi::pam_getenvlist(self.handle);

            if list.is_null() {
                return envs;
            }
            
            /*
             * Self note for the future.
             * *p.add(i) = *(p + i) in C
             *
             * One of the most stupid naming conventions ever seen, 
             * in the history of programming, but that is typical Rust. 
             */

            let mut i = 0;
            loop {
                let entry = *list.add(i);
                if entry.is_null() {
                    break;
                }

                let c_str = CStr::from_ptr(entry);
                if let Ok(s) = c_str.to_str() {
                    envs.push(s.to_owned());
                }

                i += 1;
            }

            // Free each string and the list itself
            let mut j = 0;
            while !(*list.add(j)).is_null() {
                free(*list.add(j) as *mut c_void);
                j += 1;
            }
            free(list as *mut c_void);
        }

        envs
    }
}

/**
 *
 */
impl Drop for PamHandle {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            if self.session.get() {
                self.close_session(0);
            }
        
            unsafe { 
                c_ffi::pam_end(self.handle, self.result.get() as c_int);
            }
            
            self.handle = std::ptr::null_mut();
        }
    }
}

/**
 * Initialize a PAM session and return a handle on success.
 *
 * @param service       PAM service name (e.g., "login", "sudo", "runas").
 * @param username      The target username to authenticate.
 * @param conversation  The conversation handler implementing `PamConv`.
 *
 * @return PAM handle wrapped in `Result`, or error code on failure.
 */
pub fn pam_start<T: PamConv>(service: &str, username: &str, conversation: &mut T) -> Result<PamHandle, u32> {
    let mut handle: *mut pam_handle_t = std::ptr::null_mut();
    let     c_service                 = cstring!(service);
    let     c_username                = cstring!(username);
    let     result: u32;
    
    let mut conversation = pam_conv {
        conv: Some(pam_conv_wrap::<T>),
        appdata_ptr: conversation as *mut T as *mut c_void
    };
    
    unsafe {
        result = c_ffi::pam_start(c_service.as_ptr(), c_username.as_ptr(), &mut conversation, &mut handle) as u32;
    }
        
    if result == PAM_SUCCESS && !handle.is_null() {
        return Ok(
            PamHandle {
                handle: handle,
                result: Cell::new(PAM_SUCCESS),
                session: Cell::new(false)
            }
        );
    }
    
    Err(result)
}
