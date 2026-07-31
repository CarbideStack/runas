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

use crate::modules::error::Error;
use zeroize::Zeroize;
use bitflags::bitflags;
    
use std::{
    mem, 
    ptr,
    slice,
    collections::HashMap,
    cell::{
        Cell
    },
    ffi::{
        CStr,
        CString
    },
    panic::{
        AssertUnwindSafe,
        catch_unwind
    },
    io::{
        Error as IOError
    }
};
    
use libc::{
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

    use libc::{
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
        pub fn pam_strerror(pamh: *mut pam_handle_t, errnum: c_int) -> *const c_char;
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
 *
 */
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PamError {
    code: u32,
    message: String,
}

impl PamError {
    pub fn new(code: u32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn code(&self) -> u32 {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

/**
 * Defines the message types emitted during PAM conversation callbacks.
 */
#[derive(PartialEq)]
pub enum PromptMode {
    Visible,
    Hidden,
}

/**
 * High-level conversation interface for PAM authentication.
 *
 * Implementations of this trait receive messages and prompts
 * during authentication and respond accordingly.
 */
pub trait Conversation {
    fn prompt(&mut self, message: &str, mode: PromptMode) -> Result<String, Error>;
    fn info(&mut self, message: &str) -> Result<(), Error>;
    fn error(&mut self, message: &str) -> Result<(), Error>;
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
    fn new(count: usize) -> Result<Self, Error> {
        let ptr = unsafe {
            calloc(count as size_t, mem::size_of::<pam_response>() as size_t) as *mut pam_response
        };

        if ptr.is_null() {
            return Err(Error::Io(IOError::last_os_error()))
        }

        Ok(Self { ptr, count })
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
 * user-defined callback. 
 *
 * Since we can't send Rust Errors through PAM via C and back to Rust, 
 * any none Error::Pam are written to stderr and normal PAM response
 * are sent back to PAM. 
 */
unsafe extern "C" fn pam_conv_process<T: Conversation>(
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
        Ok(replies) => replies,
        Err(err) => {
            eprintln!("PAM allocation error: {}", err);
            return PAM_BUF_ERR as c_int
        }
    };

    let callback = unsafe {
        &mut *(appdata_ptr as *mut T)
    };

    for i in 0..num_msg {
        let request_ptr = unsafe { 
            *(msg.add(i as usize)) as *const pam_message 
        };
        
        if request_ptr.is_null() {
            eprintln!("PAM conversation error: null request pointer");
            return PAM_CONV_ERR as c_int;
        }
        
        let request = unsafe {
            &(*request_ptr)
        };
        
        let msg = if request.msg.is_null() {
            eprintln!("PAM conversation error: null message pointer");
            return PAM_CONV_ERR as c_int;
            
        } else {
            match unsafe { CStr::from_ptr(request.msg) }.to_str() {
                Ok(message) => message,
                Err(err) => {
                    eprintln!("PAM conversation error: {}", err);
                    return PAM_CONV_ERR as c_int
                }
            }
        };
        
        match request.msg_style as u32 {
            PAM_PROMPT_ECHO_ON |
            PAM_PROMPT_ECHO_OFF => {
            
                let style = if request.msg_style as u32 == PAM_PROMPT_ECHO_ON
                        && !msg.to_lowercase().contains("password") {
                    PromptMode::Visible
                } else {
                    PromptMode::Hidden
                };
                
                let zero_out = style == PromptMode::Hidden;
                let answer = match callback.prompt(msg, style) {
                    Ok(answer) => answer,
                    Err(Error::Pam(err)) => return err.code() as c_int,
                    Err(err) => {
                        eprintln!("PAM conversation error: {}", err);
                        return PAM_CONV_ERR as c_int
                    }
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
                    eprintln!("PAM allocation error: {}", IOError::last_os_error());
                    return PAM_BUF_ERR as c_int
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
                match callback.error(msg) {
                    Ok(_) => {}
                    Err(Error::Pam(err)) => return err.code() as c_int,
                    Err(err) => {
                        eprintln!("PAM conversation error: {}", err);
                        return PAM_CONV_ERR as c_int
                    }
                };
            }
            
            PAM_TEXT_INFO => {
                match callback.info(msg) {
                    Ok(_) => {}
                    Err(Error::Pam(err)) => return err.code() as c_int,
                    Err(err) => {
                        eprintln!("PAM conversation error: {}", err);
                        return PAM_CONV_ERR as c_int
                    }
                };
            }
            
            _ => {
                eprintln!("PAM conversation error: unknown message style ({})", request.msg_style);
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
unsafe extern "C" fn pam_conv_wrap<T: Conversation>(
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

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PamItem {
    Service      = PAM_SERVICE,
    User         = PAM_USER,
    RUser        = PAM_RUSER,
    Tty          = PAM_TTY,
    RHost        = PAM_RHOST,
    Conv         = PAM_CONV,
    AuthTok      = PAM_AUTHTOK,
    OldAuthTok   = PAM_OLDAUTHTOK,
    UserPrompt   = PAM_USER_PROMPT,
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct AuthFlags: u32 {
        const SILENT                 = PAM_SILENT as u32;
        const DISALLOW_NULL_AUTHTOK  = PAM_DISALLOW_NULL_AUTHTOK as u32;
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct AccntFlags: u32 {
        const SILENT = PAM_SILENT as u32;
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct SessionFlags: u32 {
        const SILENT = PAM_SILENT as u32;
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct AuthTokenFlags: u32 {
        const SILENT                  = PAM_SILENT as u32;
        const CHANGE_EXPIRED_AUTHTOK  = PAM_CHANGE_EXPIRED_AUTHTOK as u32;
    }
}

/**
 *
 */
pub struct PamHandle {
    handle: *mut pam_handle_t,
    last_status: Cell<c_int>,
    session: Cell<bool>
}

/**
 *
 */
impl PamHandle {
    /**
     *
     */
    fn check(&self, result: c_int) -> Result<(), Error> {
        self.last_status.set(result);

        if result as u32 == PAM_SUCCESS {
            Ok(())
        } else {
            Err(Error::Pam(self.error(result)))
        }
    }

    /**
     *
     */
    pub fn error(&self, code: c_int) -> PamError {
        let message = unsafe {
            let ptr = c_ffi::pam_strerror(self.handle, code);

            if ptr.is_null() {
                return PamError::new(
                    PAM_SYSTEM_ERR, 
                    format!("Unknown error ({code})")
                );
            }

            CStr::from_ptr(ptr)
                .to_string_lossy()
                .into_owned()
        };

        PamError::new(code as u32, message)
    }

    /**
     * Authenticate a user associated with the given PAM handle.
     */
    pub fn authenticate(&self, flags: AuthFlags) -> Result<(), Error> {
        self.check(unsafe {
            c_ffi::pam_authenticate(self.handle, flags.bits() as c_int)
        })
    }

    /**
     * Perform PAM account management checks (e.g., expiration, validity).
     */
    #[allow(unused)]
    pub fn acct_mgmt(&self, flags: AccntFlags) -> Result<(), Error> {
        let result = unsafe {
            c_ffi::pam_acct_mgmt(self.handle, flags.bits() as c_int)
        };

        self.last_status.set(result);

        match result as u32 {
            PAM_SUCCESS => Ok(()),
            PAM_NEW_AUTHTOK_REQD => {
                Err(Error::PamActionRequired(self.error(PAM_NEW_AUTHTOK_REQD as c_int)))
            }
            result => Err(Error::Pam(self.error(result as c_int))),
        }
    }
    
    /**
     *
     */
    #[allow(unused)]
    pub fn chauthtok(&self, flags: AuthTokenFlags) -> Result<(), Error> {
        self.check(unsafe {
            c_ffi::pam_chauthtok(self.handle, flags.bits() as c_int)
        })
    }

    /**
     * Open a new PAM session for the authenticated user.
     *
     * This should be called after successful authentication and account checks.
     * It initializes session modules like pam_systemd, pam_env, etc.
     */
    #[allow(unused)]
    pub fn open_session(&self, flags: SessionFlags) -> Result<(), Error> {
        if self.session.get() {
            return Ok(());
        }

        self.check(unsafe {
            c_ffi::pam_setcred(self.handle, PAM_ESTABLISH_CRED as c_int)
        })?;

        self.check(unsafe {
            c_ffi::pam_open_session(self.handle, flags.bits() as c_int)
        })?;

        self.session.set(true);

        Ok(())
    }

    /**
     * Close a previously opened PAM session.
     *
     * This should be called once the session process terminates.
     */
    #[allow(unused)]
    pub fn close_session(&self, flags: SessionFlags) -> Result<(), Error> {
        if !self.session.get() {
            return Ok(());
        }

        self.check(unsafe {
            c_ffi::pam_close_session(self.handle, flags.bits() as c_int)
        })?;

        self.check(unsafe {
            c_ffi::pam_setcred(self.handle, PAM_DELETE_CRED as c_int)
        })
    }
    
    /**
     * 
     */
    #[allow(unused)]
    pub fn set_item(&self, item_type: PamItem, value: &str) -> Result<(), Error> {
        let c_value = CString::new(value)?;

        self.check(unsafe {
            c_ffi::pam_set_item(self.handle, item_type as c_int, c_value.as_ptr() as *const c_void)
        })
    }
    
    /**
     * Get a list of environment variables from PAM.
     */
    #[allow(unused)]
    pub fn getenvlist(&self) -> Result<HashMap<String, String>, Error> {
        let mut envs = HashMap::new();

        unsafe {
            let list = c_ffi::pam_getenvlist(self.handle);

            if list.is_null() {
                return Ok(envs);
            }

            let mut result: Result<(), Error> = Ok(());

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

                match CStr::from_ptr(entry).to_str() {
                    Ok(s) => {
                        match s.split_once('=') {
                            Some((key, value)) => {
                                envs.insert(key.to_owned(), value.to_owned());
                            }
                            
                            None => {
                                result = Err(Error::StaticMessage(
                                    "invalid environment variable returned by PAM",
                                ));
                                break;
                            }
                        }
                    }

                    Err(e) => {
                        result = Err(e.into());
                        break;
                    }
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

            result?;
        }

        Ok(envs)
    }
}

/**
 *
 */
impl Drop for PamHandle {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            if self.session.get() {
                let _ = self.close_session(SessionFlags::empty());
            }
        
            unsafe { 
                c_ffi::pam_end(self.handle, self.last_status.get());
            }
            
            self.handle = std::ptr::null_mut();
        }
    }
}

/**
 *
 */
pub fn pam_error(code: c_int) -> PamError {
    let message = unsafe {
        let ptr = c_ffi::pam_strerror(std::ptr::null_mut(), code);

        if ptr.is_null() {
            return PamError::new(
                PAM_SYSTEM_ERR,
                format!("Unknown error ({code})")
            );
        }

        CStr::from_ptr(ptr)
            .to_string_lossy()
            .into_owned()
    };

    PamError::new(code as u32, message)
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
pub fn pam_start<T: Conversation>(service: &str, username: &str, conversation: &mut T) -> Result<PamHandle, Error> {
    let mut handle: *mut pam_handle_t = std::ptr::null_mut();
    let     c_service                 = CString::new(service)?;
    let     c_username                = CString::new(username)?;
    
    let mut conversation = pam_conv {
        conv: Some(pam_conv_wrap::<T>),
        appdata_ptr: conversation as *mut T as *mut c_void
    };

    let result = unsafe {
        c_ffi::pam_start(c_service.as_ptr(), c_username.as_ptr(), &mut conversation, &mut handle)
    };

    if result as u32 != PAM_SUCCESS {
        return Err(Error::Pam(pam_error(result)));

    } else if handle.is_null() {
        // Should not be possible
        return Err(Error::StaticMessage("returned null pointer PAM handle"));
    }

    Ok(
        PamHandle {
            handle: handle,
            last_status: Cell::new(PAM_SUCCESS as c_int),
            session: Cell::new(false)
        }
    )
}
