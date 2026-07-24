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
 * Minimal Rust FFI bindings and wrappers for `libcrypt` and shadow password access.
 *
 * This module exposes two low-level system interfaces:
 *
 *  - `crypt()`: links against the C `libcrypt` library to hash a password using a salt.
 *  - `getspnam()`: links against the C `libc` function to read the shadow password
 *    entry for a specific user.
 *
 * These functions are wrapped with safe Rust interfaces that perform `CString`
 * conversions and return `Option<String>` for convenience.
 *
 * ## Dependencies
 * Requires the system libraries:
 *  - `libcrypt` (for `crypt()`)
 *  - `libc` (for `getspnam()` and `spwd`)
 *
 * The crate must be linked with `-l crypt` at build time.
 */

mod c_ffi {
    use nix::libc::{
        spwd, 
        c_char
    };

    unsafe extern "C" {
        /**
         * Link to the C library function `crypt()`.
         *
         * Hashes a password using the specified salt and returns a pointer
         * to a static buffer containing the hashed value.
         */
        pub fn crypt(key: *const c_char, salt: *const c_char) -> *mut c_char;
        
        /**
         * Link to the C library function `getspnam()`.
         *
         * Looks up a user entry in `/etc/shadow` and returns a pointer to
         * a static `struct spwd`.
         */
        pub fn getspnam(name: *const c_char) -> *mut spwd;
    }
}

use crate::shared::*;
use crate::errx;
use std::ptr;
use zeroize::Zeroize;

use nix::libc::{
    spwd, 
    c_char
};

use std::ffi::{
    CStr, 
    CString
};

/**
 * Container for the getspnam() output
 */
pub struct ShadowEntry {
    pub passwd_hash: String,
    pub last_change: i64,
    pub max_age: i64,
    pub inactive: i64,
    pub expiry: i64,
}

/**
 * Rust-safe wrapper for `libcrypt::crypt()`.
 *
 * Hashes a password using a given salt and returns the resulting hash as a `String`.
 *
 * Returns `None` if `crypt()` fails (e.g., invalid salt or internal error).
 *
 * @param passwd  Plaintext password
 * @param salt    Salt string (e.g., "$6$somesalt")
 */
pub fn crypt(passwd: String, salt: &str) -> Option<String> {
    let mut bytes = passwd.into_bytes();
    bytes.push(0u8);
    
    let c_salt = CString::new(salt).unwrap_or_else(|e| {
        bytes.zeroize();
        errx!(1, "crypt: {}\n\t{}", MSG_PARSE_CSTRING, e);
    });
    
    let hash: *mut c_char = unsafe {
        c_ffi::crypt(bytes.as_ptr() as *const c_char, c_salt.as_ptr())
    };
    
    bytes.zeroize();
    
    if hash == ptr::null_mut() {
        return None;
    }
    
    return Some(
        unsafe {
            CStr::from_ptr(hash).to_string_lossy().into_owned()
        }
    );
}

/**
 * Rust-safe wrapper for `libc::getspnam()`.
 *
 * Queries the system shadow password file (`/etc/shadow`) for a given username
 * and returns the hashed password field, if accessible.
 *
 * Returns `None` if the user does not exist or access is denied.
 *
 * @param username  Username to look up
 */
pub fn getspnam(username: &str) -> Option<ShadowEntry> {
    let c_username = CString::new(username).unwrap_or_else(|e| { errx!(1, "getspnam: {}\n\t{}", MSG_PARSE_CSTRING, e); });

    unsafe {
        let spwd_ptr: *mut spwd = c_ffi::getspnam(c_username.as_ptr());
        
        if spwd_ptr != ptr::null_mut() {
            let entry = &*spwd_ptr;
            
            return Some(ShadowEntry {
                passwd_hash: CStr::from_ptr(entry.sp_pwdp).to_string_lossy().into_owned(),
                last_change: entry.sp_lstchg,
                max_age: entry.sp_max,
                inactive: entry.sp_inact,
                expiry: entry.sp_expire,
            });
        }
    }
    
    return None;
}

