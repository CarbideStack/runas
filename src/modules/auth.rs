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
 * Unified authentication interface for `runas`.
 *
 * This module provides a single authentication entry point that selects between
 * two backends:
 *
 *  - **PAM-based authentication** (`--features use_pam`):  
 *    Uses the system’s Pluggable Authentication Module (PAM) stack to verify
 *    credentials and perform account management checks.
 *
 *  - **Shadow-file authentication** (default, no PAM):  
 *    Directly reads `/etc/shadow`, retrieves the stored password hash via
 *    `getspnam()`, and verifies it using `crypt()`.
 *
 * The top-level `authenticate()` function is responsible for determining whether
 * authentication is required, selecting the appropriate backend, and enforcing
 * privilege and membership checks.
 */

use cfg_if::cfg_if;

use crate::shared::*;
use super::user::{
    Account,
    Group
};

cfg_if! {
    if #[cfg(feature = "backend_scopex")] {
        cfg_if! {
            if #[cfg(feature = "use_pam")] {
                use crate::ffi::pam::PAM_CRED_INSUFFICIENT;
                use std::env;

                pub type AuthType = Result<Vec<String>, u32>;

                #[allow(dead_code)]
                const DEFAULT_FALSE: AuthType = Err(PAM_CRED_INSUFFICIENT);

            } else {
                pub type AuthType = Result<Vec<String>, ()>;
                const DEFAULT_FALSE: AuthType = Err(());
            }
        }

        #[allow(dead_code)]
        const DEFAULT_TRUE: AuthType = Ok(Vec::new());
        
        impl TypeCheck for AuthType {
            #[inline]
            fn is_true(&self) -> bool { self.is_ok() }
        }

    } else if #[cfg(feature = "use_pam")] {
        use crate::ffi::pam::{
            PAM_SUCCESS,
            PAM_AUTH_ERR
        };
        
        pub type AuthType = u32;
        const DEFAULT_TRUE: AuthType = PAM_SUCCESS;
        const DEFAULT_FALSE: AuthType = PAM_AUTH_ERR;
        
        impl TypeCheck for AuthType {
            #[inline]
            fn is_true(&self) -> bool { *self == PAM_SUCCESS }
        }
        
    } else {
        pub type AuthType = bool;
        const DEFAULT_TRUE: AuthType = true;
        const DEFAULT_FALSE: AuthType = false;
        
        impl TypeCheck for AuthType {
            #[inline]
            fn is_true(&self) -> bool { *self }
        }
    }
}

/*
 * We use a sub module in order to wrap the feature check in a block.
 * Rust will not allow empty blocks for some stupid reason.
 */

#[cfg(feature = "use_pam")]
mod feat {

    use cfg_if::cfg_if;

    use crate::shared::*;
    use crate::modules::passwd::ask_password;
    use crate::modules::user::Account;
    use super::AuthType;
    
    use crate::ffi::pam::{
        CONV,
        PamConv, 
        pam_start
    };
    
    use crate::ffi::pam::{
        PAM_SUCCESS,
        PAM_NEW_AUTHTOK_REQD,
        PAM_CHANGE_EXPIRED_AUTHTOK
    };
    
    cfg_if! {
        if #[cfg(feature = "backend_scopex")] {
            use std::borrow::Cow;
            use std::os::unix::io::AsRawFd;
            use std::process;
            use std::io::{self, IsTerminal};
            use nix::sys::signal::Signal;

            use crate::modules::proc::{
                watch_process,
                set_parent_exit_signal
            };

            use crate::modules::fork_sync::{
                ForkSync,
                SyncDecision
            };

            use std::mem::{
                drop,
                ManuallyDrop
            };
            
            use crate::ffi::pam::{
                PAM_TTY,
                PAM_USER,
                PAM_RUSER,
                PAM_SYSTEM_ERR
            };
            
            use nix::unistd::{
                ttyname,
                fork,
                ForkResult,
                Pid,
                setpgid
            };
        }
    }

    /**
     *
     */
    struct Conv {
        flags: RunFlags
    }
    
    impl PamConv for Conv {
        /**
         *
         */
        fn prompt(&mut self, msg: &str, style: CONV) -> Result<String, NULL> {
            let mut flags = self.flags;
            
            if style == CONV::ECHO_OFF {
                flags |= RunFlags::PROMPT_HIDE;
            }
        
            Ok(
                ask_password(msg, flags)
            )
        }
        
        /**
         *
         */
        fn msg(&mut self, msg: &str, style: CONV) {
            if style == CONV::MSG {
                println!("PAM info: {}", msg);
            
            } else {
                eprintln!("PAM error: {}", msg);
            }
        }
    }
    
    /**
     * PAM-based authentication backend.
     *
     * Uses the system PAM stack to authenticate a user interactively
     * through a conversation handler.
     */
    pub(crate) fn auth(
            user: &Account, 
            #[cfg(feature = "backend_scopex")] target: &Account, 
            flags: RunFlags,
            #[cfg(feature = "backend_scopex")] disable_auth: bool
    ) -> AuthType {
    
        let mut conv = Conv {flags};

        cfg_if! {
            if #[cfg(feature = "backend_scopex")] {
                let pam_user = if disable_auth {
                    target.name()
                } else {
                    user.name()
                };

            } else {
                let pam_user = user.name();
            }
        }
        
        match pam_start(env!("CARGO_PKG_NAME"), pam_user, &mut conv) {
            Ok(handle) => {
                cfg_if! {
                    if #[cfg(feature = "backend_scopex")] {
                        let mut result = PAM_SUCCESS;

                        if io::stdin().is_terminal() {
                            let fd: i32 = io::stdin().as_raw_fd();

                            if let Ok(tty_path) = ttyname(fd) {
                                let tty: Cow<'_, str> = tty_path.as_os_str().to_string_lossy();
                                let _ = handle.set_item(PAM_TTY, &tty);
                                
                            } else {
                                let _ = handle.set_item(PAM_TTY, "/runas");
                            }
                            
                        } else {
                            let _ = handle.set_item(PAM_TTY, "/runas");
                        }
                        
                        if !disable_auth {
                            result = handle.authenticate(0);
                        }      
                        
                        if result == PAM_SUCCESS {
                            result = handle.set_item(PAM_RUSER, user.name());
                        }
                        
                        if !disable_auth {
                            if result == PAM_SUCCESS {
                                result = handle.acct_mgmt(0);
                                
                                if result == PAM_NEW_AUTHTOK_REQD
                                        && (flags & RunFlags::AUTH_NO_PROMPT) == RunFlags::NONE {
                                    
                                    result = handle.chauthtok(PAM_CHANGE_EXPIRED_AUTHTOK);
                                }
                            }
                            
                            if result == PAM_SUCCESS {
                                result = handle.set_item(PAM_USER, target.name());
                            }
                        }
                        
                        if result == PAM_SUCCESS {
                            result = handle.open_session(0);
                        }
                    
                        if result == PAM_SUCCESS {
                            let sync = match ForkSync::new() {
                                Ok(sync) => sync,
                                Err(err) => {
                                    eprintln!("fork failed: {}", err);
                                    return Err(PAM_SYSTEM_ERR);
                                }
                            };
                            let pam_env = handle.getenvlist();
                            let handle = ManuallyDrop::new(handle);

                            match unsafe { fork() } {
                                Ok(ForkResult::Child) => {
                                    let pipe = sync.into_child();

                                    /* The child dies when the parent does.
                                     * This is not completly stable as the process we launch
                                     * can easily reconfigure this, but it helps with simple
                                     * things. 
                                     */
                                    if let Err(error) = set_parent_exit_signal(Signal::SIGKILL) {
                                        eprintln!("failed to configure parent-death signal: {}", error);
                                        return Err(PAM_SYSTEM_ERR);
                                    }

                                    // Create process group
                                    if let Err(err) = setpgid(Pid::from_raw(0), Pid::from_raw(0)) {
                                        eprintln!("fork failed: {}", err);
                                        return Err(PAM_SYSTEM_ERR);
                                    }

                                    // Notify the parent that we are ready to continue
                                    let ready = pipe.ready_and_wait();

                                    /* The parent failed. We will not continue without
                                     * parent supervision.
                                     */
                                    if ready != Ok(SyncDecision::Continue) {
                                        return Err(PAM_SYSTEM_ERR);
                                    }

                                    // Everything succeded. Let's get this process running.
                                    return Ok(pam_env);
                                }
                                
                                Ok(ForkResult::Parent { child }) => {
                                    // Wait for the process and keep PAM session alive
                                    let status_code: i32 = watch_process(child, sync.into_parent());
                                    
                                    // Ensure that PAM has a chance to quit before terminating
                                    drop(ManuallyDrop::into_inner(handle));
                                    
                                    // Terminate the parent when the child exits
                                    process::exit(status_code);
                                }
                                
                                Err(err) => {
                                    eprintln!("fork failed: {}", err);

                                    drop(ManuallyDrop::into_inner(handle));

                                    return Err(PAM_SYSTEM_ERR);
                                }
                            }
                        }
                        
                        Err(result)
                    
                    } else {
                        let mut result = handle.authenticate(0);
                        
                        if result == PAM_SUCCESS {
                            result = handle.acct_mgmt(0);
                            
                            if result == PAM_NEW_AUTHTOK_REQD
                                    && (flags & RunFlags::AUTH_NO_PROMPT) == RunFlags::NONE {
                                
                                result = handle.chauthtok(PAM_CHANGE_EXPIRED_AUTHTOK);
                            }
                        }
                    
                        result
                    }
                }
            }
            
            Err(code) => {
                cfg_if! {
                    if #[cfg(feature = "backend_scopex")] {
                        Err(code)
                    
                    } else {
                        code
                    }
                }
            }
        }
    }
}

/**
 *
 */
#[cfg(not(feature = "use_pam"))]
mod feat {

    use std::time::SystemTime;
    use std::time::UNIX_EPOCH;

    use crate::shared::*;
    use crate::modules::user::Account;
    use super::{
        AuthType,
        DEFAULT_FALSE,
        DEFAULT_TRUE
    };
    
    use crate::modules::passwd::{
        ask_password, 
        time_compare
    };
    
    use crate::ffi::shadow::{
        crypt, 
        getspnam
    };

    /**
     * Shadow-file authentication backend.
     */
    pub(crate) fn auth(user: &Account, flags: RunFlags) -> AuthType {
        if let Some(entry) = getspnam(user.name()) {
            let today = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| (duration.as_secs() / 86_400) as i64)
                .unwrap_or(i64::MAX);

            let passwd_expiry = if entry.last_change == 0 {
                return DEFAULT_FALSE // Password change required

            } else if entry.last_change > 0 && entry.max_age >= 0 {
                match entry.last_change.checked_add(entry.max_age) {
                    Some(expiry) => Some(expiry),
                    None => return DEFAULT_FALSE, // Invalid shadow data
                }

            } else {
                None // Password aging is not configured
            };

            let accnt_expired = entry.expiry >= 0 && today > entry.expiry;
            let passwd_expired = passwd_expiry.is_some_and(|expiry| today > expiry);
            let inactive = entry.inactive >= 0
                && passwd_expiry
                    .and_then(|expiry| expiry.checked_add(entry.inactive))
                    .is_some_and(|expiry| today > expiry);

            if accnt_expired || passwd_expired || inactive {
                return DEFAULT_FALSE;
            }

            let pwd = ask_password(PROMPT_TEXT, flags | RunFlags::PROMPT_HIDE);
            
            if let Some(user_hash) = crypt(pwd, &entry.passwd_hash) {
                if time_compare(&user_hash, &entry.passwd_hash) {
                    return DEFAULT_TRUE
                }
            }
            
        } else {
            eprintln!("auth: {}", MSG_IO_USER_DB);
        }
    
        DEFAULT_FALSE
    }
}

/**
 *
 */
#[cfg(all(feature = "backend_scopex", feature = "use_pam"))]
pub(crate) fn get_envp() -> Vec<String> {
    env::vars()
        .map(|(key, value)| format!("{key}={value}"))
        .collect()
}

/**
 * Authenticate a user against a target account.
 *
 * @param user     The invoking account
 * @param target   The target account being accessed
 * @param flags    Runtime authentication flags
 *
 * @return `true` if authentication succeeds or is not required, `false` otherwise.
 */
pub fn authenticate(user: &Account, target: &Account, flags: RunFlags) -> AuthType {
    /*
     * The following will evaluate to true:
     *  - The user is root (Can do whatever they want).
     *  - The user is launching this as it's own UID and primary GID.
     *  - The user is launching this as it's own UID and a GID that the UID is a member of.
     *
     * The following will require authentication:
     *  - The user tries to switch UID away from it's own.              E.g. --uid
     *  - The user tries to access a GID that it is not a member of.    E.g. --gid
     */
    if user.is_root() || (target.uid() == user.uid()
                        && (target.gid() == user.gid() || user.is_member(target.group()))) {
                         
        cfg_if! {
            if #[cfg(all(feature = "backend_scopex", feature = "use_pam"))] {
                if target.uid() != user.uid() {
                    // Even when root, we should get a new session when switching user, but no authentication.
                    return feat::auth(user, target, flags, user.is_root());
                }
            
                return Ok( get_envp() );
            
            } else {
                return DEFAULT_TRUE;
            }
        }
        
    } else if (flags & RunFlags::AUTH_NO_PROMPT) != RunFlags::NONE 
            && (flags & RunFlags::AUTH_STDIN) == RunFlags::NONE {
            
        /*
         * Password prompt was requested disabled while 
         * not requesting passing via stdin. 
         *
         * We just fail, beause auth() will launch a prompt if stdin is disabled, 
         * and caller did not want a prompt. 
         */
        return DEFAULT_FALSE;
        
    } else if let Some(wheel) = Group::from(AUTH_GROUP) {
        /*
         * We only allow the wheel group to reach outside their
         * own UID and GID's. 
         */
        if !user.is_member(&wheel) {
            return DEFAULT_FALSE;
        }
            
        cfg_if! {
            if #[cfg(all(feature = "backend_scopex", feature = "use_pam"))] {
                return feat::auth(user, target, flags, false);
                
            } else {
                return feat::auth(user, flags);
            }
        }
    }
    
    /*
     * Default to false.
     */
    DEFAULT_FALSE
}
