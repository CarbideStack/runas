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

use crate::{
    shared::{
        RunFlags,
        AUTH_GROUP
    }
};
use super::{
    error::{
        Error
    },
    user::{
        Account,
        Group
    }
};

#[cfg(all(feature = "backend_scopex", feature = "use_pam"))]
use std::collections::HashMap;

/**
 *
 */
#[cfg(all(feature = "backend_scopex", feature = "use_pam"))]
pub type AuthType = HashMap<String, String>;

#[cfg(not(all(feature = "backend_scopex", feature = "use_pam")))]
pub type AuthType = ();

#[cfg(not(all(feature = "backend_scopex", feature = "use_pam")))]
const DEFAULT_TRUE: Result<AuthType, Error> = Ok(());
const DEFAULT_FALSE: Result<AuthType, Error> = Err(Error::StaticMessage("authentication failed"));

#[cfg(feature = "use_pam")]
mod feat {
    use super::AuthType;
    use nix::unistd::ttyname;

    use crate::{
        shared::RunFlags,
        ffi::{
            pam::{
                pam_start,
                Conversation,
                PromptMode,
                AuthFlags,
                AuthTokenFlags,
                AccntFlags,
                PamItem
            } 
        },
        modules::{
            passwd::ask_password,
            user::Account,
            error::Error
        }
    };

    use std::{
        os::unix::io::AsRawFd,
        io::{
            IsTerminal,
            stdin as io_stdin
        }
    };

    #[cfg(feature = "backend_scopex")]
    use std::{
        process,
        mem::{
            drop,
            ManuallyDrop
        }
    };

    #[cfg(feature = "backend_scopex")]
    use nix::{
        sys::signal::Signal,
        unistd::{
            fork,
            ForkResult,
            Pid,
            setpgid
        }
    };

    #[cfg(feature = "backend_scopex")]
    use crate::{
        ffi::{
            pam::SessionFlags
        },
        modules::{
            proc::{
                watch_process,
                set_parent_exit_signal
            },
            fork_sync::{
                ForkSync,
                SyncDecision
            }
        }
    };

    /**
     *
     */
    struct Conv {
        flags: RunFlags
    }

    impl Conversation for Conv {
        /**
         *
         */
        fn prompt(&mut self, msg: &str, style: PromptMode) -> Result<String, Error> {
            let mut flags = self.flags;
            
            if style == PromptMode::Hidden {
                flags |= RunFlags::PROMPT_HIDE;
            }
        
            ask_password(msg, flags)
        }
        
        /**
         *
         */
        fn info(&mut self, msg: &str) -> Result<(), Error> {
            println!("PAM info: {}", msg);
            Ok(())
        }

        /**
         *
         */
        fn error(&mut self, msg: &str) -> Result<(), Error> {
            eprintln!("PAM error: {}", msg);
            Ok(())
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
    ) -> Result<AuthType, Error> {

        let mut conv = Conv {flags};

        #[cfg(feature = "backend_scopex")]
        let pam_user = if disable_auth {
            target.name()
        } else {
            user.name()
        };

        #[cfg(not(feature = "backend_scopex"))]
        let pam_user = user.name();

        #[cfg(not(feature = "backend_scopex"))]
        let disable_auth = false;

        let handle = pam_start(env!("CARGO_PKG_NAME"), pam_user, &mut conv)?;

        if io_stdin().is_terminal() {
            let fd = io_stdin().as_raw_fd();

            if let Ok(tty_path) = ttyname(fd) {
                let tty = tty_path.as_os_str().to_string_lossy();
                handle.set_item(PamItem::Tty, &tty)?;
                
            } else {
                handle.set_item(PamItem::Tty, "/runas")?;
            }
            
        } else {
            handle.set_item(PamItem::Tty, "/runas")?;
        }

        if !disable_auth {
            handle.authenticate(AuthFlags::empty())?;
        }

        handle.set_item(PamItem::RUser, user.name())?;

        match handle.acct_mgmt(AccntFlags::empty()) {
            Ok(()) => {}

            Err(Error::PamActionRequired(_))
                if !flags.contains(RunFlags::AUTH_NO_PROMPT) =>
            {
                handle.chauthtok(AuthTokenFlags::CHANGE_EXPIRED_AUTHTOK)?;
            }

            Err(err) => return Err(err),
        }

        #[cfg(feature = "backend_scopex")]
        handle.set_item(PamItem::User, target.name())?;

        #[cfg(not(feature = "backend_scopex"))]
        return Ok(());

        #[cfg(feature = "backend_scopex")]
        {
            handle.open_session(SessionFlags::empty())?;

            let sync = ForkSync::new()?;
            let pam_env = handle.getenvlist()?;
            let handle = ManuallyDrop::new(handle);

            match unsafe { fork() } {
                Ok(ForkResult::Child) => {
                    let pipe = sync.into_child();

                    set_parent_exit_signal(Signal::SIGKILL)?;
                    setpgid(Pid::from_raw(0), Pid::from_raw(0))?;

                    // Notify the parent that we are ready to continue
                    if pipe.ready_and_wait()? != SyncDecision::Continue {
                        return Err(Error::Unknown);
                    }

                    // Everything succeded. Let's get this process running.
                    return Ok(pam_env);
                }

                Ok(ForkResult::Parent { child }) => {
                    // Wait for the process and keep PAM session alive
                    let status_code: i32 = match watch_process(child, sync.into_parent()) {
                        Ok(code) => code,
                        Err(err) => {
                            eprintln!("{err}");
                            1
                        }
                    };

                    // Ensure that PAM has a chance to quit before terminating
                    drop(ManuallyDrop::into_inner(handle));
                    
                    // Terminate the parent when the child exits
                    process::exit(status_code);
                }

                Err(err) => {
                    drop(ManuallyDrop::into_inner(handle));
                    return Err(Error::from(err));
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
    use super::{
        DEFAULT_TRUE,
        DEFAULT_FALSE,
        AuthType
    };

    use std::{
        time::{
            SystemTime,
            UNIX_EPOCH
        }
    };

    use crate::{
        shared::{
            RunFlags,
            PROMPT_TEXT,
        },
        modules::{
            error::Error,
            user::Account,
            passwd::{
                ask_password,
                time_compare
            }
        },
        ffi::{
            shadow::{
                crypt,
                getspnam
            }
        }
    };

    /**
     * Shadow-file authentication backend.
     */
    pub fn auth(user: &Account, flags: RunFlags) -> Result<AuthType, Error> {
        if let Some(entry) = getspnam(user.name())? {
            let today = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| (duration.as_secs() / 86_400) as i64)
                .unwrap_or(i64::MAX);

            let passwd_expiry = if entry.last_change == 0 {
                /*
                 * TODO:
                 *      Add passwd change after password verification? 
                 *       - Instead of failing, verify and prompt for change.
                 */
                return Err(Error::StaticMessage("password has expired")) // Password change required

            } else if entry.last_change > 0 && entry.max_age >= 0 {
                match entry.last_change.checked_add(entry.max_age) {
                    Some(expiry) => Some(expiry),
                    None => return Err(Error::StaticMessage("invalid shadow data")), // Invalid shadow data
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

            if accnt_expired {
                return Err(Error::StaticMessage("account has expired"));

            } else if passwd_expired {
                return Err(Error::StaticMessage("password has expired"));

            } else if inactive {
                return Err(Error::StaticMessage("account has been disabled due to password inactivity"));
            }

            let pwd = ask_password(PROMPT_TEXT, flags | RunFlags::PROMPT_HIDE)?;
            let user_hash = crypt(pwd, &entry.passwd_hash)?;
            
            if time_compare(&user_hash, &entry.passwd_hash) {
                return DEFAULT_TRUE;
            }
        }
    
        DEFAULT_FALSE
    }
}

/**
 *
 */
enum AuthDecision {
    Allow,
    Deny,
    Authenticate,
}

/**
 *
 */
fn auth_decision(
    is_root: bool,
    same_uid: bool,
    has_target_group: bool,
    non_interactive: bool
) -> AuthDecision {
    /*
     * The following will evaluate to Allow:
     *  - The user is root (Can do whatever they want).
     *  - The user is launching this as it's own UID and primary GID.
     *  - The user is launching this as it's own UID and a GID that the UID is a member of.
     *
     * The following will evaluate to Authenticate:
     *  - The user tries to switch UID away from it's own.              E.g. --uid
     *  - The user tries to access a GID that it is not a member of.    E.g. --gid
     */
    if is_root || (same_uid && has_target_group) {
        return AuthDecision::Allow;

    } else if !non_interactive {
        return AuthDecision::Authenticate;
    }

    return AuthDecision::Deny;
}

/**
 * Authenticate a user against a target account.
 *
 * @param user     The invoking account
 * @param target   The target account being accessed
 * @param flags    Runtime authentication flags
 */
pub fn authenticate(user: &Account, target: &Account, flags: RunFlags) -> Result<AuthType, Error> {
    let non_interactive =
        flags.contains(RunFlags::AUTH_NO_PROMPT)
            && !flags.contains(RunFlags::AUTH_STDIN);

    match auth_decision(
        user.is_root(),
        target.uid() == user.uid(),
        target.gid() == user.gid() || user.is_member(target.group())?,
        non_interactive
    ) {
        AuthDecision::Allow => {
            #[cfg(not(all(feature = "backend_scopex", feature = "use_pam")))]
            return DEFAULT_TRUE;

            #[cfg(all(feature = "backend_scopex", feature = "use_pam"))]
            return feat::auth(user, target, flags, true);
        }

        AuthDecision::Deny => {
            return DEFAULT_FALSE;
        }

        AuthDecision::Authenticate => {
            let is_wheel_member: bool = if let Some(wheel) = Group::from(AUTH_GROUP)? {
                user.is_member(&wheel)?
            } else {
                false
            };

            if !is_wheel_member {
                return DEFAULT_FALSE;
            }

            #[cfg(all(feature = "backend_scopex", feature = "use_pam"))]
            return feat::auth(user, target, flags, false);

            #[cfg(not(all(feature = "backend_scopex", feature = "use_pam")))]
            return feat::auth(user, flags);
        }
    }
}
