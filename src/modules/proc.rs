// Copyright (c) 2025 Daniel Bergløv
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

use cfg_if::cfg_if;
use crate::errx;
use super::user::Account;
use std::ffi::CString;

use nix::unistd::{
    setgroups, 
    setresgid, 
    setresuid
};

cfg_if! {
    if #[cfg(feature = "backend_scopex")] {
        use crate::shared::*;
        use super::path::find_executable;
        use nix::libc::gid_t;
        use std::os::unix::ffi::OsStrExt;
        use std::time::Duration;

        use std::{
            thread,
            env
        };
        
        use std::os::raw::{
            c_char,
            c_int
        };
        
        use std::sync::atomic::{
            AtomicI32, 
            Ordering
        };
        
        use nix::sys::signal::{
            self, 
            Signal,
            SigSet,
            SigHandler,
            SigAction,
            SaFlags,
            SigmaskHow
        };
        
        use nix::sys::wait::{
            waitpid,
            WaitStatus
        };
        
        use nix::unistd::{
            execve,
            Pid
        };
    
    } else {
        use nix::unistd::{
            execvp, 
            Gid, 
            Uid
        };
    }
}

/**
 *
 */
#[cfg(feature = "backend_scopex")]
static CAUGHT_SIGNAL: AtomicI32 = AtomicI32::new(0);

/**
 *
 */
#[cfg(feature = "backend_scopex")]
extern "C" fn catch_signal(signum: c_int) {
    CAUGHT_SIGNAL.compare_exchange(0, signum, Ordering::SeqCst, Ordering::SeqCst).ok();
}

/**
 *
 */
#[cfg(feature = "backend_scopex")]
pub fn watch_process(pid: Pid) -> i32 {
    let mut status_code: i32 = 0;
    let     all              = SigSet::all();
    let     proc             = pid.as_raw();
    let mut alive: bool      = proc >= 0;
    
    // Disable all signals targeting this application
    if let Err(e) = signal::pthread_sigmask(SigmaskHow::SIG_BLOCK, Some(&all), None) {
        eprintln!("failed to block signals: {}", e);
        status_code = 1;
    }
    
    let mut old_action: Option<SigAction> = None;
    
    // Setup signal handling
    if status_code == 0 {
        // Setup handler to deal with specific signals
        let handler = SigHandler::Handler(catch_signal);
        let action = SigAction::new(handler, SaFlags::empty(), SigSet::empty());
        
        // Whitelisted signals
        let signals: &[Signal] = &[Signal::SIGTERM, Signal::SIGALRM, Signal::SIGTSTP];
        let mut unblock_set = SigSet::empty();
        
        // Add custom handler to select signals
        for &sig in signals {
            match unsafe { signal::sigaction(sig, &action) } {
                Ok(prev) => {
                    old_action = Some(prev);
                }
                
                Err(e) => {
                    eprintln!("failed to install SIGTERM handler: {}", e);
                    status_code = 1;
                    
                    break;
                }
            }
            
            unblock_set.add(sig);
        }
        
        if status_code == 0 {
            // Whitelist our select signals
            if let Err(e) = signal::pthread_sigmask(SigmaskHow::SIG_UNBLOCK, Some(&unblock_set), None) {
                eprintln!("failed to unblock signals: {}", e);
                status_code = 1;
            }
        }
    }
    
    // Start watching the process
    if status_code == 0 && proc >= 0 {
        match waitpid(pid, None) {
            Ok(WaitStatus::Exited(_, code)) => {
                status_code = code as i32;
                alive = false;
            }
            
            Ok(WaitStatus::Signaled(_, sig, core)) => {
                let sig_num: i32 = sig as i32;
                status_code = sig_num + 128;
                alive = false;
                
                println!("killed by {:?} ({}), core dumped: {}", sig, sig_num, core);
            }
            
            Ok(ws) => {
                eprintln!("unexpected wait status: {:?}", ws);
                status_code = 1;
            }
            
            Err(_) => {
                status_code = 1;
                
                // If we got interrupted by a signal and caught_signal is set,
                // prefer the caught signal as exit cause.
                let caught = CAUGHT_SIGNAL.load(Ordering::SeqCst);
                
                if caught != 0 {
                    status_code = caught + 128;
                }
            }
        }
        
    } else if status_code == 0 {
        status_code = 1;
        
        // No child: if we caught a signal, map it, otherwise default 1
        let caught = CAUGHT_SIGNAL.load(Ordering::SeqCst);
        
        if caught != 0 {
            status_code = caught + 128;
        }
    }
    
    // Ask the process nicely to stop, then kill the damn thing
    if status_code != 0 && alive {
        let _ = signal::kill(pid, Signal::SIGTERM);
        thread::sleep(Duration::from_secs(2));
        let _ = signal::kill(pid, Signal::SIGKILL);
    }
    
    // restore old SIGTERM handler if we saved it
    if let Some(old) = old_action {
        let _ = unsafe { signal::sigaction(Signal::SIGTERM, &old) };
    }
    
    status_code
}

/**
 *
 */
#[cfg(feature = "backend_scopex")]
fn initgroups(username: &str, gid: gid_t) -> Result<NULL, std::io::Error> {
    let c_user = CString::new(username).unwrap_or_else(|e| { errx!(1, "initgroups: {}\n\t{}", MSG_PARSE_CSTRING, e); });
    
    // SAFETY: initgroups reads /etc/group and sets supplementary group list.
    // Must be called as root.
    let r = unsafe { 
        nix::libc::initgroups(c_user.as_ptr() as *const c_char, gid) 
    };
    
    if r != 0 {
        return Err(std::io::Error::last_os_error());
    }
    
    Ok(NULL)
}

/**
 *
 */
pub fn exec(
    user: &Account, 
    #[cfg(feature = "backend_scopex")] target: &Account, 
    cmd: &CString, 
    argv: &[CString], 
    #[cfg(feature = "backend_scopex")] envp: &[CString],
    #[cfg(feature = "backend_scopex")] cwd: &Option<String>
) {

    cfg_if! {
        if #[cfg(feature = "backend_scopex")] {
            let target_gid = target.gid();
            let target_uid = target.uid();
            let user_gid = user.gid();
            let user_uid = user.uid();
            
            let path_str = cmd.to_str().unwrap_or_else(|e| { errx!(1, "exec: {}\n\t{}", MSG_PARSE_CSTRING, e); });
            let cmd_path = match find_executable(path_str, envp) {
                Ok(path) => {
                    CString::new(path.as_os_str().as_bytes()).unwrap_or_else(|err| {
                        errx!(1, "exec: {}\n\t{}", MSG_PARSE_CSTRING, err);
                    })
                }

                Err(err) => {
                    errx!(1, "exec: {}: {}", path_str, err);
                }
            };
    
            if !setgroups(&[]).is_ok() {
                errx!(1, "Failed to reset group privileges");

            } else if !initgroups(target.name(), target_gid.as_raw()).is_ok() {
                errx!(1, "Failed to load target groups");
                
            } else if !setresgid(target_gid, target_gid, user_gid).is_ok() {
                errx!(1, "Failed to set target group");
            
            } else if !setresuid(target_uid, target_uid, user_uid).is_ok() {
                errx!(1, "Failed to set target user");
            }
            
            if let Some(d) = cwd {
                if let Err(e) = env::set_current_dir(d) {
                    errx!(1, e);
                }
            }
            
            execve(&cmd_path, argv, envp).expect("Failed to spawn process");
        
        } else {
            let root_gid = Gid::from_raw(0);
            let root_uid = Uid::from_raw(0);

            if !setgroups(&[]).is_ok() {
                errx!(1, "Failed to reset group privileges");

            } else if !setresgid(root_gid, root_gid, user.gid()).is_ok() {
                errx!(1, "Failed to raise group privileges");

            } else if !setresuid(root_uid, root_uid, user.uid()).is_ok() {
                errx!(1, "Failed to raise user privileges");
            }
        
            execvp(cmd, argv).expect("Failed to spawn process");
        }
    }
}

