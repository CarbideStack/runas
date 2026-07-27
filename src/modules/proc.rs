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
use std::convert::Infallible;

use nix::unistd::{
    setgroups, 
    setresgid, 
    setresuid
};

cfg_if! {
    if #[cfg(feature = "backend_scopex")] {
        use crate::shared::*;
        use super::path::find_executable;
        use super::fork_sync::ForkEndpoint;
        use nix::libc::gid_t;
        use nix::errno::Errno;
        use std::os::unix::ffi::OsStrExt;
        use std::os::fd::AsRawFd;
        use std::io;
        use std::env;

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
            SaFlags
        };
        
        use nix::sys::wait::{
            waitpid,
            WaitStatus,
            WaitPidFlag
        };
        
        use nix::unistd::{
            setpgid,
            tcgetpgrp,
            tcsetpgrp,
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
const FORWARDED_SIGNALS: &[Signal] = &[
    Signal::SIGHUP,
    Signal::SIGINT,
    Signal::SIGQUIT,
    Signal::SIGTERM,
    Signal::SIGALRM,
    Signal::SIGTSTP,
    Signal::SIGCONT,
    Signal::SIGWINCH,
];

/**
 *
 */
#[cfg(feature = "backend_scopex")]
extern "C" fn catch_signal(signum: c_int) {
    CAUGHT_SIGNAL.store(signum, Ordering::SeqCst);
}

/**
 * 
 */
#[cfg(feature = "backend_scopex")]
struct SignalHandler {
    actions: Vec<(Signal, SigAction)>,
    foreground_group: Option<(i32, Pid, Pid)>,
}

#[cfg(feature = "backend_scopex")]
impl SignalHandler {
    /**
     * 
     */
    fn forward_signal(group: Pid) -> Option<Signal> {
        let raw = CAUGHT_SIGNAL.swap(0, Ordering::SeqCst);
        let caught = Signal::try_from(raw).ok()?;

        /*
        * kill() with a negative PID addresses the entire child process group.
        */
        let _ = signal::kill(Pid::from_raw(-group.as_raw()), caught);
        Some(caught)
    }

    /**
     * 
     */
    fn install(child: Pid) -> nix::Result<Self> {
        let action = SigAction::new(
            SigHandler::Handler(catch_signal),
            SaFlags::empty(),
            SigSet::empty(),
        );
        let mut actions = Vec::with_capacity(FORWARDED_SIGNALS.len());

        for &sig in FORWARDED_SIGNALS {
            match unsafe { signal::sigaction(sig, &action) } {
                Ok(prev) => actions.push((sig, prev)),

                Err(e) => {
                    for (sig, prev) in actions.into_iter().rev() {
                        let _ = unsafe { signal::sigaction(sig, &prev) };
                    }

                    return Err(e);
                }
            }
        }

        /*
         * A background supervisor must ignore SIGTTOU while transferring
         * terminal ownership to and from the child process group.
         */
        let ignore = SigAction::new(SigHandler::SigIgn, SaFlags::empty(), SigSet::empty());
        match unsafe { signal::sigaction(Signal::SIGTTOU, &ignore) } {
            Ok(prev) => actions.push((Signal::SIGTTOU, prev)),
            Err(error) => {
                for (sig, prev) in actions.into_iter().rev() {
                    let _ = unsafe { signal::sigaction(sig, &prev) };
                }

                return Err(error);
            }
        }

        /*
         * Give the child process group control of the terminal. Ignore errors
         * when stdin is not a controlling terminal.
         */
        let terminal = io::stdin().as_raw_fd();
        let foreground_group = tcgetpgrp(terminal).ok().and_then(|original| {
            tcsetpgrp(terminal, child)
                .ok()
                .map(|_| (terminal, original, child))
        });

        Ok(Self {
            actions,
            foreground_group,
        })
    }

    /**
     * 
     */
    fn transfer_to_parent(&self) {
        if let Some((terminal, original, _)) = self.foreground_group {
            let _ = tcsetpgrp(terminal, original);
        }
    }

    /**
     * 
     */
    fn transfer_to_child(&self) {
        if let Some((terminal, _, child)) = self.foreground_group {
            let _ = tcsetpgrp(terminal, child);
        }
    }
}

#[cfg(feature = "backend_scopex")]
impl Drop for SignalHandler {
    /**
     * 
     */
    fn drop(&mut self) {
        self.transfer_to_parent();

        for &(sig, ref prev) in self.actions.iter().rev() {
            let _ = unsafe { signal::sigaction(sig, prev) };
        }
    }
}

/**
 *
 */
#[cfg(feature = "backend_scopex")]
pub fn watch_process(pid: Pid, pipe: ForkEndpoint) -> i32 {

    // Create the process group
    if setpgid(pid, pid).is_err() {
        eprintln!("failed to create child process group");
        return 1;
    }

    // Install signal handler
    let handler = match SignalHandler::install(pid) {
        Ok(handler) => handler,
        Err(error) => {
            eprintln!("failed to install signal handlers: {error}");
            return 1;
        }
    };

    // Notify the child process that we are ready on this side
    let _ = pipe.ready_and_wait();

    // Let the watcher deal with foreground changes when the child stops
    let flags = WaitPidFlag::WUNTRACED | WaitPidFlag::WCONTINUED;

    loop {
        match waitpid(pid, Some(flags)) {
            Ok(WaitStatus::Exited(_, code)) => {
                return code;
            }
            
            Ok(WaitStatus::Signaled(_, sig, _)) => {
                return 128 + sig as i32;
            }
            
            Ok(WaitStatus::Stopped(_, sig)) => {
                eprintln!("child stopped by {sig:?}");

                /*
                * Return terminal control and stop the supervisor.
                * After the shell resumes, restore the child as the foreground group
                * and wake the child process group.
                */
                handler.transfer_to_parent();
                let _ = signal::raise(Signal::SIGSTOP);
                handler.transfer_to_child();
                let _ = signal::kill(Pid::from_raw(-pid.as_raw()), Signal::SIGCONT);
            }

            Ok(WaitStatus::Continued(_)) | Ok(WaitStatus::StillAlive) => {
                let _ = SignalHandler::forward_signal(pid);
            }

            Ok(WaitStatus::PtraceEvent(_, _, _)) | Ok(WaitStatus::PtraceSyscall(_)) => {}

            Err(Errno::EINTR) => {
                let _ = SignalHandler::forward_signal(pid);
            }

            Err(Errno::ECHILD) => return 1,

            Err(error) => {
                eprintln!("waitpid failed: {error}");
                return 1;
            }
        }
    }
}

/**
 *
 */
#[cfg(feature = "backend_scopex")]
fn initgroups(username: &str, gid: gid_t) -> Result<NULL, io::Error> {
    let c_user = CString::new(username).unwrap_or_else(|e| { errx!(1, "initgroups: {}\n\t{}", MSG_PARSE_CSTRING, e); });
    
    // SAFETY: initgroups reads /etc/group and sets supplementary group list.
    // Must be called as root.
    let r = unsafe { 
        nix::libc::initgroups(c_user.as_ptr() as *const c_char, gid) 
    };
    
    if r != 0 {
        return Err(io::Error::last_os_error());
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
) -> Infallible {

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
            
            execve(&cmd_path, argv, envp).expect("Failed to spawn process")
        
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
        
            execvp(cmd, argv).expect("Failed to spawn process")
        }
    }
}

