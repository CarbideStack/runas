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

use crate::modules::{
    env::clean_environment,
    error::Error,
    user::Account,
};

#[cfg(all(feature = "backend_scopex", feature = "use_pam"))]
use crate::modules::{
    fg_handler::ForegroundHandler,
    fork_sync::ForkEndpoint,
    signal_recv::SignalReceiver,
};

use std::{
    convert::Infallible,
    ffi::CString
};

#[cfg(feature = "backend_scopex")]
use std::{
    env::{
        set_current_dir as env_set_current_dir,
        var as env_var
    },
    path::Path,
    io::Error as IOError,
    os::{
        raw::c_char
    },
};

use nix::unistd::{
    setgroups,
    setresgid,
    setresuid,
};

#[cfg(feature = "backend_scopex")]
use nix::{
    libc::{
        initgroups as libc_initgroups,
        gid_t
    },
    unistd::execve,
    errno::Errno
};

#[cfg(not(feature = "backend_scopex"))]
use nix::unistd::{
    execvp,
    Gid,
    Uid,
};

#[cfg(all(feature = "backend_scopex", feature = "use_pam"))]
use nix::{
    sys::{
        signal::{self, Signal},
        wait::{
            waitpid,
            WaitPidFlag,
            WaitStatus,
        },
    },
    unistd::{
        getppid,
        setpgid,
        Pid,
    },
};

/**
 * 
 */
#[cfg(all(feature = "backend_scopex", feature = "use_pam"))]
const RECEIVED_SIGNALS: &[Signal] = &[
    Signal::SIGCHLD,
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
#[cfg(all(feature = "backend_scopex", feature = "use_pam"))]
pub(crate) fn watch_process(pid: Pid, pipe: ForkEndpoint) -> Result<i32, Error> {

    let mut signals = SignalReceiver::install(RECEIVED_SIGNALS.iter().copied())?;
    let handler = ForegroundHandler::install(pid)?;

    // Create the process group
    setpgid(pid, pid)?;

    // Notify the child process that we are ready on this side
    let _ = pipe.ready_and_wait();

    // Let the watcher deal with foreground changes when the child stops
    let flags = WaitPidFlag::WUNTRACED | WaitPidFlag::WCONTINUED | WaitPidFlag::WNOHANG;

    //
    let mut initiate = true;

    loop {
        let signal = if initiate {
            initiate = false;
            Signal::SIGCHLD

        } else {
            let event = signals.wait()?;

            match event.signal() {
                Some(signal) => signal,
                None => {
                    continue;
                }
            }
        };

        if signal == Signal::SIGCHLD {
            loop {
                match waitpid(pid, Some(flags)) {
                    Ok(WaitStatus::Exited(_, code)) => return Ok(code),
                    Ok(WaitStatus::Signaled(_, sig, _)) => return Ok(128 + sig as i32),
                    
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

                    Ok(WaitStatus::StillAlive) => break,
                    Ok(_) => continue,

                    Err(Errno::EINTR) => continue,
                    Err(Errno::ECHILD) => return Ok(1),
                    Err(error) => return Err(Error::from(error))
                }
            }

        } else {
            let _ = signal::kill(Pid::from_raw(-pid.as_raw()), signal);
        }
    }
}

/**
 * 
 */
#[cfg(all(feature = "backend_scopex", feature = "use_pam"))]
pub(crate) fn set_parent_exit_signal(signal: Signal) -> Result<(), Errno> {
    let result = unsafe {
        libc::prctl(
            libc::PR_SET_PDEATHSIG,
            signal as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    };

    Errno::result(result).map(|_| ())
}

/**
 *
 */
#[cfg(feature = "backend_scopex")]
fn initgroups(username: &str, gid: gid_t) -> Result<(), Error> {
    let c_user = CString::new(username)?;
    
    // SAFETY: initgroups reads /etc/group and sets supplementary group list.
    // Must be called as root.
    let r = unsafe { 
        libc_initgroups(c_user.as_ptr() as *const c_char, gid) 
    };
    
    if r != 0 {
        return Err(Error::from(IOError::last_os_error()));
    }
    
    Ok(())
}

/**
 * Execute a command using the caller's PATH, falling back to PATH entries
 * supplied through envp.
 */
#[cfg(feature = "backend_scopex")]
fn execvpe(
    cmd: &CString,
    argv: &[CString],
    envp: &[CString],
) -> Result<Infallible, Error> {
    let command = cmd.to_str()?;

    if command.contains('/') {
        return execve(cmd, argv, envp).map_err(Error::from);
    }

    let caller_path = env_var("PATH").ok();
    let paths = caller_path
        .iter()
        .map(String::as_str)
        .chain(
            envp.iter().filter_map(|entry| {
                entry.to_str().ok()?.strip_prefix("PATH=")
            })
        );

    let mut permission_denied = false;

    for path in paths {
        for directory in path.split(':') {
            if directory.is_empty() {
                continue;
            }

            let candidate = Path::new(directory).join(command);
            let candidate = CString::new(
                candidate.as_os_str().as_encoded_bytes()
            )?;

            match execve(&candidate, argv, envp) {
                Err(Errno::ENOENT | Errno::ENOTDIR) => continue,

                Err(Errno::EACCES) => {
                    permission_denied = true;
                }

                Err(error) => {
                    return Err(Error::from(error));
                }

                Ok(never) => match never {},
            }
        }
    }

    if permission_denied {
        Err(Error::from(Errno::EACCES))
    } else {
        Err(Error::from(Errno::ENOENT))
    }
}

/**
 *
 */
pub fn exec<
    #[cfg(feature = "backend_scopex")]
    P: AsRef<Path>,
>(
                                       user: &Account, 
    #[cfg(feature = "backend_scopex")] target: &Account, 
                                       cmd: &CString, 
                                       argv: &[CString], 
    #[cfg(feature = "backend_scopex")] envp: &[CString],
    #[cfg(feature = "backend_scopex")] cwd: Option<P>
) -> Result<Infallible, Error> {

    let current_gid = user.gid();
    let current_uid = user.uid();

    let (target_gid, target_uid) = {
        #[cfg(feature = "backend_scopex")]
        {
            (target.gid(), target.uid())
        }

        #[cfg(not(feature = "backend_scopex"))]
        {
            (Gid::from_raw(0), Uid::from_raw(0))
        }
    };

    #[cfg(all(feature = "use_pam", feature = "backend_scopex"))]
    let supervisor = getppid();

    clean_environment();
    setgroups(&[])?;

    #[cfg(feature = "backend_scopex")]
    initgroups(target.name(), target_gid.as_raw())?;

    setresgid(target_gid, target_gid, current_gid)?;
    setresuid(target_uid, target_uid, current_uid)?;

    #[cfg(not(feature = "backend_scopex"))]
    return execvp(cmd, argv).map_err(Error::from);

    #[cfg(all(feature = "backend_scopex", feature = "use_pam"))]
    {
        /* credential changes may cause Linux to clear this,
         * so we call it again.
         */
        set_parent_exit_signal(Signal::SIGKILL)?;

        /* Also make sure that the parent did not change during 
         * the time we took to re-configure the death signal
         */

        if getppid() != supervisor {
            let _ = signal::raise(Signal::SIGKILL);
        }
    }

    #[cfg(feature = "backend_scopex")]
    {
        if let Some(dir) = cwd {
            env_set_current_dir(dir)?;
        }

        return execvpe(cmd, argv, envp);
    }
}
