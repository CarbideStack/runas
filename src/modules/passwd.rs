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
 * Terminal and password handling utilities for `runas`.
 *
 * This module provides two core features:
 * 
 *  1. **Constant-time string comparison** (`time_compare`) — used to safely
 *     compare user-supplied credentials against stored values without leaking
 *     timing information.
 *  2. **Secure password input** (`ask_password`) — prompts the user for a password
 *     through a terminal or standard input while disabling echo, restoring state
 *     afterward.
 */

use crate::{
    shared::{
        RunFlags,
        PATH_TTY,
    },
    modules::{
        signal_recv::SignalReceiver,
        error::Error
    }
};

#[cfg(feature = "with_askpass_support")]
use crate::modules::{
    env::clean_environment,
    fork_sync::{
        ForkSync,
        SyncDecision,
    },
    proc::set_parent_exit_signal,
};

use zeroize::Zeroizing;
use nix::{
    errno::Errno,
    sys::{
        stat::Mode,
        signal::{
            raise,
            Signal
        },
        termios::{
            SetArg, 
            LocalFlags, 
            Termios,
            tcsetattr, 
            tcgetattr
        }
    },
    poll::{
        poll, 
        PollFd, 
        PollFlags
    },
    fcntl::{
        OFlag,
        open
    },
    libc::{
        STDIN_FILENO, 
        STDERR_FILENO
    },
    unistd::{
        close,
        read, 
        write
    }
};

#[cfg(feature = "with_askpass_support")]
use nix::{
    libc::{
        prctl,
        PR_SET_NO_NEW_PRIVS,
        STDOUT_FILENO,
    },
    sys::{
        signal,
        wait::{
            waitpid,
            WaitPidFlag,
            WaitStatus,
        },
    },
    unistd::{
        dup2,
        execv,
        fork,
        getgid,
        getuid,
        pipe,
        setpgid,
        setresgid,
        setresuid,
        ForkResult,
        Pid,
    },
};

use std::os::unix::io::{
    AsRawFd, 
    RawFd
};

#[cfg(feature = "with_askpass_support")]
use std::{
    convert::Infallible,
    env::var_os,
    ffi::CString,
    os::unix::ffi::OsStrExt,
    path::Path,
};

/**
 * 
 */
const MAX_INPUT_LEN: usize = 1024;

/**
 * 
 */
const PROMPT_SIGNALS: &[Signal] = &[
    Signal::SIGHUP,
    Signal::SIGINT,
    Signal::SIGQUIT,
    Signal::SIGTERM,
    Signal::SIGTSTP,
];

/**
 *
 */
#[cfg(feature = "with_askpass_support")]
const HELPER_SIGNALS: &[Signal] = &[
    Signal::SIGCHLD,
    Signal::SIGHUP,
    Signal::SIGINT,
    Signal::SIGQUIT,
    Signal::SIGTERM,
    Signal::SIGTSTP,
    Signal::SIGCONT,
];

/**
 *
 */
struct Prompt {
    input: RawFd,
    output: RawFd,
    interrupt: RawFd,
    owned: bool,
    termios: Option<Termios>,
    input_eof: bool,
}

impl Prompt {
    /**
     *
     */
    fn new(input: RawFd, output: RawFd, interrupt: RawFd, owned: bool) -> Self {
        Self {
            input,
            output,
            interrupt,
            owned,
            termios: None,
            input_eof: false
        }
    }

    /**
     *
     */
    fn hide_input(&mut self) -> Result<(), Error> {
        let original = tcgetattr(self.input)?;
        let mut changed = original.clone();

        changed.local_flags &= !(LocalFlags::ICANON | LocalFlags::ECHO);

        /*
        * Save the complete original state before attempting the change.  If
        * tcsetattr() partially affects a device before reporting failure,
        * Drop still attempts to restore it.
        */
        self.termios = Some(original);
        tcsetattr(self.input, SetArg::TCSANOW, &changed)?;

        Ok(())
    }

    /**
     *
     */
    #[allow(dead_code)]
    fn eof(&mut self) -> bool {
        return self.input_eof;
    }

    /**
     * 
     */
    fn write(&mut self, mut bytes: &[u8]) -> Result<(), Error> {
        while !bytes.is_empty() {
            match write(self.output, bytes) {
                Ok(0) => {
                    // Should not happen, if it fails then we should get an error instead
                    return Err(Error::StaticMessage("failed to write prompt"));
                }
                
                Ok(written) => {
                    bytes = &bytes[written..];
                }

                Err(Errno::EINTR) => continue,

                Err(error) => {
                    return Err(Error::from(error));
                }
            }
        }

        Ok(())
    }

    /**
     * 
     */
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Errno> {
        loop {
            let input = if self.input_eof {
                -1
            } else {
                self.input
            };

            let mut descriptors = [
                PollFd::new(self.interrupt, PollFlags::POLLIN),
                PollFd::new(input, PollFlags::POLLIN),
            ];

            match poll(&mut descriptors, -1) {
                Ok(_) => {}
                Err(Errno::EINTR) => continue,
                Err(error) => return Err(error),
            }

            let interrupt_events = descriptors[0].revents().unwrap_or(PollFlags::empty());

            if interrupt_events.contains(PollFlags::POLLIN) {
                return Err(Errno::EINTR);

            } else if interrupt_events.intersects(PollFlags::POLLERR | PollFlags::POLLHUP | PollFlags::POLLNVAL) {
                return Err(Errno::EIO);
            }

            if !self.input_eof {
                let input_events = descriptors[1].revents().unwrap_or(PollFlags::empty());

                if input_events.intersects(PollFlags::POLLIN | PollFlags::POLLHUP) {
                    let count = read(self.input, buf)?;

                    if count == 0 {
                        self.input_eof = true;
                    }

                    return Ok(count);

                } else if input_events.intersects(PollFlags::POLLERR | PollFlags::POLLNVAL) {
                    return Err(Errno::EIO);
                }
            }
        }
    }
}

impl Drop for Prompt {
    /**
     *
     */
    fn drop(&mut self) {
        if let Some(original) = self.termios.as_ref() {
            let _ = write(self.output, b"\n");
            let _ = tcsetattr(self.input, SetArg::TCSANOW, original);
        }

        if self.owned {
            if self.input != self.output {
                let _ = close(self.output);
            }

            let _ = close(self.input);
        }
    }
}

/**
 * 
 */
fn launch_prompt(msg: &str, flags: RunFlags) -> Result<String, Error> {
    /*
     * Rust drops locals in reverse order, so
     * Prompt restores the terminal before SignalHandler restores the old
     * signal actions.
     */
    let mut signals = SignalReceiver::install(PROMPT_SIGNALS.iter().copied())?;

    let use_stdin = (flags & RunFlags::AUTH_STDIN) != RunFlags::NONE;
    let hide = (flags & RunFlags::PROMPT_HIDE) != RunFlags::NONE;

    let (input, output, owned) = if use_stdin {
        (STDIN_FILENO, STDERR_FILENO, false)
    } else {
        match open(PATH_TTY, OFlag::O_RDWR, Mode::empty()) {
            Ok(fd) => (fd, fd, true),
            Err(_) => (STDIN_FILENO, STDERR_FILENO, false),
        }
    };

    let mut prompt = Prompt::new(input, output, signals.as_raw_fd(), owned);

    if !use_stdin {
        if hide {
            prompt.hide_input()?;
        }

        prompt.write(msg.as_bytes())?;

        // Not all PAM messages add a space at the end.
        if !msg.ends_with(' ') {
            prompt.write(b" ")?;
        }
    }

    /*
     * Zeroizing bounds the allocation and clears it on every return path.
     * overflow counts ignored bytes beyond the limit so backspace behaves
     * correctly without ever allowing the allocation to grow past the cap.
     */
    let mut buffer = Zeroizing::new(Vec::with_capacity(MAX_INPUT_LEN));
    let mut overflow = 0usize;
    let mut ch = [0u8; 1];

    loop {
        match prompt.read(&mut ch) {
            Ok(0) => break,

            Ok(_) => {
                if ch[0] == b'\r' || ch[0] == b'\n' {
                    break;

                } else if !use_stdin && hide && (ch[0] == 127 || ch[0] == 8) {
                    if overflow != 0 {
                        overflow -= 1;
                        let _ = prompt.write(b"\x08 \x08");

                    } else if buffer.pop().is_some() {
                        let _ = prompt.write(b"\x08 \x08");
                    }

                    continue;

                } else if buffer.len() < MAX_INPUT_LEN {
                    buffer.push(ch[0]);

                } else if overflow < usize::MAX {
                    overflow += 1;
                }

                if !use_stdin && hide {
                    let _ = prompt.write(b"*");
                }
            }

            Err(Errno::EINTR) => {
                let event = signals.read()?;

                if let Some(event) = event {
                    let signal = event
                        .signal().ok_or(Error::Message(
                            format!("invalid signal number {}", Errno::EINVAL)
                        ))?;

                    return Err(Error::Interrupted(signal));
                }
            }

            Err(error) => {
                return Err(Error::from(error));
            }
        }
    }

    if overflow != 0 {
        return Err(Error::Message(
            format!("input exceeds the maximum length of {} bytes", MAX_INPUT_LEN)
        ));
    }

    let password = std::str::from_utf8(buffer.as_slice())?.to_owned();

    Ok(password)
}

/**
 * 
 */
#[cfg(feature = "with_askpass_support")]
fn launch_helper(msg: &str) -> Result<String, Error> {
    let (passwd_read, passwd_write) = pipe()?;
    let sync = ForkSync::new()?;

    match unsafe { fork() } {
        Ok(ForkResult::Child) => {
            let Err(err) = (|| -> Result<Infallible, Error> {
                // Child never reads from this pipe.
                close(passwd_read)?;

                if passwd_write != STDOUT_FILENO {
                    dup2(passwd_write, STDOUT_FILENO)?;
                    close(passwd_write)?;
                }

                // child should not have access to the Runas stdin
                let null_fd = open("/dev/null", OFlag::O_RDONLY, Mode::empty())?;

                if null_fd != STDIN_FILENO {
                    dup2(null_fd, STDIN_FILENO)?;
                    close(null_fd)?;
                }

                let uid = getuid();
                let gid = getgid();

                // Lower the privileges from the setuid
                setresgid(gid, gid, gid)?;
                setresuid(uid, uid, uid)?;

                set_parent_exit_signal(Signal::SIGKILL)?;

                let sync = sync.into_child();

                if sync.ready_and_wait()? != SyncDecision::Continue {
                    return Err(Error::Unknown);
                }

                // Do not allow further privilege to be set by setuid etc. on the target binary
                Errno::result(unsafe {
                    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
                })?;

                let helper = var_os("RUNAS_ASKPASS")
                    .filter(|value| !value.is_empty())
                    .or_else(|| {
                        var_os("SUDO_ASKPASS")
                            .filter(|value| !value.is_empty())
                    })
                    .ok_or(Error::StaticMessage(
                        "RUNAS_ASKPASS is configured",
                    ))?;

                clean_environment();

                if !Path::new(&helper).is_absolute() {
                    return Err(Error::StaticMessage(
                        "RUNAS_ASKPASS must contain an absolute path"
                    ));
                }

                let helper = CString::new(helper.as_os_str().as_bytes())?;
                let prompt = CString::new(msg)?;

                let argv = [
                    helper.clone(),
                    prompt,
                ];

                return execv(&helper, &argv).map_err(Error::from);

            })();

            eprintln!("{}", err);
            std::process::exit(1);
        }

        Ok(ForkResult::Parent { child }) => {
            // Parent never writes to this pipe.
            close(passwd_write)?;
            setpgid(child, child)?;

            let mut signals = SignalReceiver::install(HELPER_SIGNALS.iter().copied())?;
            let mut prompt = Prompt::new(
                passwd_read,
                passwd_read, // unused 
                signals.as_raw_fd(),
                true,
            );

            let sync = sync.into_parent();

            if sync.ready_and_wait()? != SyncDecision::Continue {
                return Err(Error::StaticMessage(
                    "askpass helper failed during startup"
                ));
            }

            let mut buffer = Zeroizing::new(Vec::with_capacity(MAX_INPUT_LEN));
            let mut chunk = Zeroizing::new([0u8; 128]);
            let mut overflow = false;
            let mut child_status: Option<i32> = None;

            let flags = WaitPidFlag::WUNTRACED | WaitPidFlag::WCONTINUED | WaitPidFlag::WNOHANG;

            loop {
                match prompt.read(&mut chunk[..]) {
                    // Wait for child to exit
                    Ok(0) => {},

                    Ok(count) => {
                        let remaining = (MAX_INPUT_LEN + 1).saturating_sub(buffer.len());
                        let accepted = count.min(remaining);

                        buffer.extend_from_slice(&chunk[..accepted]);

                        if accepted != count {
                            overflow = true;
                        }
                    }

                    Err(Errno::EINTR) => {
                        let Some(event) = signals.read()? else {
                            continue;
                        };

                        let signal = event.signal().ok_or_else(|| {
                            Error::Message(format!(
                                "invalid signal number {}",
                                event.raw_signal()
                            ))
                        })?;

                        if signal == Signal::SIGCHLD {
                            loop {
                                match waitpid(child, Some(flags)) {
                                    Ok(WaitStatus::Exited(_, code)) => {
                                        child_status = Some(code);
                                        break;
                                    }

                                    Ok(WaitStatus::Signaled(_, sig, _)) => {
                                        child_status = Some(128 + sig as i32);
                                        break;
                                    }
                                    
                                    Ok(WaitStatus::StillAlive) => break,
                                    Ok(_) => continue,

                                    Err(Errno::EINTR) => continue,
                                    Err(error) => return Err(Error::from(error))
                                }
                            }

                        } else {
                            let _ = signal::kill(Pid::from_raw(-child.as_raw()), signal);
                        }
                    }

                    Err(error) => {
                        return Err(Error::from(error));
                    }
                }

                if prompt.eof() && child_status.is_some() {
                    break;
                }
            }

            let status = child_status.ok_or(Error::StaticMessage("askpass helper status is unavailable"))?;

            if status != 0 {
                return Err(Error::Message(
                    format!("askpass helper exited with status {}", status)
                ));
            }

            if buffer.last() == Some(&b'\n') {
                buffer.pop();

                if buffer.last() == Some(&b'\r') {
                    buffer.pop();
                }
            }

            if overflow || buffer.len() > MAX_INPUT_LEN {
                return Err(Error::Message(
                    format!("input exceeds the maximum length of {} bytes", MAX_INPUT_LEN)
                ));
            }
            
            return Ok(std::str::from_utf8(&buffer)?.to_owned());
        }

        Err(err) => {
            return Err(Error::from(err));
        }
    }
}

/**
 * Compare two strings in constant time.
 *
 * This function ensures consistent runtime regardless of input similarity
 * or mismatch position, mitigating timing side-channel attacks.
 *
 * - Compares byte-by-byte without early exit.
 * - Performs XOR over both byte arrays.
 * - Pads comparisons with inverted bytes if the second string is shorter,
 *   to avoid leaking password length through timing.
 *
 * The order of these arguments mater. Every operation is based on the 
 * known string. Any timing attempt will only ever time against the known
 * string, revealing nothing about the secret string. 
 *
 * Returns `true` if both strings are identical, `false` otherwise.
 */
#[cfg(not(feature = "use_pam"))]
pub(crate) fn time_compare(known: &str, secret: &str) -> bool {
    let     buff_known:  &[u8]   = known.as_bytes();
    let     buff_secret: &[u8]   = secret.as_bytes();
    let     known_len:   usize   = buff_known.len();
    let     secret_len:  usize   = buff_secret.len();
    let mut result:      usize   = known_len ^ secret_len; // Immediate fail if length differ
    let mut buff_inv:    Vec<u8> = vec![0u8; known_len];
    
    // Invert the 'known' password so that it does not match against itself.
    // If 'secret' password is shorter than the 'known' password, 
    // we start matching against itself. This avoids timing attacks that could be able
    // to detect the correct password length. 
    // We always loop against the 'known' password and always to the end.
    for i in 0..known_len {
        buff_inv[i] = !(buff_known[i]);
    }
    
    // Compare the two passwords one character at a time. 
    // We don't stop, even if a mismatch is found. Password match
    // will always use time that equals the length of the 'self' password.
    for i in 0..known_len {
        result |= if i >= secret_len {
            buff_known[i] ^ buff_inv[i]
        } else {
            buff_known[i] ^ buff_secret[i]
        } as usize
    }
    
    return result == 0;
}

/**
 * Prompt the user for a password securely.
 *
 * Displays a message on the terminal or reads from
 * standard input if `RunFlags::AUTH_STDIN` is set.
 *
 * - Disables terminal echo and canonical mode while reading input.
 * - Supports backspace and overwriting behavior.
 * - Restores terminal flags to their previous state on exit.
 * - Returns the collected password as a UTF-8 `String`.
 *
 * # Parameters
 * - `msg`: Prompt message displayed to the user.
 * - `flags`: Behavior control flags (`RunFlags::AUTH_STDIN`, etc.).
 */
pub(crate) fn ask_password(msg: &str, flags: RunFlags) -> Result<String, Error> {
    #[cfg(feature = "with_askpass_support")]
    if flags.contains(RunFlags::AUTH_ASKPASS) {
        return launch_helper(msg);
    }

    loop {
        match launch_prompt(msg, flags) {
            Ok(password) => return Ok(password),

            Err(Error::Interrupted(signal)) => {
                /*
                * If SIGTSTP stops the process, retry the prompt after SIGCONT.
                * If another signal was ignored or handled by the caller,
                * retry as well.  Signals with their default terminating action
                * do not return from raise().
                */
                let _ = raise(signal);
            }

            Err(error) => {
                return Err(error);
            }
        }
    }
}
