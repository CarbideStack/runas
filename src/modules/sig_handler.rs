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

use std::os::fd::AsRawFd;
use std::os::raw::c_int;
use std::io;

use std::sync::atomic::{
    AtomicI32, 
    Ordering
};

use nix::unistd::{
    tcgetpgrp,
    tcsetpgrp,
    Pid
};

use nix::sys::signal::{
    self, 
    Signal,
    SigSet,
    SigHandler,
    SigAction,
    SaFlags
};

/**
 * 
 */
static CAUGHT_SIGNAL: AtomicI32 = AtomicI32::new(0);

/**
 * 
 */
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
extern "C" fn catch_signal(signum: c_int) {
    CAUGHT_SIGNAL.store(signum, Ordering::SeqCst);
}

/**
 * 
 */
pub struct SignalHandler {
    actions: Vec<(Signal, SigAction)>,
    foreground_group: Option<(i32, Pid, Pid)>,
}

impl SignalHandler {
    /**
     * 
     */
    pub fn forward_signal(group: Pid) -> Option<Signal> {
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
    pub fn install(child: Pid) -> nix::Result<Self> {
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
    pub fn transfer_to_parent(&self) {
        if let Some((terminal, original, _)) = self.foreground_group {
            let _ = tcsetpgrp(terminal, original);
        }
    }

    /**
     * 
     */
    pub fn transfer_to_child(&self) {
        if let Some((terminal, _, child)) = self.foreground_group {
            let _ = tcsetpgrp(terminal, child);
        }
    }
}

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
