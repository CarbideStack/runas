// Copyright (c) 2026 Daniel Bergløv
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

/*!
 * Foreground terminal ownership for a supervised process group.
 *
 * `ForegroundHandler` gives the child process group control of the invoking
 * terminal and restores the original foreground process group when dropped.
 * It also ignores `SIGTTOU` while active so a background supervisor can call
 * `tcsetpgrp()` without being stopped by the terminal driver.
 */

use std::io;
use std::os::fd::{AsRawFd, RawFd};

use nix::sys::signal::{
    self,
    SaFlags,
    SigAction,
    SigHandler,
    SigSet,
    Signal,
};

use nix::unistd::{
    tcgetpgrp,
    tcsetpgrp,
    Pid,
};

/**
 * Owns foreground-terminal state for one supervised child process group.
 */
pub(crate) struct ForegroundHandler {
    prev_sigttou: SigAction,
    foreground_group: Option<(RawFd, Pid, Pid)>,
}

impl ForegroundHandler {
    /**
     * Ignore `SIGTTOU` and give the terminal to `child`.
     *
     * Failure to inspect or transfer the terminal is not fatal. This permits
     * use when stdin is not a controlling terminal. Failure to install the
     * `SIGTTOU` disposition is returned to the caller.
     */
    pub(crate) fn install(child: Pid) -> nix::Result<Self> {
        let ignore = SigAction::new(
            SigHandler::SigIgn,
            SaFlags::empty(),
            SigSet::empty(),
        );

        let prev_sigttou = unsafe {
            signal::sigaction(Signal::SIGTTOU, &ignore)?
        };

        let terminal = io::stdin().as_raw_fd();
        let foreground_group = tcgetpgrp(terminal).ok().and_then(|original| {
            tcsetpgrp(terminal, child)
                .ok()
                .map(|_| (terminal, original, child))
        });

        Ok(Self {
            prev_sigttou,
            foreground_group,
        })
    }

    /**
     * Give the terminal back to the process group that originally owned it.
     */
    pub(crate) fn transfer_to_parent(&self) {
        if let Some((terminal, original, _)) = self.foreground_group {
            let _ = tcsetpgrp(terminal, original);
        }
    }

    /**
     * Give the terminal to the supervised child process group.
     */
    pub(crate) fn transfer_to_child(&self) {
        if let Some((terminal, _, child)) = self.foreground_group {
            let _ = tcsetpgrp(terminal, child);
        }
    }
}

impl Drop for ForegroundHandler {
    /**
     * Restore terminal ownership before restoring the `SIGTTOU` disposition.
     */
    fn drop(&mut self) {
        self.transfer_to_parent();

        let _ = unsafe {
            signal::sigaction(Signal::SIGTTOU, &self.prev_sigttou)
        };
    }
}
