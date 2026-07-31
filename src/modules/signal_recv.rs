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
 * Thread-local signal reception through Linux signalfd.
 *
 * `SignalReceiver` blocks a caller-selected set of signals on the creating
 * thread and makes those signals available through a nonblocking file
 * descriptor. The descriptor can be used in an external `poll()` loop, or the
 * convenience methods in this module can wait for and drain pending signals.
 *
 * The receiver must be created after `fork()` when a future child must not
 * inherit the blocked signal mask. It must also remain on its creating thread.
 *
 * Ordinary Unix signals are not a lossless message protocol. Multiple pending
 * instances of the same non-real-time signal may be coalesced by the kernel.
 * Different pending signals remain individually readable.
 */

use std::{
    convert::TryFrom,
    marker::PhantomData,
    rc::Rc,
    os::{
        fd::{
            AsRawFd,
            RawFd
        }
    }
};
use nix::{
    errno::Errno,
    Result as NixResult,
    poll::{
        poll,
        PollFd,
        PollFlags
    },
    sys::{
        signal::{
            pthread_sigmask,
            SigSet,
            SigmaskHow,
            Signal
        },
        signalfd::{
            SignalFd,
            siginfo,
            SfdFlags
        }
    }
};

/**
 * One signal record read from the kernel.
 *
 * The raw `signalfd_siginfo` record is retained so callers can inspect fields
 * specific to signals such as `SIGCHLD`.
 */
pub struct SignalEvent {
    info: siginfo,
}

impl SignalEvent {
    /**
     * Return the signal number as reported by the kernel.
     */
    pub fn raw_signal(&self) -> i32 {
        self.info.ssi_signo as i32
    }

    /**
     * Convert the signal number to nix's `Signal` representation.
     */
    pub fn signal(&self) -> Option<Signal> {
        Signal::try_from(self.raw_signal()).ok()
    }

    /**
     * Return the signal-specific status field.
     *
     * For `SIGCHLD`, this contains the child's exit status or signal.
     * `waitpid()` must still be used to consume and authoritatively classify
     * the child state change.
     */
    #[allow(dead_code)]
    pub fn status(&self) -> i32 {
        self.info.ssi_status
    }

    /**
     * Return the kernel signal code.
     */
    #[allow(dead_code)]
    pub fn code(&self) -> i32 {
        self.info.ssi_code
    }
}

/**
 * A caller-configurable signalfd and its associated thread signal mask.
 *
 * Construction blocks the selected signals and saves the previous mask.
 * Dropping the receiver restores that exact previous mask.
 */
pub struct SignalReceiver {
    fd: SignalFd,
    prev_mask: SigSet,
    _thread_bound: PhantomData<Rc<()>>,
}

impl SignalReceiver {
    /**
     * Block `signals` on the current thread and create a nonblocking,
     * close-on-exec signalfd for them.
     *
     * `SIGKILL` and `SIGSTOP` cannot be blocked and are rejected.
     */
    pub fn install<I>(signals: I) -> NixResult<Self>
    where
        I: IntoIterator<Item = Signal>,
    {
        let mut mask = SigSet::empty();
        let mut prev_mask = SigSet::empty();

        for signal in signals {
            if signal == Signal::SIGKILL || signal == Signal::SIGSTOP {
                return Err(Errno::EINVAL);
            }

            mask.add(signal);
        }

        pthread_sigmask(
            SigmaskHow::SIG_BLOCK,
            Some(&mask),
            Some(&mut prev_mask),
        )?;

        let fd = match SignalFd::with_flags(&mask, SfdFlags::SFD_CLOEXEC | SfdFlags::SFD_NONBLOCK) {
            Ok(fd) => fd,
            Err(err) => {
                /*
                 * Self was not constructed, so Drop cannot restore the mask.
                 */
                let _ = pthread_sigmask(SigmaskHow::SIG_SETMASK, Some(&prev_mask), None);

                return Err(err);
            }
        };

        Ok(Self {
            fd,
            prev_mask,
            _thread_bound: PhantomData,
        })
    }

    /**
     * Read the oldest currently pending signal.
     *
     * `None` means no selected signal is pending. This method never blocks.
     */
    pub fn read(&mut self) -> NixResult<Option<SignalEvent>> {
        self.fd
            .read_signal()
            .map(|event| event.map(|info| SignalEvent { info }))
    }

    /**
     * Wait until at least one selected signal is available, then read it.
     *
     * Unblocked signals may interrupt `poll()`. Interrupted waits are retried.
     */
    #[allow(dead_code)]
    pub fn wait(&mut self) -> NixResult<SignalEvent> {
        loop {
            if let Some(event) = self.read()? {
                return Ok(event);
            }

            let mut descriptors = [
                PollFd::new(self.as_raw_fd(), PollFlags::POLLIN)
            ];

            match poll(&mut descriptors, -1) {
                Ok(_) => {}
                Err(Errno::EINTR) => continue,
                Err(err) => return Err(err),
            }

            let events = descriptors[0]
                .revents()
                .ok_or(Errno::EIO)?;

            if events.intersects(PollFlags::POLLERR | PollFlags::POLLHUP) {
                return Err(Errno::EIO);

            } else if events.contains(PollFlags::POLLNVAL) {
                return Err(Errno::EBADF);
            }
        }
    }
}

impl AsRawFd for SignalReceiver {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl Drop for SignalReceiver {
    fn drop(&mut self) {
        let _ = pthread_sigmask(SigmaskHow::SIG_SETMASK, Some(&self.prev_mask), None);
    }
}
