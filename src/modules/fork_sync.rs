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
 * Small synchronization primitive for coordinating the two sides of fork().
 *
 * ForkSync creates two close-on-exec pipes before the fork:
 *
 * - one pipe for child-to-parent status;
 * - one pipe for parent-to-child status.
 *
 * Each side either reports failure or reports readiness and waits for the
 * other side to become ready. If either side exits or drops its endpoint
 * first, the peer observes EOF and aborts.
 */

use std::os::unix::io::RawFd;
use nix::{
    errno::Errno,
    Result as NixResult,
    fcntl::OFlag,
    unistd::{
        close, 
        pipe2, 
        read, 
        write
    }
};

const STATUS_READY: u8 = 1;
const STATUS_FAILED: u8 = 2;

/**
 * An owned pipe descriptor.
 *
 * The descriptor is closed automatically when this value is dropped.
 */
struct Descriptor {
    raw: RawFd,
}

impl Descriptor {
    /**
     * Create the read and write descriptors for one close-on-exec pipe.
     */
    fn pipe() -> NixResult<(Self, Self)> {
        let (read, write) = pipe2(OFlag::O_CLOEXEC)?;

        Ok((Self { raw: read }, Self { raw: write }))
    }

    /**
     * Write one protocol byte, retrying interrupted operations.
     */
    fn write_byte(&self, value: u8) -> NixResult<()> {
        loop {
            match write(self.raw, &[value]) {
                Ok(1) => return Ok(()),
                Ok(_) => return Err(Errno::EIO),
                Err(Errno::EINTR) => continue,
                Err(error) => return Err(error),
            }
        }
    }

    /**
     * Read one protocol byte, retrying interrupted operations.
     *
     * None indicates that the other side closed the pipe.
     */
    fn read_byte(&self) -> NixResult<Option<u8>> {
        let mut value = [0u8; 1];

        loop {
            match read(self.raw, &mut value) {
                Ok(0) => return Ok(None),
                Ok(1) => return Ok(Some(value[0])),
                Ok(_) => return Err(Errno::EIO),
                Err(Errno::EINTR) => continue,
                Err(error) => return Err(error),
            }
        }
    }
}

impl Drop for Descriptor {
    fn drop(&mut self) {
        let _ = close(self.raw);
    }
}

/**
 * The result of waiting for the other side of the fork.
 */
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SyncDecision {
    Continue,
    Abort,
}

/**
 * Pipe endpoints created before fork().
 *
 * Consume this value with into_child() in the child and into_parent() in the
 * parent. Each method closes the endpoints belonging to the other side.
 */
pub(crate) struct ForkSync {
    child_write: Option<Descriptor>,
    child_read: Option<Descriptor>,
    parent_write: Option<Descriptor>,
    parent_read: Option<Descriptor>,
}

impl ForkSync {
    /**
     * Create a new synchronization pair.
     */
    pub(crate) fn new() -> NixResult<Self> {
        let (parent_read, child_write) = Descriptor::pipe()?;
        let (child_read, parent_write) = Descriptor::pipe()?;

        Ok(Self {
            child_write: Some(child_write),
            child_read: Some(child_read),
            parent_write: Some(parent_write),
            parent_read: Some(parent_read),
        })
    }

    /**
     * Convert the inherited endpoints into the child side.
     */
    pub(crate) fn into_child(mut self) -> ForkEndpoint {
        drop(self.parent_read.take());
        drop(self.parent_write.take());

        ForkEndpoint {
            write: self.child_write.take(),
            read: self.child_read.take(),
            status_sent: false,
        }
    }

    /**
     * Convert the inherited endpoints into the parent side.
     */
    pub(crate) fn into_parent(mut self) -> ForkEndpoint {
        drop(self.child_write.take());
        drop(self.child_read.take());

        ForkEndpoint {
            read: self.parent_read.take(),
            write: self.parent_write.take(),
            status_sent: false,
        }
    }
}

/**
 * One side of the fork synchronization barrier.
 */
pub(crate) struct ForkEndpoint {
    write: Option<Descriptor>,
    read: Option<Descriptor>,
    status_sent: bool,
}

impl ForkEndpoint {
    /**
     * Report successful initialization and wait for the peer.
     */
    pub(crate) fn ready_and_wait(mut self) -> NixResult<SyncDecision> {
        self.send_status(STATUS_READY)?;

        let decision = match self.read.as_ref().ok_or(Errno::EBADF)?.read_byte()? {
            Some(STATUS_READY) => SyncDecision::Continue,
            Some(STATUS_FAILED) | None => SyncDecision::Abort,
            Some(_) => return Err(Errno::EPROTO),
        };

        drop(self.read.take());
        Ok(decision)
    }

    /**
     * Report failed initialization.
     *
     * The caller decides how its side should terminate after reporting the
     * failure. Dropping this endpoint closes all remaining descriptors.
     */
    #[allow(dead_code)]
    pub(crate) fn report_failure(mut self) -> NixResult<()> {
        self.send_status(STATUS_FAILED)
    }

    /**
     * 
     */
    fn send_status(&mut self, status: u8) -> NixResult<()> {
        if self.status_sent {
            return Err(Errno::EALREADY);
        }

        self.write
            .as_ref()
            .ok_or(Errno::EBADF)?
            .write_byte(status)?;
        self.status_sent = true;
        drop(self.write.take());
        Ok(())
    }
}
