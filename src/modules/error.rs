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

#[cfg(feature = "use_pam")]
use crate::ffi::pam::PamError;

use nix::{
    errno::Errno,
    sys::signal::Signal
};
use std::{
    fmt::{
        Display,
        Result as FmtResult
    },
    error::Error as IError,
    ffi::NulError,
    io::Error as IOError,
    str::Utf8Error,
    num::ParseIntError
};

/**
 *
 */
#[derive(Debug)]
pub enum Error {
    Unknown,
    Message(String),
    StaticMessage(&'static str),
    Errno(Errno),
    Io(IOError),
    Nul(NulError),
    InvalidUtf8(Utf8Error),
    Interrupted(Signal),
    ParseInt(ParseIntError),

    #[cfg(feature = "use_pam")]
    Pam(PamError),

    #[cfg(feature = "use_pam")]
    PamActionRequired(PamError),
}

/**
 *
 */
impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> FmtResult {
        match self {
            Self::Unknown                                 => write!(f, "unknown error"),
            Self::Message(msg)                            => write!(f, "{}", msg),
            Self::StaticMessage(msg)                      => write!(f, "{}", msg),
            Self::Errno(err)                              => write!(f, "system error: {err}"),
            Self::Io(err)                                 => write!(f, "I/O error: {}", err),
            Self::Nul(err)                                => write!(f, "invalid C string: {}", err),
            Self::InvalidUtf8(err)                        => write!(f, "invalid UTF-8: {}", err),
            Self::ParseInt(err)                           => write!(f, "parse error {}", err),
            Self::Interrupted(signal)                     => write!(f, "interrupted by {}", signal),

            #[cfg(feature = "use_pam")]
            Self::Pam(err) | Self::PamActionRequired(err) => {
                write!(f, "PAM: {}", err.message())
            }
        }
    }
}

/**
 *
 */
impl IError for Error {}

/**
 *
 */
impl From<ParseIntError> for Error {
    fn from(err: ParseIntError) -> Self {
        Error::ParseInt(err)
    }
}

/**
 *
 */
impl From<Signal> for Error {
    fn from(signal: Signal) -> Self {
        Error::Interrupted(signal)
    }
}

/**
 *
 */
impl From<Errno> for Error {
    fn from(err: Errno) -> Self {
        Error::Errno(err)
    }
}

/**
 *
 */
impl From<&str> for Error {
    fn from(msg: &str) -> Self {
        Error::Message(msg.to_owned())
    }
}

/**
 *
 */
impl From<String> for Error {
    fn from(msg: String) -> Self {
        Error::Message(msg)
    }
}

/**
 *
 */
impl From<IOError> for Error {
    fn from(err: IOError) -> Self {
        Error::Io(err)
    }
}

/**
 *
 */
impl From<NulError> for Error {
    fn from(err: NulError) -> Self {
        Error::Nul(err)
    }
}

/**
 *
 */
impl From<Utf8Error> for Error {
    fn from(err: Utf8Error) -> Self {
        Error::InvalidUtf8(err)
    }
}

/**
 *
 */
#[cfg(feature = "use_pam")]
impl From<PamError> for Error {
    fn from(err: PamError) -> Self {
        Error::Pam(err)
    }
}
