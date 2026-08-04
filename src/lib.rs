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

pub mod shared;

mod ffi {
    #[cfg(not(feature = "use_pam"))]
    pub mod shadow;

    #[cfg(feature = "use_pam")]
    pub mod pam;
}

pub mod modules {
    pub mod error;
    pub mod user;
    pub mod auth;
    pub mod proc;
    pub mod env;

    pub(crate) mod passwd;
    pub(crate) mod signal_recv;

    #[cfg(any(
        all(feature = "backend_scopex", feature = "use_pam"), 
        feature = "with_askpass_support"
    ))]
    pub(crate) mod fork_sync;

    #[cfg(all(feature = "backend_scopex", feature = "use_pam"))]
    pub(crate) mod fg_handler;
}

#[cfg(all(feature = "backend_run0", feature = "backend_scopex"))]
compile_error!("You cannot combine the features 'backend_run0' and 'backend_scopex'");

#[cfg(all(feature = "backend_run0", feature = "without_expand_env"))]
compile_error!("The feature 'without_expand_env' does not work with the 'backend_run0' feature");

#[cfg(all(feature = "backend_scopex", feature = "without_expand_env"))]
compile_error!("The feature 'without_expand_env' does not work with the 'backend_scopex' feature");
