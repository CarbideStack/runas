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

use std::{
    os::unix::fs::PermissionsExt,
    ffi::CString,
    env::{
        var as env_var,
    },
    fs::{
        canonicalize,
        metadata
    },
    path::{
        Path, 
        PathBuf
    },
    io::{
        Result as IOResult,
        Error as IOError,
        ErrorKind,
    }
};

use libc::{
    ENOTDIR,
    EACCES,
    ENOENT
};

/**
 *
 */
pub(crate) fn find_executable(cmd: &str, extra_envp: &[CString]) -> IOResult<PathBuf> {
    let path = Path::new(cmd);

    // Case 1: already absolute
    if path.is_absolute() {
        return inspect_candidate(path).map(|_| path.to_path_buf());
    }

    // Case 2: relative (contains /)
    if cmd.contains('/') {
        return match canonicalize(path) {
            Ok(full) => inspect_candidate(&full).map(|_| full),
            Err(err) => Err(err),
        };
    }

    let mut permission_denied = false;

    // Case 3: search in current PATH
    if let Ok(path_var) = env_var("PATH") {
        match search_path_var(cmd, &path_var) {
            Ok(found) => return Ok(found),
            Err(err) => {
                if err.kind() == ErrorKind::PermissionDenied {
                    permission_denied = true;

                } else if err.kind() != ErrorKind::NotFound
                        && err.raw_os_error() != Some(ENOTDIR) {

                    return Err(err);
                }
            }
        }
    }

    // Case 4: search any PATH= in provided envp
    for entry in extra_envp.iter().rev() {
        let Ok(entry) = entry.to_str() else {
            continue;
        };

        let Some(path_var) = entry.strip_prefix("PATH=") else {
            continue;
        };

        match search_path_var(cmd, path_var) {
            Ok(found) => return Ok(found),
            Err(err) => {
                if err.kind() == ErrorKind::PermissionDenied {
                    permission_denied = true;

                } else if err.kind() != ErrorKind::NotFound
                        && err.raw_os_error() != Some(ENOTDIR) {

                    return Err(err);
                }
            }
        }
    }

    // Case 5: missing or permission denied
    if permission_denied {
        Err(IOError::from_raw_os_error(EACCES))

    } else {
        Err(IOError::from_raw_os_error(ENOENT))
    }
}

/**
 *
 */
fn search_path_var(cmd: &str, path_var: &str) -> IOResult<PathBuf> {
    let mut permission_denied = false;

    for dir in path_var.split(':') {
        if dir.is_empty() {
            continue;
        }

        let candidate = Path::new(dir).join(cmd);

        match inspect_candidate(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(err) => {
                if err.kind() == ErrorKind::PermissionDenied {
                    permission_denied = true;

                } else if err.kind() != ErrorKind::NotFound
                        && err.raw_os_error() != Some(ENOTDIR) {

                    return Err(err);
                }
            }
        }
    }

    if permission_denied {
        Err(IOError::from_raw_os_error(EACCES))

    } else {
        Err(IOError::from_raw_os_error(ENOENT))
    }
}

/**
 *
 */
fn inspect_candidate(path: &Path) -> IOResult<()> {
    let metadata = metadata(path)?;

    if !metadata.is_file() {
        return Err(IOError::from_raw_os_error(EACCES));

    } else if metadata.permissions().mode() & 0o111 == 0 {
        return Err(IOError::from_raw_os_error(EACCES));
    }

    Ok(())
}
