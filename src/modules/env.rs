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

use super::{
    error::Error,
    user::Account
};
use std::{
    path::Path,
    fs::File,
    os::unix::fs::MetadataExt,
    collections::{
        HashMap,
        HashSet
    },
    sync::LazyLock,
    io::{
        ErrorKind::NotFound,
        BufRead,
        BufReader
    },
    env::{
        vars as env_vars,
        remove_var as env_remove_var
    }
};

/**
 *
 */
static ENV_VARS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    HashSet::from([
        "PATH",
        "LANG",
        "PWD",
        "TERM",
        "COLORTERM",
        "DISPLAY",
        "WAYLAND_DISPLAY",
        "XAUTHORITY",
        "DBUS_SESSION_BUS_ADDRESS",
        "SSH_AUTH_SOCK",
    ])
});

/**
 *
 */
pub fn clean_environment() {
    for (key, _) in env_vars() {
        if ENV_VARS.contains(key.as_str())
            || key.starts_with("LC_")
            || key.starts_with("XDG_")
        {
            continue;
        }

        unsafe {
            env_remove_var(&key);
        }
    }
}

/**
 *
 */
#[cfg(feature = "backend_scopex")]
pub fn set_environment(
    target: &Account, 
    env: &mut HashMap<String, String>
) {
    env.entry("HOME".to_owned())
        .or_insert_with(|| target.home().to_owned());

    env.entry("USER".to_owned())
        .or_insert_with(|| target.name().to_owned());

    env.entry("LOGNAME".to_owned())
        .or_insert_with(|| target.name().to_owned());

    env.entry("SHELL".to_owned())
        .or_insert_with(|| target.shell().to_owned());

    for (key, value) in env_vars() {
        if ENV_VARS.contains(key.as_str())
            || key.starts_with("LC_")
        {
            env.entry(key).or_insert(value);
        }
    }
}

/**
 * Add or override environment variables from the file '/etc/runas.env'. 
 *
 * The structure of the file is as follows:
 *      USER NAME=VALUE
 *
 * This will set the environment NAME=VALUE when target user matches USER. 
 * Multiple variables can be set for multiple users, one variable per line.
 */
pub fn load_overwrite_vars<P, T>(
    path: P,
    target: &Account,
    placeholders: Option<&[(&str, T)]>,
    env: &mut HashMap<String, String>,
) -> Result<(), Error>
where
    P: AsRef<Path>,
    T: AsRef<str>,
{
    let file = match File::open(path) {
        Ok(f) => f,

        Err(e) if e.kind() == NotFound => {
            return Ok(());
        }

        Err(e) => return Err(e.into()),
    };

    // Validate permissions/ownership
    {
        let meta = file.metadata()?;

        // Must be owned by root
        if meta.uid() != 0 {
            return Err(Error::StaticMessage(
                "ignoring environment override file: not owned by root",
            ));
        }

        // Must not be group/world writable
        if meta.mode() & 0o022 != 0 {
            return Err(Error::StaticMessage(
                "ignoring environment override file: writable by group or others",
            ));
        }
    }

    let reader = BufReader::new(file);

    for line in reader.lines() {
        let line = line?;
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let mut parts = line.splitn(2, char::is_whitespace);

        let name = match parts.next() {
            Some(v) => v,
            None => continue,
        };

        if name != "*" && name != target.name() {
            continue;
        }

        let val = match parts.next() {
            Some(v) => v.trim_start(),
            None => continue,
        };

        // Validate VAR=VALUE format
        let (key, value) = match val.split_once('=') {
            Some((k, v)) => (k.trim(), v.trim()),
            None => continue,
        };

        // Validate environment variable name
        if key.is_empty() {
            continue;
        }

        if !key.bytes().enumerate().all(|(i, b)| match b {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'_' => true,

            b'0'..=b'9' => i != 0,

            _ => false,
        }) {
            continue;
        }

        if env.contains_key(key) {
            continue;
        }

        let mut value = value.to_owned();

        if let Some(placeholders) = placeholders {
            for (name, replacement) in placeholders {
                value = value.replace(
                    &format!("${{{}}}", name),
                    replacement.as_ref(),
                );
            }
        }

        env.insert(key.to_owned(), value);
    }

    Ok(())
}
