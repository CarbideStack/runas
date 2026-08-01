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
 * runas — A systemd-integrated privilege and user switching utility.
 *
 * This program is a secure, minimal replacement for classic `sudo`-style tools.
 * It performs user authentication and delegates the final process execution to
 * `systemd-run`, taking advantage of systemd’s service supervision, cgroup isolation,
 * and clean environment handling. 
 *
 * Unlike traditional privilege tools, `runas` does not execute processes directly.
 * After verifying authentication (via PAM or a custom backend), it constructs a
 * complete `systemd-run` command line and replaces itself with that process
 * using `execvp()`. This makes `runas` stateless after delegation, and ensures
 * that all executed commands are systemd-managed.
 *
 * The binary must run setuid-root, like `sudo`, since it temporarily raises privileges
 * to change UID before delegating to `systemd-run`. It does **not** maintain any root
 * privileges after exec; the invoked process is fully isolated in its own transient
 * systemd service.
 *
 * ### Command Flow
 * ```
 * runas  →  authenticate()  →  build argv  →  execvp("systemd-run", ...)
 * ```
 */

#[macro_use]
extern crate runas;

use runas::{
    modules::{
        error::Error,
        proc::exec,
        env::load_overwrite_vars,
        auth::authenticate,
        user::{
            Group, 
            Account
        },
    },
    shared::*
};

#[cfg(feature = "backend_scopex")]
use runas::modules::env::set_environment;

use nix::unistd::Uid as CUid;

use std::{
    ffi::CString,
    collections::HashMap,
    env::{
        args as env_args,
        var as env_var
    }
};

#[cfg(feature = "backend_scopex")]
use std::path::Path;

#[cfg(not(feature = "backend_scopex"))]
use std::{
    io::{
        IsTerminal,
        stdout,
        stderr,
        stdin
    }
};

#[cfg(feature = "backend_run0")]
use std::{
    env::current_dir as env_current_dir,
    path::PathBuf,
    os::unix::ffi::OsStrExt
};

use getopts::{
    Options,
    Matches
};

/**
 * A structure to store available options
 */
#[derive(PartialEq, Eq)]
struct CliOption {
    flag: &'static str,
    name: &'static str,
    desc: &'static str,
    val:  &'static str
}

const OPT_USER     : CliOption  =  CliOption { flag: "u",   name: "user",            desc: "Run process as the specified user name or ID",      val: "USER"  };
const OPT_GROUP    : CliOption  =  CliOption { flag: "g",   name: "group",           desc: "Run process as the specified group name or ID",     val: "GROUP" };
const OPT_SHELL    : CliOption  =  CliOption { flag: "s",   name: "shell",           desc: "Run $SHELL as the target user",                     val: EMPTY   };
const OPT_HELP     : CliOption  =  CliOption { flag: "h",   name: "help",            desc: "Display this help screen",                          val: EMPTY   };
const OPT_NONINT   : CliOption  =  CliOption { flag: "n",   name: "non-interactive", desc: "Non-interactive mode, don't prompt for password",   val: EMPTY   };
const OPT_STDIN    : CliOption  =  CliOption { flag: "S",   name: "stdin",           desc: "Read password from standard input",                 val: EMPTY   };
const OPT_VERSION  : CliOption  =  CliOption { flag: "v",   name: "version",         desc: "Display version information and exit",              val: EMPTY   };
const OPT_ENV      : CliOption  =  CliOption { flag: EMPTY, name: "env",             desc: "Set environment variable",                          val: "ENV"   };
const OPT_PRESERVE : CliOption  =  CliOption { flag: EMPTY, name: "preserve-env",    desc: "Comma separated list of variables to preserve",     val: "LIST"  };
const OPT_CHDIR    : CliOption  =  CliOption { flag: "D",   name: "chdir",           desc: "Run the command in the specified directory",        val: "PATH"  };

const ARGV_SCHEME: &[CliOption] = &[OPT_USER, OPT_GROUP, OPT_SHELL, OPT_HELP, OPT_NONINT, OPT_STDIN, OPT_VERSION, OPT_ENV, OPT_PRESERVE, OPT_CHDIR];

/**
 * Prints the usage/help text based on the current command-line schema.
 */
fn print_usage(program: &str, argv_opt: &Options) {
    let brief: String = format!("Usage: {} [options] -- CMD", program);
    print!("{}", argv_opt.usage(&brief));
}

/**
 * Build and return a configured `getopts::Options` parser
 * matching the static argument schema in `ARGV_SCHEME`.
 */
fn get_argv_options() -> Options {
    let mut argv_opt = Options::new();
    
    for cli_opt in ARGV_SCHEME {
        if cli_opt.val == EMPTY {
            argv_opt.optflag(cli_opt.flag, cli_opt.name, cli_opt.desc);
        
        } else {
            argv_opt.optopt(cli_opt.flag, cli_opt.name, cli_opt.desc, cli_opt.val);
        }
    }
    
    return argv_opt;
}

/**
 * Constructs the initial `systemd-run` argument vector.
 * The UID placeholder (index 2) is later replaced dynamically
 * when the target user is resolved.
 */
#[cfg(not(feature = "backend_scopex"))]
fn build_argv() -> Vec<CString> {
    let mut argv = vec![
        cstring!(match option_env!("RUNAS_SYSTEMD_PATH") {
            Some(path) => path,
            None => "/usr/bin/systemd-run",
        })
    ];

    #[cfg(feature = "backend_run0")]
    argv.extend([
        cstring!("run0"),
        cstring!("--user"), cstring!("0"),      // MUST be in this order
        cstring!("--shell-prompt-prefix="),     // Remove the stupid SuperUser icon
        cstring!("--background=")               // Remove the annoying red background
    ]);

    #[cfg(not(feature = "backend_run0"))]
    argv.extend([
        cstring!("systemd-run"),
        cstring!("--uid"), cstring!("0"),       // MUST be in this order
        cstring!("--quiet"),
        cstring!("-G"),
        cstring!("--send-sighup"),
        
        #[cfg(not(feature = "without_expand_env"))]
        cstring!("--expand-environment=false")
    ]);

    return argv;
}

/**
 * Program entry point.
 *
 * 1. Parses command line arguments
 * 2. Authenticates user credentials
 * 3. Builds `systemd-run` command argv
 * 4. Executes it with appropriate privileges
 */
fn main() -> Result<(), Error> {
    let argv_raw: Vec<String> = env_args().collect();
    let argv_opt: Options     = get_argv_options();

    let argv_in: Matches = match argv_opt.parse(&argv_raw[1..]) {
        Ok(m) => m,
        Err(e) => {
            print_usage(&*argv_raw[0], &argv_opt);
            return Err(Error::Message(e.to_string()));
        }
    };

    let shell = argv_in.opt_present("s");
    let help  = argv_in.opt_present("h");
    let ver   = argv_in.opt_present("v");

    let special_count =
        shell as u8 +
        help as u8 +
        ver as u8;
        
    if special_count > 1 {
        return Err(Error::StaticMessage("Options -s, -h and -v are mutually exclusive"));
        
    } else if (help || ver || shell) && !argv_in.free.is_empty() {
        return Err(Error::StaticMessage("This option does not accept command arguments"));
        
    } else if !shell && !help && !ver && argv_in.free.is_empty() {
        return Err(Error::StaticMessage("No command specified"));
    }

    let mut env:            HashMap<String, String> = HashMap::new();
    let mut target_group:   Option<Group>           = None;
    let mut target_account: Option<Account>         = None;
    let mut flags:          RunFlags                = RunFlags::NONE;
    let mut argv:           Vec<CString>            = {
        #[cfg(not(feature = "backend_scopex"))]
        {
            build_argv()
        }

        #[cfg(feature = "backend_scopex")]
        {
            Vec::new()
        }
    };

    #[cfg(feature = "backend_scopex")]
    let mut target_dir: Option<String> = None;

    for opt in ARGV_SCHEME {
        if argv_in.opt_present(opt.name) {
            match *opt {
                OPT_HELP => {
                    print_usage(&argv_raw[0], &argv_opt);
                    return Ok(());
                }

                OPT_VERSION => {
                    #[cfg(any(
                        feature = "use_pam", 
                        feature = "backend_scopex", 
                        feature = "backend_run0"
                    ))]
                    {
                        let mut feat: Vec<&'static str> = Vec::new();

                        #[cfg(feature = "use_pam")]
                        feat.push("PAM");

                        #[cfg(feature = "backend_scopex")]
                        feat.push("SCOPEX");

                        #[cfg(feature = "backend_run0")]
                        feat.push("RUN0");

                        println!(
                            "{} {} {}",
                            env!("CARGO_PKG_NAME"),
                            env!("CARGO_PKG_VERSION"),
                            feat.join(",")
                        );
                    }

                    #[cfg(not(any(
                        feature = "use_pam", 
                        feature = "backend_scopex", 
                        feature = "backend_run0"
                    )))]
                    {
                        println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
                    }

                    return Ok(());
                }

                OPT_USER => {
                    let value = argv_in
                        .opt_str(opt.name)
                        .ok_or(Error::StaticMessage("User was not supplied"))?;
                    
                    target_account = Account::from(&value)?;
                    
                    if target_account.is_none() {
                        return Err(Error::Message(format!("User {} is not valid", value)));
                    }

                    #[cfg(not(feature = "backend_scopex"))]
                    {
                        argv[3] = cstring!(cstring!(value));
                    }
                }

                OPT_GROUP => {
                    let value = argv_in
                        .opt_str(opt.name)
                        .ok_or(Error::StaticMessage("Group was not supplied"))?;
                    
                    target_group = Group::from(&value)?;
                    
                    if target_group.is_none() {
                        return Err(Error::Message(format!("Group {} is not valid", value)));
                    }  
                    
                    #[cfg(not(feature = "backend_scopex"))]
                    if !target_group.is_none() {
                        #[cfg(feature = "backend_run0")]
                        argv.push(cstring!("--group"));

                        #[cfg(not(feature = "backend_run0"))]
                        argv.push(cstring!("--gid"));

                        argv.push(cstring!(value));
                    }
                }

                OPT_ENV => {
                    let value = argv_in
                        .opt_str(opt.name)
                        .ok_or(Error::StaticMessage("Missing environment variable"))?;

                    let (name, value) = value
                        .split_once('=')
                        .ok_or(Error::StaticMessage("Missing environment list"))?;

                    env.insert(name.to_owned(), value.to_owned());
                }

                OPT_PRESERVE => {
                    let value = argv_in
                        .opt_str(opt.name)
                        .ok_or(Error::StaticMessage("Missing environment list"))?;
                
                    for raw in value.split(',') {
                        let name: &str = raw.trim();
                        
                        if !name.is_empty() {
                            if let Ok(val) = env_var(name) {
                                env.insert(name.to_owned(), val);
                            }
                        }
                    }
                }

                OPT_CHDIR => {
                    let value = argv_in
                        .opt_str(opt.name)
                        .ok_or(Error::StaticMessage("No path was defined for working directory"))?;

                    #[cfg(not(feature = "backend_scopex"))]
                    {
                        #[cfg(feature = "backend_run0")]
                        {
                            argv.push(cstring!("--chdir"));
                        }

                        #[cfg(not(feature = "backend_run0"))]
                        {
                            argv.push(cstring!("--working-directory"));
                        }

                        argv.push(cstring!(value));
                    }


                    #[cfg(feature = "backend_scopex")]
                    {
                        target_dir = Some(value);
                    }
                }

                OPT_SHELL  => flags |= RunFlags::SHELL,
                OPT_STDIN  => flags |= RunFlags::AUTH_STDIN,
                OPT_NONINT => flags |= RunFlags::AUTH_NO_PROMPT,
                
                _ => NULL
            }
        }
    }

    // Create selected user account or set it to root if not set via argv
    let current_user: Account = Account::current()?.ok_or(
        Error::StaticMessage("Failed to initialize current user")
    )?;
    
    // Get declared target or assume root
    let mut target_user: Account = if let Some(account) = target_account { 
        account 
    } else {
        Account::from_uid(CUid::from_raw(0))?.ok_or(
            Error::StaticMessage("Failed to initialize default user")
        )?
    };
    
    // If we have a different gid in argv, update the group
    if let Some(group) = target_group {
        target_user.set_group(group);
    }

    // Get the currently used shell, fallback to sh
    #[cfg(feature = "backend_scopex")]
    let target_shell: String = match env_var("SHELL") {
        Ok(val) if !val.trim().is_empty() => val,
        _ => {
            let s: &str = target_user.shell().trim();
            
            if !s.is_empty() {
                s.to_string()
            
            } else {
                String::from("/bin/sh")
            }
        }
    };

    #[cfg(feature = "backend_run0")]
    if !argv.iter().any(|arg| arg.to_str() == Ok("--chdir")) {
        let path: Result<PathBuf, _> = env_current_dir();
    
        if let Ok(cwd) = path {
            argv.push(cstring!("--chdir"));
            argv.push(cstring!(
                cwd.as_os_str().as_bytes()
            ));
        }
    }

    #[cfg(not(any(feature = "backend_scopex", feature = "backend_run0")))]
    if !argv.iter().any(|arg| arg.to_str() == Ok("--chdir")) {
        argv.push(cstring!("--same-dir"));
    }

    // Configure environment and target execution
    if (flags & RunFlags::SHELL) != RunFlags::NONE {
        if argv_in.free.len() > 0 {
            return Err(Error::StaticMessage("Not expecting arguments with the --shell option"));
            
        } else if (flags & RunFlags::AUTH_STDIN) != RunFlags::NONE {
            return Err(Error::StaticMessage("The --stdin option is not allowed combined with the --shell option"));
        }

        #[cfg(feature = "backend_scopex")]
        {
            // We only want the name, so make a login shell, e.g. 
            //      /bin/bash      -> -bash
            //      /usr/bin/zsh   -> -zsh
            //      /bin/sh        -> -sh
            let shell_name = Path::new(&*target_shell)
                .file_name()
                .unwrap()
                .to_string_lossy();
                
            argv.push(
                cstring!(&*target_shell)
            );

            argv.push(
                cstring!("-{}", shell_name)
            );
        }

        #[cfg(not(any(feature = "backend_run0", feature = "backend_scopex")))]
        {
            argv.push(cstring!("--shell"));
            argv.push(cstring!("--scope"));
        }

    } else {
        #[cfg(feature = "backend_scopex")]
        {
            let parts: Option<(&String, &[String])> = argv_in.free.split_first();
        
            // Copy all of the argv that execvp() should run
            if let Some((first, rest)) = parts {
                argv.push(
                    cstring!(&**first)
                );
                
                argv.push(
                    cstring!(&**first)
                );
                
                // Push all remaining arguments
                for opt in rest {
                    argv.push(
                        cstring!(&**opt)
                    );
                }
            }
        }

        #[cfg(not(feature = "backend_scopex"))]
        {
            if stdout().is_terminal()
                    && stderr().is_terminal()
                    && stdin().is_terminal()
            {
                argv.push(cstring!("--pty"));
            } else {
                argv.push(cstring!("--pipe"));
            }

            #[cfg(not(feature = "backend_run0"))]
            {
                argv.push(cstring!("--service-type=exec"));
                argv.push(cstring!("--wait"));
            }
        }
    }

    #[cfg(all(feature = "backend_scopex", feature = "use_pam"))]
    let result = authenticate(&current_user, &target_user, flags)?;

    #[cfg(not(all(feature = "backend_scopex", feature = "use_pam")))]
    authenticate(&current_user, &target_user, flags)?;

    let uid = target_user.uid().as_raw().to_string();
    let gid = target_user.gid().as_raw().to_string();

    let placeholders = [
        ("USER",  target_user.name()),
        ("GROUP", target_user.group().name()),
        ("UID",   uid.as_str()),
        ("GID",   gid.as_str())
    ];

    if let Err(err) = load_overwrite_vars(ENV_FILE, &target_user, Some(&placeholders), &mut env) {
        return Err(err);
    }

    #[cfg(all(feature = "backend_scopex", feature = "use_pam"))]
    for (name, value) in result {
        env.entry(name).or_insert(value);
    }

    #[cfg(feature = "backend_scopex")]
    set_environment(&target_user, &mut env);

    #[cfg(not(feature = "backend_scopex"))]
    {
        for (name, value) in env {
            argv.push(cstring!("--setenv"));
            argv.push(cstring!("{}={}", name, value));
        }

        if (flags & RunFlags::SHELL) == RunFlags::NONE {
            argv.push(cstring!("--"));
            
            // Copy all of the argv that systemd-run should execute
            for opt in argv_in.free {
                argv.push(
                    cstring!(opt)
                );
            }
        }
    }

    #[cfg(feature = "backend_scopex")]
    let envp: Vec<CString> = env
        .into_iter()
        .map(|(name, value)| cstring!("{}={}", name, value))
        .collect();

    #[cfg(feature = "backend_scopex")]
    exec(&current_user, &target_user, &argv[0], &argv[1..], &envp, target_dir)?;

    #[cfg(not(feature = "backend_scopex"))]
    exec(&current_user, &argv[0], &argv[1..])?;

    Ok(())
}
