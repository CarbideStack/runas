# RunAS - Privilege Escalation

`runas` is a Rust utility that provides an authentication front-end, with optional backend, for running commands with elevated privileges on trusted, personal systems. Its goal is to do one thing well: verify the caller and hand off execution to a reliable backend rather than attempt to become a full policy engine like `sudo`, for hardware that does not require that sort of control.

## Key ideas

- **Authenticate, then delegate.** `runas` verifies the invoking user and then delegates command execution to one of several execution backends (systemd-run, run0, or a minimal internal executor).
- **Minimal configuration.** No complex policy files; user membership in the "wheel" group is the single mechanism to grant privilege.
- **Build-time choices.** Backend and authentication mechanisms are selected at compile time using Cargo features so deployments remain small and explicit.
- **Intended audience.** Personal machines, home labs, single-admin environments — not enterprise policy management.

## Features

- Two authentication modes:
  - Shadow-file verification (default): locally compare password hashes from the system shadow file.
  - PAM-based authentication (`use_pam` feature): leverage system PAM for authentication and session handling.
- Three execution backends (selectable at build time):
  - `systemd-run` (default): uses systemd through systemd-run to start the command.
  - `run0` (`backend_run0` feature): uses systemd through systemd-run via run0 to start the command.
  - Native "scopex" executor (`backend_scopex` feature): a minimal internal executor that runs commands in a clean process environment.
- "Sudo-like" CLI surface where applicable — common flags are supported, but not the full `sudo` feature set.

__Features__

| Options               | Value   | Description                                     |
| --------------------- | ------- | ----------------------------------------------- |
| -s, --shell           |         | Run $SHELL as the target user                   |
| -u, --user            | USER    | Run process as the specified user name or ID    |
| -g, --group           | GROUP   | Run process as the specified group name or ID   |
| -h, --help            |         | Display help screen                             |
|     --env             | VAR=VAL | Set environment variable                        |
|     --preserve-env    | LIST    | Comma separated list of variables to preserve   |
| -n, --non-interactive |         | Non-interactive mode, don't prompt for password |
| -S, --stdin           |         | Read password from standard input               |
| -v, --version         |         | Display version information and exit            |
| --                    |         | Stop processing command line arguments          |


__Build Features__

| Flag               | Description                                                            |
| ------------------ | ---------------------------------------------------------------------- |
| use_pam            | This will build runas with PAM support.                                |
| backend_run0       | This will build runas to target run0 instead of systemd-run directly   |
| backend_scopex     | This will build runas with it's own backend implementation             |
| without_expand_env | This will build runas without --expand-environment=false (systemd-run) |

## Security posture & assumptions

- Simplicity over policy: `runas` intentionally avoids a full policy language. Membership in the "wheel" group grants run capability.
- No timestamp cache: `runas` does not store credentials or implement password-timestamping. If you require cached authentication, configure it through PAM (when built with PAM) or use a different tool.
- Intended for trusted machines: `runas` is not designed for multi-administrator or high-compliance environments. For granular access control, use `sudo` with a proper `sudoers` policy.

## Build (examples)

Build commands demonstrate how to enable different features. Features are additive; choose the backend and authentication you want at compile time.

- Default build (systemd-run backend, shadow auth):
    ```bash
    cargo build --release
    ```

- Build with `run0` backend:
    ```bash
    cargo build --release --features "backend_run0"
    ```

- Build with the native executor:
    ```bash
    cargo build --release --features "backend_scopex"
    ```

- Build with PAM authentication:
    ```bash
    RUSTFLAGS="-l pam" cargo build --release --features "use_pam"
    ```

    > You must manually add `-l pam` to the `RUSTFLAGS` environment variable. Sadly there is no way to do this automatically via cargo.toml or build.rs.

- Omit systemd's "--expand-environment=false" option (available when building for systemd-run):
    ```bash
    cargo build --release --features "without_expand_env"
    ```

- You can combine features:
    ```bash
    RUSTFLAGS="-l pam" cargo build --release --features "backend_run0,use_pam"
    ```

### Systemd path

The `systemd-run` executable defaults to `/usr/bin/systemd-run`. A different
absolute path can be selected at build time using `RUNAS_SYSTEMD_PATH`:

```bash
RUNAS_SYSTEMD_PATH=/custom/path/systemd-run cargo build --release
```

## PAM specifics

When compiled with the `use_pam` feature and using the native executor:
- `runas` will establish a PAM session after successful authentication.
- PAM session modules may set environment variables or perform session initialization; those are pulled into the executed session.

PAM allows flexible integrations (including optional timestamping via PAM modules) without adding complexity to `runas` itself. If you need PAM-based session or timestamp behavior, configure it in your PAM stack.

 > NOTE: You need to add a PAM configuration file, e.g. `/etc/pam.d/runas` in order for PAM authentication to behave correctly. These are very distro dependent and it's not possible or safe to make a universal one. You need one that is tailored to the way existing PAM configurations are setup on your specific OS installation.

## Limitations

- No `/etc/sudoers`/`/etc/doas.conf` equivalent — there is no policy parser.
- No timestamp-based password caching by default.
- No fine-grained environment protections: `runas` does not attempt to replicate `sudo`'s protected environment features.
- Any user placed in "wheel" obtains full `runas` privileges.

An alias can be used to customise the command as a limited replacement for full configuration files. 

```sh
alias runas='runas --preserve-env MYVAR'
```

## Deployment recommendations

- Use on single-admin machines or homelabs where group membership is manageable.
- Keep the binary owned by root with strict file permissions:
    ```bash
    chown root:root /usr/bin/runas
    chmod 4750 /usr/bin/runas
    ```
- Prefer PAM if you need richer authentication flows or session hooks; otherwise, the shadow-file mode is a compact default.
